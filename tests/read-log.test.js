import { describe, it, expect, beforeAll, afterAll, afterEach } from 'vitest'
import {
  startFakeSftpServer,
  loadFakeRegistry,
  nonSftpRequests,
  countNetwork,
  NO_NON_SFTP_REQUESTS
} from './helpers/fake-sftp-server.js'
import {
  readLogHandler,
  selectLines,
  WINDOW_BYTES,
  MAX_OUTPUT_BYTES,
  MAX_LINE_CHARS,
  LINE_TRUNCATED_MARKER
} from '../src/tools/read-log.js'
import { closeAll } from '../src/ssh/client.js'

// Fixture paths are fake: they exist only in the in-process server's tree.
const ROOT = '/var/www/example.com/public'
const LOGS = '/var/log/sites/example.com'
const CANARY = '/srv/canary/secret.txt'
const SIBLING_CANARY = '/var/log/sites/escape.example-other/escape.example.error.log'

const DEBUG_LINES = Array.from({ length: 30 }, (_, i) => `debug line ${i}`)

const ERROR_LINES = [
  'PHP Fatal error: Uncaught Error in index.php:12',
  'PHP Warning: something minor',
  'literal dot-star .* here',
  'char class [a-z]+ literal',
  'open paren ( only',
  'backslash \\ path',
  'dollar $(id) text',
  'quote "; ls -la',
  'pipe | grep x',
  'caret ^PHP start',
  'php fatal ERROR lowercase',
  'nothing special'
]

// 1 MB debug log: 16384 lines of exactly 64 bytes.
const BIG_DEBUG = Array.from({ length: 16384 }, (_, i) => `line ${String(i).padStart(6, '0')} `.padEnd(63, 'x')).join('\n') + '\n'
// 2000 lines of 1500 characters (about 3 MB).
const WIDE_LINES = Array.from({ length: 2000 }, (_, i) => `${String(i).padStart(4, '0')}:`.padEnd(1500, 'w'))
const LONG_LINE = 'L'.repeat(100000)

// A log whose tail window starts inside a two-byte UTF-8 character of a line
// that matches the filter. Only the complete lines after it may be returned.
const WINDOW_HEAD = 'head line\n'.repeat(10)
const PARTIAL_LINE = '\u00e9'.repeat(100) + ' MATCH-PARTIAL\n' // 215 bytes
const SPLIT_OFFSET = 101 // second byte of the 51st two-byte character
const WINDOW_TAIL = 'MATCH-LAST 1\nMATCH-LAST 2\n'
const FILLER_BYTES = WINDOW_BYTES + SPLIT_OFFSET - Buffer.byteLength(PARTIAL_LINE) - Buffer.byteLength(WINDOW_TAIL)
const FILLER = ('f'.repeat(99) + '\n').repeat(Math.floor(FILLER_BYTES / 100)) +
  (FILLER_BYTES % 100 > 0 ? 'f'.repeat(FILLER_BYTES % 100 - 1) + '\n' : '')
const WINDOW_LOG = Buffer.from(WINDOW_HEAD + PARTIAL_LINE + FILLER + WINDOW_TAIL, 'utf8')

const SITES = {
  'example.com': { wordpressRoot: ROOT, logDir: LOGS },
  'big.example': { wordpressRoot: '/var/www/big/public', logDir: '/var/log/sites/big' },
  'stream.example': { wordpressRoot: '/var/www/stream/public', logDir: '/var/log/sites/stream' },
  'escape.example': { wordpressRoot: '/var/www/escape/public', logDir: '/var/log/sites/escape.example' },
  'inside.example': { wordpressRoot: '/var/www/inside/public', logDir: '/var/log/sites/inside' },
  'window.example': { wordpressRoot: '/var/www/window/public', logDir: '/var/log/sites/window' }
}

let fake
let restoreRegistry

beforeAll(async () => {
  fake = await startFakeSftpServer({
    files: {
      [`${ROOT}/wp-content/debug.log`]: { content: DEBUG_LINES.join('\n') + '\n' },
      [`${LOGS}/example.com.error.log`]: { content: ERROR_LINES.join('\r\n') + '\r\n' },
      [`${LOGS}/example.com.access.log`]: { content: 'GET / 200\nGET /wp-login.php 403\n' },

      '/var/www/big/public/wp-content/debug.log': { content: BIG_DEBUG },
      '/var/log/sites/big/big.example.error.log': { content: WIDE_LINES.join('\n') + '\n' },
      '/var/log/sites/big/big.example.access.log': { content: `short\n${LONG_LINE}\ntail\n` },

      '/var/www/stream/public/wp-content/debug.log': { endless: true, size: 10 * 1024 * 1024 },
      '/var/log/sites/stream/stream.example.error.log': { content: 'never served\n', hangRead: true },

      '/var/www/escape/public/wp-content/debug.log': { symlink: CANARY },
      '/var/log/sites/escape.example/escape.example.error.log': { symlink: SIBLING_CANARY },
      '/var/log/sites/escape.example/escape.example.access.log': { dir: true },
      '/var/www/escape/public/index.php': { content: '<?php' },

      '/var/www/inside/public/wp-content/debug.log': { symlink: '../logs/debug.log' },
      '/var/www/inside/public/logs/debug.log': { content: 'inside root\n' },
      '/var/log/sites/inside/inside.example.access.log': { content: 'SWAPPED-CONTENT\n', fstatType: 'fifo' },

      '/var/www/window/public/wp-content/debug.log': { content: WINDOW_LOG },

      [CANARY]: { content: 'CANARY-SECRET\n' },
      [SIBLING_CANARY]: { content: 'CANARY-SIBLING\n' }
    }
  })
  restoreRegistry = await loadFakeRegistry(fake, SITES)
})

afterEach(() => {
  // Reset first so a failure is reported only for the test that caused it.
  const seen = nonSftpRequests(fake)
  const opens = [...fake.events.opens]
  fake.resetEvents()
  expect(seen).toEqual(NO_NON_SFTP_REQUESTS)
  expect(opens).not.toContain(CANARY)
  expect(opens).not.toContain(SIBLING_CANARY)
})

afterAll(async () => {
  closeAll()
  restoreRegistry?.()
  await fake?.close()
})

const NOT_AVAILABLE = 'E_NOT_AVAILABLE: The requested resource is not available.'

async function failure(input, options) {
  const err = await readLogHandler(input, options).then(() => null, e => e)
  expect(err).not.toBeNull()
  return err
}

describe('read_log log selection', () => {
  it('maps debug to the WordPress root wp-content/debug.log', async () => {
    const result = await readLogHandler({ site: 'example.com', log: 'debug', lines: 10 })
    expect(fake.events.opens).toEqual([`${ROOT}/wp-content/debug.log`])
    expect(result.content).toBe(DEBUG_LINES.slice(-10).join('\n'))
  })

  it('maps error to {logDir}/{site}.error.log', async () => {
    await readLogHandler({ site: 'example.com', log: 'error', lines: 20 })
    expect(fake.events.opens).toEqual([`${LOGS}/example.com.error.log`])
  })

  it('maps access to {logDir}/{site}.access.log', async () => {
    const result = await readLogHandler({ site: 'example.com', log: 'access', lines: 30 })
    expect(fake.events.opens).toEqual([`${LOGS}/example.com.access.log`])
    expect(result.content).toBe('GET / 200\nGET /wp-login.php 403')
  })

  it('refuses a log name outside the enum without echoing it', async () => {
    const err = await failure({ site: 'example.com', log: '../../etc/passwd', lines: 10 })
    expect(err.code).toBe('E_INVALID_INPUT')
    expect(err.message).toBe('E_INVALID_INPUT: The tool arguments are invalid.')
    expect(fake.events.ops).toEqual([])
  })
})

describe('read_log output shape and caps', () => {
  it('returns structured output without server paths', async () => {
    const result = await readLogHandler({ site: 'example.com', log: 'debug', lines: 5 })
    expect(result).toEqual({
      site: 'example.com',
      log: 'debug',
      requestedLines: 5,
      returnedLines: 5,
      content: DEBUG_LINES.slice(-5).join('\n'),
      truncated: { window: false, longLines: 0, bytes: false },
      redactedLines: 0,
      retrievedAt: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T/)
    })
    expect(JSON.stringify(result)).not.toContain('/var/')
  })

  it('caps lines at 500', async () => {
    const result = await readLogHandler({ site: 'big.example', log: 'debug', lines: 9999 })
    expect(result.requestedLines).toBe(500)
    expect(result.returnedLines).toBe(500)
    expect(result.content.split('\n')).toHaveLength(500)
    expect(result.content.endsWith('line 016383 '.padEnd(63, 'x'))).toBe(true)
  })

  it('reads only the tail window of a large log', async () => {
    const size = Buffer.byteLength(BIG_DEBUG)
    const result = await readLogHandler({ site: 'big.example', log: 'debug', lines: 500 })
    expect(fake.events.readBytesServed).toBeLessThanOrEqual(WINDOW_BYTES)
    const reads = fake.events.ops.filter(o => o.op === 'READ')
    expect(reads.length).toBeGreaterThan(0)
    for (const r of reads) expect(r.offset).toBeGreaterThanOrEqual(size - WINDOW_BYTES)
    expect(result.truncated.window).toBe(true)
    // The partial first line of the window is dropped.
    for (const line of result.content.split('\n')) expect(line).toMatch(/^line \d{6} x+$/)
  })

  it('caps the returned bytes and keeps the newest lines', async () => {
    const result = await readLogHandler({ site: 'big.example', log: 'error', lines: 500 })
    expect(Buffer.byteLength(result.content, 'utf8')).toBeLessThanOrEqual(MAX_OUTPUT_BYTES)
    expect(result.truncated.bytes).toBe(true)
    expect(result.returnedLines).toBeLessThan(500)
    expect(result.content.split('\n').at(-1)).toBe(WIDE_LINES.at(-1))
  })

  it('drops the partial first line of a window that starts mid-line and mid-character', async () => {
    // Fixture sanity: the window starts inside the matching partial line.
    const windowStart = WINDOW_LOG.length - WINDOW_BYTES
    expect(windowStart - Buffer.byteLength(WINDOW_HEAD)).toBe(SPLIT_OFFSET)
    expect(WINDOW_LOG[windowStart] & 0xc0).toBe(0x80) // a UTF-8 continuation byte

    const result = await readLogHandler({ site: 'window.example', log: 'debug', lines: 10, filter: 'match' })
    expect(result.content).toBe('MATCH-LAST 1\nMATCH-LAST 2')
    expect(result.content).not.toContain('PARTIAL')
    expect(result.content).not.toContain('\ufffd')
    expect(result.truncated.window).toBe(true)
  })

  it('does not split a surrogate pair when cutting a long line', () => {
    const line = 'a'.repeat(MAX_LINE_CHARS - 1) + '\u{1F600}' + 'b'.repeat(10)
    const { lines } = selectLines(line + '\n', { dropFirstLine: false, lines: 10 })
    expect(lines).toEqual(['a'.repeat(MAX_LINE_CHARS - 1) + LINE_TRUNCATED_MARKER])
    expect(lines[0]).not.toMatch(/[\ud800-\udbff](?![\udc00-\udfff])/)
  })

  it('caps long lines and marks them', async () => {
    const result = await readLogHandler({ site: 'big.example', log: 'access', lines: 10 })
    const lines = result.content.split('\n')
    expect(lines).toHaveLength(3)
    expect(lines[0]).toBe('short')
    expect(lines[1]).toBe('L'.repeat(MAX_LINE_CHARS) + LINE_TRUNCATED_MARKER)
    expect(lines[2]).toBe('tail')
    expect(result.truncated.longLines).toBe(1)
  })
})

describe('read_log filter', () => {
  it('matches case-insensitively', async () => {
    const result = await readLogHandler({ site: 'example.com', log: 'error', lines: 50, filter: 'FATAL' })
    expect(result.content.split('\n')).toEqual([
      'PHP Fatal error: Uncaught Error in index.php:12',
      'php fatal ERROR lowercase'
    ])
  })

  it.each([
    ['.*'],
    ['[a-z]+'],
    ['('],
    ['\\'],
    ['$(id)'],
    ['"; ls'],
    ['|'],
    ['^PHP'],
    ['x*']
  ])('treats %j as a literal substring', async filter => {
    const expected = ERROR_LINES.filter(line => line.toLowerCase().includes(filter.toLowerCase()))
    const result = await readLogHandler({ site: 'example.com', log: 'error', lines: 50, filter })
    expect(result.returnedLines).toBe(expected.length)
    expect(result.content).toBe(expected.join('\n'))
  })

  it('filters before taking the last N lines', async () => {
    const result = await readLogHandler({ site: 'example.com', log: 'debug', lines: 3, filter: 'line 1' })
    expect(result.content.split('\n')).toEqual(['debug line 17', 'debug line 18', 'debug line 19'])
  })

  it('returns empty content when nothing matches', async () => {
    const result = await readLogHandler({ site: 'example.com', log: 'error', lines: 50, filter: 'no such text' })
    expect(result.content).toBe('')
    expect(result.returnedLines).toBe(0)
  })
})

describe('read_log confinement and refusals', () => {
  it('refuses a debug log that is a symlink out of the WordPress root', async () => {
    const err = await failure({ site: 'escape.example', log: 'debug', lines: 10 })
    expect(err.message).toBe(NOT_AVAILABLE)
  })

  it('refuses an error log that links to a sibling directory sharing the log dir prefix', async () => {
    const err = await failure({ site: 'escape.example', log: 'error', lines: 10 })
    expect(err.message).toBe(NOT_AVAILABLE)
  })

  it('refuses a log path that is a directory without sending OPEN', async () => {
    const err = await failure({ site: 'escape.example', log: 'access', lines: 10 })
    expect(err.message).toBe(NOT_AVAILABLE)
    expect(fake.events.ops.filter(o => o.op === 'OPEN')).toEqual([])
  })

  it('refuses a log whose type on the open handle is not regular, closes the handle and reads nothing', async () => {
    const err = await failure({ site: 'inside.example', log: 'access', lines: 10 })
    expect(err.message).toBe(NOT_AVAILABLE)
    const ops = fake.events.ops.map(o => o.op)
    expect(ops).toContain('FSTAT')
    expect(ops).not.toContain('READ')
    expect(ops.at(-1)).toBe('CLOSE')
    expect(fake.events.openHandles).toBe(0)
  })

  it('refuses a log that is a symlink to another file inside the root, without sending OPEN', async () => {
    // Only the configured log path is served, never what a link there points at.
    const err = await failure({ site: 'inside.example', log: 'debug', lines: 10 })
    expect(err.message).toBe(NOT_AVAILABLE)
    expect(fake.events.ops.filter(o => o.op === 'OPEN')).toEqual([])
  })

  it.each([['unknown.example'], ['__proto__'], ['constructor'], ['toString'], ['hasOwnProperty']])(
    'refuses site %j before any connection or SFTP session', async site => {
      let err
      const { before, after } = await countNetwork(fake, closeAll, async () => {
        err = await failure({ site, log: 'debug', lines: 10 })
      })
      expect(err.message).toBe(NOT_AVAILABLE)
      expect(after).toEqual(before)
      expect(fake.events.ops).toEqual([])
    }
  )

  it('gives byte-identical refusals for unknown site, escape and missing file', async () => {
    const unknown = await failure({ site: 'unknown.example', log: 'debug', lines: 10 })
    const escape = await failure({ site: 'escape.example', log: 'debug', lines: 10 })
    const missing = await failure({ site: 'inside.example', log: 'error', lines: 10 })
    expect(new Set([unknown.message, escape.message, missing.message])).toEqual(new Set([NOT_AVAILABLE]))
  })

  it('never echoes caller input, server paths or remote text in errors', async () => {
    const cases = [
      { site: 'unknown-site-marker.example', log: 'debug', lines: 10, filter: 'filter-marker' },
      { site: 'escape.example', log: 'debug', lines: 10, filter: 'filter-marker' },
      { site: 'escape.example', log: 'access', lines: 10, filter: 'filter-marker' },
      { site: 'example.com', log: 'nope-marker', lines: 10 },
      { site: 'example.com', log: 'debug', lines: 10, filter: 'f'.repeat(201) }
    ]
    for (const input of cases) {
      const err = await failure(input)
      expect(err.message).toMatch(/^E_[A-Z_]+: [A-Za-z .]+$/)
      for (const forbidden of ['marker', 'escape', 'example', '/var', '/srv', 'CANARY', 'fff']) {
        expect(err.message).not.toContain(forbidden)
      }
    }
  })
})

describe('read_log limits on the remote side', () => {
  it('stops an endless log at the window and closes the SFTP session', async () => {
    const result = await readLogHandler({ site: 'stream.example', log: 'debug', lines: 10 })
    expect(fake.events.readBytesServed).toBeLessThanOrEqual(WINDOW_BYTES)
    expect(Buffer.byteLength(result.content)).toBeLessThanOrEqual(MAX_OUTPUT_BYTES)
    await fake.waitFor(() => fake.openSftpSessions() === 0)
  })

  it('times out a read that never answers and closes the SFTP session', async () => {
    const started = Date.now()
    const err = await failure({ site: 'stream.example', log: 'error', lines: 10 }, { timeoutMs: 300 })
    expect(err.message).toBe('E_TIMEOUT: The operation timed out.')
    expect(Date.now() - started).toBeLessThan(2000)
    expect(fake.events.pendingReads).toBe(1)
    await fake.waitFor(() => fake.openSftpSessions() === 0)
  })

  it('sends no exec, shell or write request for any log', async () => {
    for (const log of ['debug', 'error', 'access']) {
      await readLogHandler({ site: 'example.com', log, lines: 5, filter: '$(touch x); `id` | sh' })
    }
    expect(fake.events.sessionRequests).toEqual([])
    expect(nonSftpRequests(fake)).toEqual(NO_NON_SFTP_REQUESTS)
    expect(fake.events.ops.filter(o => o.op === 'OPEN').every(o => o.flags === 1)).toBe(true)
  })
})
