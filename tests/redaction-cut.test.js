import { describe, it, expect, beforeAll, afterAll, afterEach } from 'vitest'
import {
  startFakeSftpServer,
  loadFakeRegistry,
  nonSftpRequests,
  NO_NON_SFTP_REQUESTS
} from './helpers/fake-sftp-server.js'
import { readFileHandler, redactedPrefix, LOOKAHEAD_BYTES, MAX_BYTES } from '../src/tools/read-file.js'
import { readLogHandler, WINDOW_BYTES } from '../src/tools/read-log.js'
import { REDACTED_LINE } from '../src/policy/redact.js'
import { closeAll } from '../src/ssh/client.js'

// Redaction must not depend on where the caller cuts the content: for every
// maxBytes, no character of a credential may be returned. Every synthetic
// secret contains the marker Zq7 (ZQ7 for upper-case shapes), which appears
// nowhere else in the fixtures. All values are fake.

const SECRET_MARKS = ['Zq7', 'ZQ7']

const SHAPES = {
  'URL credentials': "$url = 'scheme://exampleuser:Zq7urlSecret0@db.example.com/wp';",
  'URL credentials without a user': 'cache = scheme://:Zq7urlSecret0@cache.example.com:6379',
  'a bearer value': 'curl -H "X-Trace: 1" -H "Bearer Zq7bearerSecretValue0"',
  'a basic value': 'proxy header Basic Zq7basicValueAbc0=',
  'a JSON web token': 'session value eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.Zq7jwtSignature0',
  'a base64 line': 'Zq7' + 'AbCdEf0123456789'.repeat(4),
  'a cloud key id': 'access id AKIAZQ7EXAMPLEKEY000 in log',
  'a query-string key': 'GET /reset?action=rp&key=Zq7resetKey0&login=example HTTP/1.1',
  'a command-line password': 'mysqldump -uexample -pZq7cliSecret0 example_db',
  'a value on the next line': "define( 'DB_PASSWORD',\n  'Zq7multiLine0' );",
  'a secret far into a long line': 'a'.repeat(3000) + ' Bearer Zq7longLineSecret0',
  'a secret beyond the look-ahead': 'a'.repeat(LOOKAHEAD_BYTES + 5000) + ' Bearer Zq7farSecret0'
}

function fileFor(shape) {
  return Buffer.from(`<?php\n${shape}\necho 'ordinary';\n`, 'utf8')
}

/** What read_file reads for a given maxBytes: the cap, the look-ahead and one byte. */
function readFor(file, maxBytes) {
  return file.subarray(0, maxBytes + LOOKAHEAD_BYTES + 1)
}

function expectNoSecret(text) {
  for (const mark of SECRET_MARKS) expect(text).not.toContain(mark)
  expect(text).not.toContain('eyJ')
}

describe('redactedPrefix: no maxBytes returns any part of a credential', () => {
  it.each(Object.entries(SHAPES))('%s, for every maxBytes from 1 to the file length', (_, shape) => {
    const file = fileFor(shape)
    for (let maxBytes = 1; maxBytes <= file.length + 2; maxBytes++) {
      const result = redactedPrefix(readFor(file, maxBytes), maxBytes)
      expectNoSecret(result.text)
      expect(result.bytes).toBeLessThanOrEqual(maxBytes)
      expect(Buffer.byteLength(result.text)).toBe(result.bytes)
    }
    // Markers count toward the cap; leave room for them.
    const room = file.length + 4 * REDACTED_LINE.length
    const whole = redactedPrefix(readFor(file, room), room)
    expect(whole.text).toContain("echo 'ordinary';")
    expect(whole.text).toContain(REDACTED_LINE)
    expect(whole.redactedLines).toBeGreaterThanOrEqual(1)
  })

  it('still cuts ordinary lines at the cap', () => {
    const file = Buffer.from('first line\nsecond line\n')
    expect(redactedPrefix(readFor(file, 15), 15)).toEqual({ text: 'first line\nseco', bytes: 15, redactedLines: 0, cut: true })
    expect(redactedPrefix(readFor(file, 100), 100)).toEqual({ text: 'first line\nsecond line\n', bytes: 23, redactedLines: 0, cut: false })
  })

  it('counts markers toward the cap: lines that no longer fit are dropped and the result is cut', () => {
    const one = Buffer.from('pwd=Zq7a\n' + 'z'.repeat(40) + '\n')
    expect(redactedPrefix(readFor(one, one.length), one.length))
      .toEqual({ text: REDACTED_LINE + '\n' + 'z'.repeat(one.length - REDACTED_LINE.length - 1), bytes: one.length, redactedLines: 1, cut: true })
    const two = Buffer.from('pwd=Zq7a\npwd=Zq7b\n' + 'y'.repeat(20) + '\n')
    expect(redactedPrefix(readFor(two, two.length), two.length))
      .toEqual({ text: REDACTED_LINE + '\n', bytes: REDACTED_LINE.length + 1, redactedLines: 2, cut: true })
  })

  it('drops, and counts, a credential line whose marker does not fit', () => {
    const file = Buffer.from('ab\npassword=Zq7x\nend\n')
    const result = redactedPrefix(readFor(file, 10), 10)
    expect(result).toEqual({ text: 'ab\n', bytes: 3, redactedLines: 1, cut: true })
  })

  it('keeps CRLF line endings on redacted lines', () => {
    const file = Buffer.from('a\r\npassword=Zq7x\r\nb\r\n')
    expect(redactedPrefix(readFor(file, 100), 100).text).toBe(`a\r\n${REDACTED_LINE}\r\nb\r\n`)
  })
})

const ROOT = '/var/www/cut.example/public'
const LOGS = '/var/log/sites/cut'

// A debug log whose tail window starts inside an assignment whose value is on
// the next line.
const ASSIGN = "define( 'DB_PASSWORD',\n"
const VALUE = "  'Zq7windowValue0' );\n"
const HEAD = 'head line\n'.repeat(200)
function filler(bytes) {
  const lines = []
  let left = bytes
  while (left > 0) {
    const n = Math.min(left, 40)
    lines.push(n === 1 ? '\n' : 'f'.repeat(n - 1) + '\n')
    left -= n
  }
  return lines.join('')
}
const TAIL = filler(WINDOW_BYTES + 5 - ASSIGN.length - VALUE.length - 'tail end\n'.length) + 'tail end\n'
const ASSIGN_LOG = HEAD + ASSIGN + VALUE + TAIL

// An error log whose tail window starts inside a key block and whose last
// body line is short.
const BODY = Array.from({ length: Math.ceil((WINDOW_BYTES + 2048) / 65) },
  (_, i) => `Ab3${String(i).padStart(6, '0')}`.padEnd(64, 'xY9')).join('\n')
const KEY_LOG = 'x\n'.repeat(50) + '-----BEGIN PRIVATE KEY-----\n' + BODY + '\nZq7s=\n-----END PRIVATE KEY-----\nafter\n'

const CUT_FILE = fileFor(SHAPES['URL credentials'])

let fake
let restoreRegistry

beforeAll(async () => {
  fake = await startFakeSftpServer({
    files: {
      [`${ROOT}/wp-content/plugins/demo/conn.php`]: { content: CUT_FILE },
      [`${ROOT}/wp-content/debug.log`]: { content: ASSIGN_LOG },
      [`${LOGS}/cut.example.error.log`]: { content: KEY_LOG },
      [`${LOGS}/backup.example.org.error.log`]: { content: 'ordinary error line\n' },
      [`${ROOT}/wp-content/plugins/demo/backup.example.org.error.log`]: { content: 'x\n' }
    }
  })
  const site = { wordpressRoot: ROOT, logDir: LOGS, allow: { extensions: ['.php', '.log'], directories: ['wp-content/plugins'] } }
  restoreRegistry = await loadFakeRegistry(fake, { 'cut.example': site, 'backup.example.org': site })
})

afterEach(() => {
  const seen = nonSftpRequests(fake)
  fake.resetEvents()
  expect(seen).toEqual(NO_NON_SFTP_REQUESTS)
})

afterAll(async () => {
  closeAll()
  restoreRegistry?.()
  await fake?.close()
})

describe('read_file through the fake server', () => {
  it('returns no part of a credential for any maxBytes from 1 to the file length', async () => {
    for (let maxBytes = 1; maxBytes <= CUT_FILE.length; maxBytes++) {
      const result = await readFileHandler({ site: 'cut.example', path: 'wp-content/plugins/demo/conn.php', maxBytes })
      expectNoSecret(result.content)
      expect(result.bytes).toBeLessThanOrEqual(maxBytes)
      expect(result.truncated).toBe(maxBytes < CUT_FILE.length)
    }
  }, 60000)

  it('reads at most the cap plus the look-ahead', async () => {
    await readFileHandler({ site: 'cut.example', path: 'wp-content/plugins/demo/conn.php', maxBytes: 10 })
    expect(fake.events.readBytesServed).toBeLessThanOrEqual(CUT_FILE.length)
    expect(10 + LOOKAHEAD_BYTES + 1).toBeLessThan(MAX_BYTES + LOOKAHEAD_BYTES + 2)
  })
})

describe('read_log windows', () => {
  it('fixture sanity: the window starts inside the assignment line', () => {
    const windowStart = Buffer.byteLength(ASSIGN_LOG) - WINDOW_BYTES
    expect(windowStart).toBe(HEAD.length + 5)
  })

  it('redacts a value whose assignment line is the partial first line of the window', async () => {
    // The filter selects the value line if it was left unredacted; the byte
    // cap alone would drop it from the output.
    const probe = await readLogHandler({ site: 'cut.example', log: 'debug', lines: 500, filter: 'Zq7' })
    expect(probe.truncated.window).toBe(true)
    expect(probe.returnedLines).toBe(0)
    const all = await readLogHandler({ site: 'cut.example', log: 'debug', lines: 500 })
    expectNoSecret(all.content)
  })

  it('redacts every key line, including a short last one, when the window starts inside a key block', async () => {
    const result = await readLogHandler({ site: 'cut.example', log: 'error', lines: 500 })
    expect(result.truncated.window).toBe(true)
    expectNoSecret(result.content)
    const lines = result.content.split('\n')
    expect(lines.at(-1)).toBe('after')
    expect(new Set(lines.slice(0, -1))).toEqual(new Set([REDACTED_LINE]))
    const probe = await readLogHandler({ site: 'cut.example', log: 'error', lines: 500, filter: 'Zq7' })
    expect(probe.returnedLines).toBe(0)
  })
})

describe('site names in log file names', () => {
  it('serves the logs of a site whose name contains a denied word', async () => {
    const result = await readLogHandler({ site: 'backup.example.org', log: 'error', lines: 5 })
    expect(result.content).toBe('ordinary error line')
  })

  it('still refuses a read_file request for a file with that name', async () => {
    const err = await readFileHandler({ site: 'backup.example.org', path: 'wp-content/plugins/demo/backup.example.org.error.log' }).then(() => null, e => e)
    expect(err?.code).toBe('E_NOT_AVAILABLE')
  })
})
