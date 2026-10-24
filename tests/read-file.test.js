import { describe, it, expect, beforeAll, afterAll, afterEach } from 'vitest'
import {
  startFakeSftpServer,
  loadFakeRegistry,
  nonSftpRequests,
  countNetwork,
  NO_NON_SFTP_REQUESTS
} from './helpers/fake-sftp-server.js'
import { readFileHandler, utf8BoundaryLength, MAX_BYTES } from '../src/tools/read-file.js'
import { closeAll } from '../src/ssh/client.js'

// Fixture paths are fake: they exist only in the in-process server's tree.
const ROOT = '/var/www/example.com/public'
const CANARIES = [
  '/srv/canary/secret.txt',
  '/home/other/uploads/secret.txt',
  '/var/www/example.com/public-backup/wp-config.php',
  '/etc/fake-passwd',
  '/srv/canary/odd2.php'
]
const CONFIG = '<?php\n// fake configuration used only by the tests\n'

let fake
let restoreRegistry

beforeAll(async () => {
  fake = await startFakeSftpServer({
    files: {
      [`${ROOT}/wp-config.php`]: { content: CONFIG },
      [`${ROOT}/index.php`]: { content: '<?php echo 1;' },
      [`${ROOT}/wp-content/big.txt`]: { content: 'b'.repeat(100 * 1024) },
      [`${ROOT}/wp-content/exact.txt`]: { content: 'e'.repeat(100) },
      [`${ROOT}/wp-content/multibyte.txt`]: { content: 'a'.repeat(99) + '\u00e9' + '\u20ac' + '\u{1F600}' + 'tail' },
      [`${ROOT}/wp-content/plugins/example/readme.txt`]: { content: 'readme' },
      [`${ROOT}/wp-content/uploads`]: { symlink: '/home/other/uploads' },
      [`${ROOT}/wp-content/link-out.txt`]: { symlink: '/etc/fake-passwd' },
      [`${ROOT}/wp-content/link-sibling.txt`]: { symlink: '/var/www/example.com/public-backup/wp-config.php' },
      [`${ROOT}/wp-content/link-relative.txt`]: { symlink: '../../../../../srv/canary/secret.txt' },
      [`${ROOT}/wp-content/link-inside.txt`]: { symlink: '../index.php' },
      [`${ROOT}/wp-content/loop-a`]: { symlink: 'loop-b' },
      [`${ROOT}/wp-content/loop-b`]: { symlink: 'loop-a' },
      [`${ROOT}/wp-content/endless.bin`]: { endless: true, size: 10 * 1024 * 1024 },
      [`${ROOT}/wp-content/slow.txt`]: { content: 'never served', hangRead: true },
      [`${ROOT}/wp-content/type-change.txt`]: { content: 'SWAPPED-CONTENT', fstatType: 'fifo' },
      // realpath answers with a `..` that only looks inside the root
      // lexically; the server resolves it through the link to outside.
      [`${ROOT}/wp-content/odd.php`]: { content: 'x', realpathReply: `${ROOT}/wp-content/out/../odd2.php` },
      [`${ROOT}/wp-content/out`]: { symlink: '/srv/canary/dir' },
      '/srv/canary/dir/placeholder.txt': { content: 'x' },

      '/var/www/current': { symlink: '/var/www/releases/1' },
      '/var/www/releases/1/index.php': { content: '<?php // release 1' },

      ...Object.fromEntries(CANARIES.map(p => [p, { content: 'CANARY' }]))
    }
  })
  restoreRegistry = await loadFakeRegistry(fake, {
    'example.com': { wordpressRoot: ROOT, logDir: '/var/log/nginx' },
    'linkroot.example': { wordpressRoot: '/var/www/current', logDir: '/var/log/nginx' }
  })
})

afterEach(() => {
  // Reset first so a failure is reported only for the test that caused it.
  const seen = nonSftpRequests(fake)
  const opens = [...fake.events.opens]
  fake.resetEvents()
  expect(seen).toEqual(NO_NON_SFTP_REQUESTS)
  for (const canary of CANARIES) expect(opens).not.toContain(canary)
})

afterAll(async () => {
  closeAll()
  restoreRegistry?.()
  await fake?.close()
})

const NOT_AVAILABLE = 'E_NOT_AVAILABLE: The requested resource is not available.'

async function failure(input, options) {
  const err = await readFileHandler(input, options).then(() => null, e => e)
  expect(err).not.toBeNull()
  return err
}

describe('read_file reads inside the root', () => {
  it('opens the canonical path of a relative path', async () => {
    await readFileHandler({ site: 'example.com', path: 'index.php', maxBytes: 1000 })
    expect(fake.events.opens).toEqual([`${ROOT}/index.php`])
  })

  it('returns structured output without server paths', async () => {
    const result = await readFileHandler({ site: 'example.com', path: './wp-content/../index.php', maxBytes: 1000 })
    expect(result).toEqual({
      site: 'example.com',
      path: 'index.php',
      content: '<?php echo 1;',
      bytes: Buffer.byteLength('<?php echo 1;'),
      truncated: false,
      redactedLines: 0,
      retrievedAt: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T/)
    })
    expect(JSON.stringify(result)).not.toContain('/var/')
  })

  it('reads a nested file', async () => {
    const result = await readFileHandler({ site: 'example.com', path: 'wp-content/plugins/example/readme.txt' })
    expect(result.content).toBe('readme')
    expect(result.path).toBe('wp-content/plugins/example/readme.txt')
  })

  it('follows a symlink that stays inside the root and reports the canonical path', async () => {
    const result = await readFileHandler({ site: 'example.com', path: 'wp-content/link-inside.txt' })
    expect(result.content).toBe('<?php echo 1;')
    expect(result.path).toBe('index.php')
  })

  it('works when the configured root is itself a symlink', async () => {
    const result = await readFileHandler({ site: 'linkroot.example', path: 'index.php' })
    expect(result.content).toBe('<?php // release 1')
  })
})

describe('read_file confinement', () => {
  async function refusedWithoutNetwork(input) {
    let err
    const { before, after } = await countNetwork(fake, closeAll, async () => {
      err = await failure(input)
    })
    expect(err.message).toBe(NOT_AVAILABLE)
    expect(after).toEqual(before)
    expect(fake.events.ops).toEqual([])
  }

  it('rejects a path traversal attempt before any connection or SFTP session', async () => {
    await refusedWithoutNetwork({ site: 'example.com', path: '../../etc/passwd', maxBytes: 1000 })
  })

  it('rejects absolute path input before any connection or SFTP session', async () => {
    await refusedWithoutNetwork({ site: 'example.com', path: '/etc/passwd', maxBytes: 1000 })
  })

  it.each([
    ['../public-backup/wp-config.php'],
    ['wp-content/../../public-backup/wp-config.php'],
    ['wp-config.php\0.txt'],
    ['.'],
    ['wp-content/..']
  ])('rejects %j lexically before any connection or SFTP session', async path => {
    await refusedWithoutNetwork({ site: 'example.com', path })
  })

  it.each([
    ['wp-content/link-out.txt'],
    ['wp-content/link-sibling.txt'],
    ['wp-content/link-relative.txt'],
    ['wp-content/uploads/secret.txt'],
    ['wp-content/loop-a']
  ])('rejects the symlink escape %j without opening the target', async path => {
    const err = await failure({ site: 'example.com', path })
    expect(err.message).toBe(NOT_AVAILABLE)
    expect(fake.events.opens).toEqual([])
  })

  it('refuses a realpath reply that is not canonical instead of normalising it', async () => {
    const err = await failure({ site: 'example.com', path: 'wp-content/odd.php' })
    expect(err.message).toBe(NOT_AVAILABLE)
    expect(fake.events.ops.filter(o => o.op === 'OPEN' || o.op === 'LSTAT')).toEqual([])
  })

  it('refuses a file whose type on the open handle is not regular, closes the handle and reads nothing', async () => {
    const err = await failure({ site: 'example.com', path: 'wp-content/type-change.txt' })
    expect(err.message).toBe(NOT_AVAILABLE)
    const ops = fake.events.ops.map(o => o.op)
    expect(ops).toContain('OPEN')
    expect(ops).toContain('FSTAT')
    expect(ops).not.toContain('READ')
    expect(ops.at(-1)).toBe('CLOSE')
    expect(fake.events.openHandles).toBe(0)
    expect(JSON.stringify(err)).not.toContain('SWAPPED')
  })

  it.each([['wp-content'], ['wp-content/plugins'], ['wp-content/missing.php']])(
    'rejects %j, which is not a regular file, without sending OPEN', async path => {
      const err = await failure({ site: 'example.com', path })
      expect(err.message).toBe(NOT_AVAILABLE)
      expect(fake.events.ops.filter(o => o.op === 'OPEN')).toEqual([])
    }
  )

  it.each([['unknown.example'], ['__proto__'], ['constructor'], ['toString'], ['hasOwnProperty']])(
    'refuses site %j before any connection or SFTP session', async site => {
      let err
      const { before, after } = await countNetwork(fake, closeAll, async () => {
        err = await failure({ site, path: 'wp-config.php' })
      })
      expect(err.message).toBe(NOT_AVAILABLE)
      expect(after).toEqual(before)
      expect(fake.events.ops).toEqual([])
    }
  )

  it('gives byte-identical refusals for unknown site, escape, sensitive file, missing file and directory', async () => {
    const messages = new Set()
    for (const input of [
      { site: 'unknown.example', path: 'wp-config.php' },
      { site: 'example.com', path: 'wp-config.php' },
      { site: 'example.com', path: 'wp-content/link-sibling.txt' },
      { site: 'example.com', path: '../../etc/passwd' },
      { site: 'example.com', path: 'wp-content/link-out.txt' },
      { site: 'example.com', path: 'wp-content/missing.php' },
      { site: 'example.com', path: 'wp-content' }
    ]) {
      messages.add((await failure(input)).message)
    }
    expect(messages).toEqual(new Set([NOT_AVAILABLE]))
  })

  it('never echoes caller input, server paths or remote text in errors', async () => {
    const cases = [
      { site: 'unknown-marker.example', path: 'path-marker.php' },
      { site: 'example.com', path: '../path-marker/../../etc/passwd' },
      { site: 'example.com', path: 'wp-content/link-out.txt' },
      { site: 'example.com', path: 'wp-content/path-marker.php' },
      { site: 'example.com', path: 'wp-config.php', maxBytes: 'marker' },
      { site: 'example.com', path: 'p'.repeat(1025) }
    ]
    for (const input of cases) {
      const err = await failure(input)
      expect(err.message).toMatch(/^E_[A-Z_]+: [A-Za-z .]+$/)
      for (const forbidden of ['marker', 'example', 'link-out', 'wp-content', '/var', '/etc', 'CANARY', 'ppp']) {
        expect(err.message).not.toContain(forbidden)
      }
    }
  })
})

describe('read_file byte limits', () => {
  it('caps maxBytes at 51200', async () => {
    const result = await readFileHandler({ site: 'example.com', path: 'wp-content/big.txt', maxBytes: 999999 })
    expect(result.bytes).toBe(MAX_BYTES)
    expect(result.content).toHaveLength(MAX_BYTES)
    expect(result.truncated).toBe(true)
    expect(fake.events.readBytesServed).toBeLessThanOrEqual(MAX_BYTES + 1)
  })

  it('returns at most maxBytes and flags truncation', async () => {
    const result = await readFileHandler({ site: 'example.com', path: 'wp-content/big.txt', maxBytes: 1000 })
    expect(result.content).toBe('b'.repeat(1000))
    expect(result.truncated).toBe(true)
  })

  it('does not flag a file of exactly maxBytes as truncated', async () => {
    const exact = await readFileHandler({ site: 'example.com', path: 'wp-content/exact.txt', maxBytes: 100 })
    expect(exact.bytes).toBe(100)
    expect(exact.truncated).toBe(false)
    const shorter = await readFileHandler({ site: 'example.com', path: 'wp-content/exact.txt', maxBytes: 99 })
    expect(shorter.truncated).toBe(true)
  })

  it.each([
    // maxBytes, expected content: 99 ASCII bytes, then 2-, 3- and 4-byte characters
    [100, 'a'.repeat(99)],
    [101, 'a'.repeat(99) + '\u00e9'],
    [103, 'a'.repeat(99) + '\u00e9'],
    [104, 'a'.repeat(99) + '\u00e9\u20ac'],
    [107, 'a'.repeat(99) + '\u00e9\u20ac'],
    [108, 'a'.repeat(99) + '\u00e9\u20ac\u{1F600}']
  ])('cuts at maxBytes %i without splitting a character', async (maxBytes, expected) => {
    const result = await readFileHandler({ site: 'example.com', path: 'wp-content/multibyte.txt', maxBytes })
    expect(result.content).toBe(expected)
    expect(result.bytes).toBe(Buffer.byteLength(expected))
    expect(result.truncated).toBe(true)
    expect(result.content).not.toContain('\ufffd')
  })

  it('leaves bytes that are not valid UTF-8 anyway untouched', () => {
    expect(utf8BoundaryLength(Buffer.from([0x61, 0x80, 0x80]))).toBe(3)
    expect(utf8BoundaryLength(Buffer.from([0x61, 0xc3]))).toBe(1)
    expect(utf8BoundaryLength(Buffer.from([]))).toBe(0)
  })

  it.each([[0], [-1], [1.5], ['100']])('refuses maxBytes %j with E_INVALID_INPUT', async maxBytes => {
    const err = await failure({ site: 'example.com', path: 'wp-config.php', maxBytes })
    expect(err.code).toBe('E_INVALID_INPUT')
    expect(fake.events.ops).toEqual([])
  })

  it('stops an endless file at the cap and closes the SFTP session', async () => {
    const result = await readFileHandler({ site: 'example.com', path: 'wp-content/endless.bin', maxBytes: 999999 })
    expect(result.bytes).toBe(MAX_BYTES)
    expect(result.truncated).toBe(true)
    expect(fake.events.readBytesServed).toBeLessThanOrEqual(MAX_BYTES + 1)
    await fake.waitFor(() => fake.openSftpSessions() === 0)
  })

  it('times out a read that never answers and closes the SFTP session', async () => {
    const started = Date.now()
    const err = await failure({ site: 'example.com', path: 'wp-content/slow.txt' }, { timeoutMs: 300 })
    expect(err.message).toBe('E_TIMEOUT: The operation timed out.')
    expect(Date.now() - started).toBeLessThan(2000)
    expect(fake.events.pendingReads).toBe(1)
    await fake.waitFor(() => fake.openSftpSessions() === 0)
  })
})

describe('read_file never executes', () => {
  it('sends no exec, shell or write request, whatever the path contains', async () => {
    for (const path of ['wp-config.php', 'x; id', '$(touch x)', '`id`', 'a | sh', 'a\nid', "x' && id '"]) {
      await readFileHandler({ site: 'example.com', path }).catch(() => {})
    }
    expect(fake.events.sessionRequests).toEqual([])
    expect(nonSftpRequests(fake)).toEqual(NO_NON_SFTP_REQUESTS)
    expect(fake.events.ops.filter(o => o.op === 'OPEN').every(o => o.flags === 1)).toBe(true)
  })
})
