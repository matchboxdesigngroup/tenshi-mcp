import { describe, it, expect, beforeAll, afterAll, afterEach } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync } from 'fs'
import os from 'os'
import path from 'path'
import { fileURLToPath } from 'url'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StdioClientTransport, getDefaultEnvironment } from '@modelcontextprotocol/sdk/client/stdio.js'
import {
  startFakeSftpServer,
  loadFakeRegistry,
  fakeServerEntry,
  nonSftpRequests,
  countNetwork,
  NO_NON_SFTP_REQUESTS
} from './helpers/fake-sftp-server.js'
import { readFileHandler } from '../src/tools/read-file.js'
import { readLogHandler, WINDOW_BYTES } from '../src/tools/read-log.js'
import { REDACTED_LINE } from '../src/policy/redact.js'
import { closeAll } from '../src/ssh/client.js'

// Acceptance fixtures for canonical-path confinement and the sensitive-file
// policy, against the in-process SFTP fake: symlink out of the root, symlink
// loop, swapped links and files, hard links, traversal encodings, sensitive
// names in case and extension variants, allowlist misses and redaction. Every
// refusal must be byte-identical to "not found". All paths and values are
// fake: they exist only in the fake's tree.

const NOT_AVAILABLE = 'E_NOT_AVAILABLE: The requested resource is not available.'

const ROOT = '/var/www/policy.example/public'
const DEMO = `${ROOT}/wp-content/plugins/demo`
const OPEN_ROOT = '/var/www/open/public'
const LOG_ROOT = '/var/www/logs/public'
const LOG_DIR = '/var/log/sites/logs'

/** Never opened by any test. */
const CANARY = '/srv/canary/secret.txt'

// Fake credentials: every value contains FAKESECRET so a leak is easy to spot.
const CREDENTIALS = [
  '<?php',
  "define( 'DB_NAME', 'example' );",
  "define( 'DB_PASSWORD', 'FAKESECRET-db-pass' );",
  "define( 'AUTH_KEY', 'FAKESECRET-auth-key' );",
  "$url = 'mysql://user:FAKESECRET-url-pass@db.example.com/wp';",
  '-----BEGIN PRIVATE KEY-----',
  'FAKESECRET0keyBodyLine0123456789abcdefABCDEF0123456789abcdefAB',
  '-----END PRIVATE KEY-----',
  "echo 'ordinary line';"
].join('\n') + '\n'

/** One node under two names is a hard link (see the fake's header). */
const HARDLINKED_CREDENTIALS = { content: CREDENTIALS }
const HARDLINKED_OUTSIDE = { content: 'HARDLINK-OUTSIDE ordinary text\n' }

const DEBUG_LOG = [
  'PHP Notice: something ordinary',
  "PHP Warning: config dump define( 'DB_PASSWORD', 'FAKESECRET-log-pass' );",
  'Authorization: Bearer FAKESECRET-bearer-token',
  'PHP Notice: another ordinary line'
].join('\n') + '\n'

// An error log larger than the tail window whose window starts inside a key
// block: the BEGIN line is outside the window, the body lines inside it.
const KEY_BODY = Array.from({ length: Math.ceil((WINDOW_BYTES + 4096) / 65) },
  (_, i) => `Ab3${String(i).padStart(6, '0')}`.padEnd(64, 'xY9')).join('\n')
const KEY_LOG = '-----BEGIN RSA PRIVATE KEY-----\n' + KEY_BODY + '\n-----END RSA PRIVATE KEY-----\nlog line after the key\n'

/** Denied names, each with an allowed extension in an allowed directory of open.example. */
const SENSITIVE_VARIANTS = [
  'wp-config.php', 'WP-CONFIG.PHP', 'Wp-Config.php', 'wp-config-sample.php', 'wp-config.php.txt', 'wp_config.php',
  'wp-config.php.bak.txt', 'index.php.bak.txt', 'dump.sql.txt', 'export.SQL.php', 'secrets.php', 'credentials.txt',
  'backups/site.php', 'wp-content/ai1wm-backups/a.txt', 'id_rsa.txt', 'server.key.txt', 'passwords.txt'
]

const SITES = {
  'policy.example': {
    wordpressRoot: ROOT,
    logDir: '/var/log/sites/policy',
    allow: { extensions: ['.php', '.txt'], directories: ['wp-content/plugins'] }
  },
  // Every directory allowed, so only the denylist can refuse.
  'open.example': {
    wordpressRoot: OPEN_ROOT,
    logDir: '/var/log/sites/open',
    allow: { extensions: ['.php', '.txt'], directories: ['.'] }
  },
  'logs.example': {
    wordpressRoot: LOG_ROOT,
    logDir: LOG_DIR,
    allow: { extensions: ['.php'], directories: ['wp-content/plugins'] }
  },
  // The server answers realpath of the root with a doubled slash.
  'dslash.example': {
    wordpressRoot: '/var/www/dslash/public',
    logDir: '/var/log/sites/dslash',
    allow: { extensions: ['.php'], directories: ['.'] }
  },
  // The configured root is a link to the file-system root.
  'slashroot.example': {
    wordpressRoot: '/var/www/slashroot',
    logDir: '/var/log/sites/slashroot',
    allow: { extensions: ['.txt'], directories: ['.'] }
  }
}

let fake
let restoreRegistry
let notFoundJson

beforeAll(async () => {
  fake = await startFakeSftpServer({
    files: {
      [`${DEMO}/readme.txt`]: { content: 'readme' },
      [`${DEMO}/settings.php`]: { content: CREDENTIALS },
      [`${DEMO}/link-out.txt`]: { symlink: CANARY },
      [`${DEMO}/loop-a.txt`]: { symlink: 'loop-b.txt' },
      [`${DEMO}/loop-b.txt`]: { symlink: 'loop-a.txt' },
      [`${DEMO}/to-root.txt`]: { symlink: '../../../index.txt' },
      [`${DEMO}/data.csv`]: { content: 'a,b' },
      [`${DEMO}/README`]: { content: 'no extension' },
      [`${ROOT}/index.txt`]: { content: 'root file, directory not allowed' },
      [`${ROOT}/wp-content/plugins-extra/x.txt`]: { content: 'sibling prefix' },
      [`${ROOT}/wp-content/themes/t/functions.php`]: { content: '<?php' },
      // swapped while a call runs (see the swap tests)
      [`${DEMO}/swap-link.txt`]: { content: 'benign' },
      [`${DEMO}/swap-file.txt`]: { content: 'benign' },
      [`${DEMO}/swap-early.txt`]: { content: 'benign' },
      [`${ROOT}/wp-content/plugins/swapdir/readme.txt`]: { content: 'benign' },
      '/srv/swap/secret-a.txt': { content: 'SWAP-CANARY-A' },
      '/srv/swap/secret-d.txt': { content: 'SWAP-CANARY-D' },
      '/srv/swap/dir/readme.txt': { content: 'SWAP-CANARY-C' },
      // hard links
      [`${DEMO}/notes.txt`]: HARDLINKED_CREDENTIALS,
      [`${OPEN_ROOT}/wp-config.php`]: HARDLINKED_CREDENTIALS,
      [`${DEMO}/wp-config-copy.txt`]: HARDLINKED_CREDENTIALS,
      [`${DEMO}/outside-hardlink.txt`]: HARDLINKED_OUTSIDE,
      '/srv/elsewhere/file.txt': HARDLINKED_OUTSIDE,

      ...Object.fromEntries(SENSITIVE_VARIANTS.filter(p => p !== 'wp-config.php')
        .map(p => [`${OPEN_ROOT}/${p}`, { content: 'SENSITIVE-CONTENT' }])),
      [`${OPEN_ROOT}/wp-content/plugins/demo/cfg-link.txt`]: { symlink: '../../../wp-config.php' },
      [`${OPEN_ROOT}/index.php`]: { content: '<?php // open index' },
      [`${OPEN_ROOT}/dslash-target.php`]: { content: 'DSLASH-TARGET', realpathReply: `${OPEN_ROOT}//dslash-target.php` },

      [`${LOG_ROOT}/wp-content/debug.log`]: { content: DEBUG_LOG },
      [`${LOG_DIR}/logs.example.error.log`]: { content: KEY_LOG },

      '/var/www/dslash/public': { dir: true, realpathReply: '/var/www//dslash/public' },
      '/var/www/dslash/public/index.php': { content: 'DSLASH-ROOT' },
      '/var/www/slashroot': { symlink: '/' },
      '/etc/fake-passwd.txt': { content: 'SLASHROOT-CANARY' },

      [CANARY]: { content: 'CANARY' }
    }
  })
  restoreRegistry = await loadFakeRegistry(fake, SITES)
  // Reference "not found" refusal, taken once so refused() adds no requests.
  const missing = await readFileHandler({ site: 'policy.example', path: 'wp-content/plugins/demo/missing.txt' }).then(() => null, e => e)
  notFoundJson = JSON.stringify(missing)
  fake.resetEvents()
})

afterEach(() => {
  // Reset first so a failure is reported only for the test that caused it.
  const seen = nonSftpRequests(fake)
  const opens = [...fake.events.opens]
  fake.resetEvents()
  expect(seen).toEqual(NO_NON_SFTP_REQUESTS)
  expect(opens).not.toContain(CANARY)
})

afterAll(async () => {
  closeAll()
  restoreRegistry?.()
  await fake?.close()
})

async function failure(promise) {
  const err = await promise.then(() => null, e => e)
  expect(err).not.toBeNull()
  return err
}

/** The refusal, checked to be exactly "not found" and nothing else. */
async function refused(promise) {
  const err = await failure(promise)
  expect(err.message).toBe(NOT_AVAILABLE)
  expect(err.code).toBe('E_NOT_AVAILABLE')
  expect(JSON.stringify(err)).toBe(notFoundJson)
  return err
}

const ops = () => fake.events.ops.map(o => o.op)

describe('symlinks', () => {
  it('serves a plain file in an allowed directory (positive control)', async () => {
    const result = await readFileHandler({ site: 'policy.example', path: 'wp-content/plugins/demo/readme.txt' })
    expect(result.content).toBe('readme')
    expect(result.redactedLines).toBe(0)
  })

  it('refuses a symlink to a file outside the root without opening it', async () => {
    await refused(readFileHandler({ site: 'policy.example', path: 'wp-content/plugins/demo/link-out.txt' }))
    expect(ops()).not.toContain('OPEN')
  })

  it('refuses a symlink loop without opening anything', async () => {
    await refused(readFileHandler({ site: 'policy.example', path: 'wp-content/plugins/demo/loop-a.txt' }))
    expect(ops()).not.toContain('OPEN')
  })

  it('refuses a symlink with an allowed name that points into a directory the allowlist does not cover', async () => {
    await refused(readFileHandler({ site: 'policy.example', path: 'wp-content/plugins/demo/to-root.txt' }))
    expect(ops()).not.toContain('OPEN')
  })

  it('refuses a symlink with an allowed name that points at a denied file', async () => {
    await refused(readFileHandler({ site: 'open.example', path: 'wp-content/plugins/demo/cfg-link.txt' }))
    expect(ops()).not.toContain('OPEN')
  })
})

describe('swapped links and files (check then open)', () => {
  it('refuses a file swapped for a link to outside between lstat and open, and reads nothing', async () => {
    const target = `${DEMO}/swap-link.txt`
    fake.afterOp('LSTAT', target, () => fake.setEntry(target, { symlink: '/srv/swap/secret-a.txt' }))
    const err = await refused(readFileHandler({ site: 'policy.example', path: 'wp-content/plugins/demo/swap-link.txt' }))
    // Residual made visible: SFTP v3 cannot stop the server from following
    // the new link at OPEN. The post-open realpath check refuses the handle
    // before any byte is read.
    expect(fake.events.opens).toEqual(['/srv/swap/secret-a.txt'])
    expect(ops()).not.toContain('READ')
    expect(ops().at(-1)).toBe('CLOSE')
    expect(fake.events.openHandles).toBe(0)
    expect(JSON.stringify(err)).not.toContain('SWAP-CANARY')
  })

  it('refuses a file replaced by one with another owner and mode between lstat and open', async () => {
    const target = `${DEMO}/swap-file.txt`
    fake.afterOp('LSTAT', target, () => fake.setEntry(target, { content: 'SWAP-OTHER-OWNER', uid: 0, gid: 0, perm: 0o600 }))
    await refused(readFileHandler({ site: 'policy.example', path: 'wp-content/plugins/demo/swap-file.txt' }))
    expect(ops()).not.toContain('READ')
    expect(fake.events.openHandles).toBe(0)
  })

  it('refuses when a parent directory is swapped for a link to outside between lstat and open', async () => {
    const target = `${ROOT}/wp-content/plugins/swapdir/readme.txt`
    fake.afterOp('LSTAT', target, () => fake.setEntry(`${ROOT}/wp-content/plugins/swapdir`, { symlink: '/srv/swap/dir' }))
    await refused(readFileHandler({ site: 'policy.example', path: 'wp-content/plugins/swapdir/readme.txt' }))
    expect(fake.events.opens).toEqual(['/srv/swap/dir/readme.txt'])
    expect(ops()).not.toContain('READ')
    expect(fake.events.openHandles).toBe(0)
  })

  it('refuses a file swapped for a link between realpath and lstat without sending OPEN', async () => {
    const target = `${DEMO}/swap-early.txt`
    fake.afterOp('REALPATH', target, () => fake.setEntry(target, { symlink: '/srv/swap/secret-d.txt' }))
    await refused(readFileHandler({ site: 'policy.example', path: 'wp-content/plugins/demo/swap-early.txt' }))
    expect(ops()).toContain('LSTAT')
    expect(ops()).not.toContain('OPEN')
  })

  it('re-checks realpath after the open on every successful read', async () => {
    await readFileHandler({ site: 'policy.example', path: 'wp-content/plugins/demo/readme.txt' })
    const sequence = ops()
    expect(sequence.indexOf('REALPATH', sequence.indexOf('FSTAT'))).toBeGreaterThan(sequence.indexOf('FSTAT'))
    expect(sequence.indexOf('READ')).toBeGreaterThan(sequence.lastIndexOf('REALPATH'))
  })
})

describe('hard links', () => {
  it('refuses a hard link whose own name is sensitive, whatever it points at', async () => {
    await refused(readFileHandler({ site: 'policy.example', path: 'wp-content/plugins/demo/wp-config-copy.txt' }))
    expect(ops()).toEqual([])
  })

  it('redacts credential lines from a hard link with an ordinary name to a credentials file', async () => {
    const result = await readFileHandler({ site: 'policy.example', path: 'wp-content/plugins/demo/notes.txt' })
    expect(result.content).not.toContain('FAKESECRET')
    expect(result.content).toContain("echo 'ordinary line';")
    expect(result.redactedLines).toBe(6)
  })

  it('documents the residual: a hard link to a file outside the root cannot be detected over SFTP v3', async () => {
    // The attributes carry no link count or inode, so the name inside the
    // root is all the client can check. Server-side confinement is the
    // backstop (see src/ssh/confine.js).
    const result = await readFileHandler({ site: 'policy.example', path: 'wp-content/plugins/demo/outside-hardlink.txt' })
    expect(result.content).toBe('HARDLINK-OUTSIDE ordinary text\n')
  })
})

describe('traversal encodings', () => {
  const ENCODED = [
    ['percent-encoded dots', '%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/fake-passwd.txt'],
    ['percent-encoded slash', 'wp-content/plugins/demo/..%2f..%2f..%2findex.txt'],
    ['double-encoded dots', '%252e%252e/index.txt'],
    ['overlong UTF-8 dot', '%c0%ae%c0%ae/index.txt'],
    ['doubled slashes around dot-dot', 'wp-content//..//..//..//etc/fake-passwd.txt'],
    ['leading double slash', '//etc/fake-passwd.txt'],
    ['backslash separators', 'wp-content\\plugins\\demo\\..\\..\\..\\index.txt'],
    ['backslash in a name', 'wp-content/plugins/demo/a\\b.txt'],
    ['NUL before an allowed extension', 'wp-config.php\u0000.txt'],
    ['NUL alone', 'wp-content/plugins/demo/readme.txt\u0000'],
    ['two-dot leader', '‥/‥/index.txt'],
    ['full-width dots', '．．/．．/index.txt'],
    ['full-width solidus', '..／..／index.txt'],
    ['full-width reverse solidus', '..＼..＼index.txt'],
    ['small full stop', '﹒﹒/index.txt'],
    ['right-to-left override', 'wp-content/plugins/demo/‮txt.php'],
    ['zero-width space', 'wp-content/plugins/demo/read​me.txt'],
    ['line separator', 'wp-content/plugins/demo/read me.txt'],
    ['unpaired surrogate', 'wp-content/plugins/demo/\ud800.txt'],
    ['newline', 'wp-content/plugins/demo/readme.txt\n../../index.txt'],
    ['dot-dot escaping the root', '../../policy.example-backup/wp-config.php']
  ]

  it.each(ENCODED)('refuses %s before any connection or SFTP session', async (_, p) => {
    let err
    const { before, after } = await countNetwork(fake, closeAll, async () => {
      err = await failure(readFileHandler({ site: 'policy.example', path: p }))
    })
    expect(err.message).toBe(NOT_AVAILABLE)
    expect(after).toEqual(before)
    expect(fake.events.ops).toEqual([])
  })

  it('accepts a doubled slash that stays inside the root (it is not traversal)', async () => {
    const result = await readFileHandler({ site: 'policy.example', path: 'wp-content//plugins/demo//readme.txt' })
    expect(result.path).toBe('wp-content/plugins/demo/readme.txt')
  })
})

describe('sensitive names', () => {
  it.each(SENSITIVE_VARIANTS.map(p => [p]))('refuses %j before any connection, although the allowlist covers it', async p => {
    let err
    const { before, after } = await countNetwork(fake, closeAll, async () => {
      err = await failure(readFileHandler({ site: 'open.example', path: p }))
    })
    expect(err.message).toBe(NOT_AVAILABLE)
    expect(after).toEqual(before)
  })

  it('serves an ordinary file of the same site (positive control)', async () => {
    const result = await readFileHandler({ site: 'open.example', path: 'index.php' })
    expect(result.content).toBe('<?php // open index')
  })
})

describe('allowlist', () => {
  it.each([
    ['a directory not listed', 'index.txt'],
    ['a theme directory not listed', 'wp-content/themes/t/functions.php'],
    ['a sibling sharing the string prefix', 'wp-content/plugins-extra/x.txt'],
    ['an extension not listed', 'wp-content/plugins/demo/data.csv'],
    ['a file without extension', 'wp-content/plugins/demo/README']
  ])('refuses %s before any connection', async (_, p) => {
    let err
    const { before, after } = await countNetwork(fake, closeAll, async () => {
      err = await failure(readFileHandler({ site: 'policy.example', path: p }))
    })
    expect(err.message).toBe(NOT_AVAILABLE)
    expect(after).toEqual(before)
  })
})

describe('canonical root and target replies', () => {
  it('refuses a realpath reply for the root with a doubled slash', async () => {
    await refused(readFileHandler({ site: 'dslash.example', path: 'index.php' }))
    expect(ops()).toEqual(['REALPATH'])
  })

  it('refuses a realpath reply for the target with a doubled slash', async () => {
    await refused(readFileHandler({ site: 'open.example', path: 'dslash-target.php' }))
    expect(ops()).not.toContain('OPEN')
  })

  it('refuses a root that resolves to the file-system root', async () => {
    await refused(readFileHandler({ site: 'slashroot.example', path: 'etc/fake-passwd.txt' }))
    expect(ops()).toEqual(['REALPATH'])
  })
})

describe('redaction', () => {
  it('redacts credential lines from read_file output and reports only the count', async () => {
    const result = await readFileHandler({ site: 'policy.example', path: 'wp-content/plugins/demo/settings.php' })
    expect(result.content).not.toContain('FAKESECRET')
    expect(result.content.split('\n')).toEqual([
      '<?php', "define( 'DB_NAME', 'example' );", REDACTED_LINE, REDACTED_LINE, REDACTED_LINE,
      REDACTED_LINE, REDACTED_LINE, REDACTED_LINE, "echo 'ordinary line';", ''
    ])
    expect(result.redactedLines).toBe(6)
    expect(result.bytes).toBe(Buffer.byteLength(result.content))
  })

  it('redacts a credential line cut by maxBytes', async () => {
    const cut = CREDENTIALS.indexOf('FAKESECRET-db-pass') + 4
    const result = await readFileHandler({ site: 'policy.example', path: 'wp-content/plugins/demo/settings.php', maxBytes: cut })
    expect(result.truncated).toBe(true)
    expect(result.content).not.toContain('FAKE')
    expect(result.content.endsWith(REDACTED_LINE)).toBe(true)
  })

  it('redacts read_log lines before the filter, so a filter cannot probe a secret', async () => {
    const all = await readLogHandler({ site: 'logs.example', log: 'debug', lines: 50 })
    expect(all.content).not.toContain('FAKESECRET')
    expect(all.redactedLines).toBe(2)
    expect(all.returnedLines).toBe(4)
    for (const filter of ['FAKESECRET', 'FAKESECRET-log-pass', 'FAKESECRET-b', 'DB_PASSWORD', 'Bearer']) {
      const probe = await readLogHandler({ site: 'logs.example', log: 'debug', lines: 50, filter })
      expect(probe.returnedLines).toBe(0)
      expect(probe.redactedLines).toBe(0)
    }
  })

  it('redacts key body lines of a log window that starts inside a key block', async () => {
    const result = await readLogHandler({ site: 'logs.example', log: 'error', lines: 500 })
    expect(result.truncated.window).toBe(true)
    expect(result.content).not.toMatch(/Ab3\d{6}/)
    expect(result.content.split('\n').at(-1)).toBe('log line after the key')
    expect(result.redactedLines).toBe(result.returnedLines - 1)
  })
})

describe('refusals are byte-identical to not found', () => {
  const CASES = {
    'not found': { site: 'policy.example', path: 'wp-content/plugins/demo/missing.txt' },
    'unknown site': { site: 'unknown.example', path: 'wp-content/plugins/demo/readme.txt' },
    'prototype site name': { site: 'constructor', path: 'wp-content/plugins/demo/readme.txt' },
    'outside root (symlink)': { site: 'policy.example', path: 'wp-content/plugins/demo/link-out.txt' },
    'outside root (lexical)': { site: 'policy.example', path: '../../etc/fake-passwd.txt' },
    'symlink loop': { site: 'policy.example', path: 'wp-content/plugins/demo/loop-a.txt' },
    'sensitive (lexical)': { site: 'open.example', path: 'wp-config.php' },
    'sensitive (resolved)': { site: 'open.example', path: 'wp-content/plugins/demo/cfg-link.txt' },
    'allowlist miss': { site: 'policy.example', path: 'index.txt' },
    'traversal encoding': { site: 'policy.example', path: '%2e%2e/index.txt' }
  }

  it('in the handler: same message, code and serialisation for every refusal', async () => {
    const seen = new Set()
    for (const input of Object.values(CASES)) {
      const err = await failure(readFileHandler(input))
      seen.add(JSON.stringify({ message: err.message, code: err.code, name: err.name, json: JSON.stringify(err), keys: Object.keys(err) }))
    }
    expect(seen.size).toBe(1)
    expect([...seen][0]).toContain(NOT_AVAILABLE)
  })

  it('over the MCP protocol: identical tool results for every refusal', async () => {
    const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
    const dir = mkdtempSync(path.join(os.tmpdir(), 'tenshi-mcp-policy-'))
    const registryPath = path.join(dir, 'registry.json')
    writeFileSync(registryPath, JSON.stringify({ servers: [fakeServerEntry(fake, SITES)] }))
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [path.join(repoRoot, 'src', 'index.js')],
      cwd: dir,
      env: { ...getDefaultEnvironment(), TENSHI_MCP_SERVERS_PATH: registryPath },
      stderr: 'pipe'
    })
    const client = new Client({ name: 'tenshi-mcp-policy-test', version: '0.0.0' })
    try {
      await client.connect(transport)
      const results = new Map()
      for (const [name, args] of Object.entries(CASES)) {
        results.set(name, JSON.stringify(await client.callTool({ name: 'read_file', arguments: args })))
      }
      expect(new Set(results.values()).size).toBe(1)
      expect(JSON.parse(results.get('not found'))).toEqual({
        content: [{ type: 'text', text: `Error: ${NOT_AVAILABLE}` }],
        isError: true
      })
      // The server is reachable through the child: a real read succeeds.
      const ok = await client.callTool({ name: 'read_file', arguments: { site: 'policy.example', path: 'wp-content/plugins/demo/readme.txt' } })
      expect(ok.isError).toBeFalsy()
    } finally {
      await client.close()
      rmSync(dir, { recursive: true, force: true })
    }
  }, 30000)
})
