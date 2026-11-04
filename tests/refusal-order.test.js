import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import {
  startFakeSftpServer,
  loadFakeRegistry,
  countNetwork,
  startCountingSink,
  TEST_ALLOW
} from './helpers/fake-sftp-server.js'
import { readFileHandler } from '../src/tools/read-file.js'
import { readLogHandler } from '../src/tools/read-log.js'
import { closeAll } from '../src/ssh/client.js'
import { lookupSite } from '../src/tools/site.js'

// Refusals that need no server (unknown or prototype site names, paths that
// leave the root lexically) happen before any network activity: no SSH
// connection, no SFTP session, and the same E_NOT_AVAILABLE whether or not
// the server is reachable.

const ROOT = '/var/www/example.com/public'
const NOT_AVAILABLE = 'E_NOT_AVAILABLE: The requested resource is not available.'

const LEXICALLY_INVALID = [
  '../../etc/passwd',
  '/etc/passwd',
  'wp-config.php\0.txt',
  '.',
  'wp-content/..',
  '../public-backup/wp-config.php'
]
const PROTOTYPE_NAMES = ['__proto__', 'constructor', 'toString', 'hasOwnProperty']

let fake
let sink
let restoreRegistry

beforeAll(async () => {
  fake = await startFakeSftpServer({
    files: {
      [`${ROOT}/index.php`]: { content: '<?php' },
      '/var/log/nginx/example.com.error.log': { content: 'line\n' }
    }
  })
  sink = await startCountingSink()
  restoreRegistry = await loadFakeRegistry(fake, {
    'example.com': { wordpressRoot: ROOT, logDir: '/var/log/nginx' }
  }, 'fake-server', [{
    id: 'unreachable-server',
    label: 'Unreachable server',
    host: sink.host,
    port: sink.port,
    user: fake.username,
    privateKeyPath: fake.clientKeyPath,
    hostKeys: [fake.hostKeyFingerprint],
    sites: {
      // A site name that would place the error and access logs outside
      // logDir is refused when the registry loads (tests/config.test.js);
      // the tools also check log paths lexically.
      'unreachable.example': {
        wordpressRoot: ROOT,
        logDir: '/var/log/nginx',
        allow: { extensions: ['.php', '.txt'], directories: ['wp-content/plugins'] }
      }
    }
  }])
})

afterAll(async () => {
  closeAll()
  restoreRegistry?.()
  await sink?.close()
  await fake?.close()
})

async function refusal(promise) {
  const err = await promise.then(() => null, e => e)
  expect(err).not.toBeNull()
  return err.message
}

describe('lookupSite', () => {
  // The handlers also refuse a missing root lexically; this pins the site
  // guard itself so it does not rely on that second layer.
  it.each(PROTOTYPE_NAMES.map(n => [n]))('refuses %j as E_NOT_AVAILABLE', name => {
    expect(() => lookupSite(name)).toThrow(NOT_AVAILABLE)
  })

  it('returns string roots for a configured site', () => {
    expect(lookupSite('example.com')).toEqual({ serverId: 'fake-server', wordpressRoot: ROOT, logDir: '/var/log/nginx', allow: TEST_ALLOW })
  })
})

describe('refusals before any network activity (reachable server)', () => {
  it.each(LEXICALLY_INVALID.map(p => [p]))('read_file path %j opens no connection and no SFTP session', async path => {
    let message
    const { before, after } = await countNetwork(fake, closeAll, async () => {
      message = await refusal(readFileHandler({ site: 'example.com', path }))
    })
    expect(message).toBe(NOT_AVAILABLE)
    expect(after).toEqual(before)
  })

  it('an over-long path fails argument validation without network activity', async () => {
    let message
    const { before, after } = await countNetwork(fake, closeAll, async () => {
      message = await refusal(readFileHandler({ site: 'example.com', path: 'p'.repeat(1025) }))
    })
    expect(message).toBe('E_INVALID_INPUT: The tool arguments are invalid.')
    expect(after).toEqual(before)
  })

  it.each(PROTOTYPE_NAMES.map(n => [n]))('site %j opens no connection and no SFTP session in either tool', async site => {
    const messages = []
    const { before, after } = await countNetwork(fake, closeAll, async () => {
      messages.push(await refusal(readFileHandler({ site, path: 'index.php' })))
      messages.push(await refusal(readLogHandler({ site, log: 'error', lines: 5 })))
    })
    expect(messages).toEqual([NOT_AVAILABLE, NOT_AVAILABLE])
    expect(after).toEqual(before)
  })

  it('counts a real call, so the unchanged counters above are meaningful', async () => {
    const { before, after } = await countNetwork(fake, closeAll, async () => {
      await readFileHandler({ site: 'example.com', path: 'index.php' })
    })
    expect(after.connections).toBe(before.connections + 1)
    expect(after.sftpSessionsOpened).toBe(before.sftpSessionsOpened + 1)
  })
})

describe('refusals do not depend on the server being reachable', () => {
  it('a lexically invalid path on an unreachable server gets the same refusal as an unknown site', async () => {
    const unknown = await refusal(readFileHandler({ site: 'unknown.example', path: 'index.php' }))
    for (const path of LEXICALLY_INVALID) {
      expect(await refusal(readFileHandler({ site: 'unreachable.example', path }))).toBe(unknown)
    }
    expect(unknown).toBe(NOT_AVAILABLE)
    expect(sink.attempts()).toBe(0)
  })

  it('sensitive and allowlist-miss paths are refused without contacting the server', async () => {
    for (const path of [
      'wp-config.php', 'WP-CONFIG.PHP', '.env', 'wp-content/plugins/x/.env.local', 'wp-content/plugins/x/dump.sql',
      'wp-content/plugins/x/backup.tar.gz', 'wp-content/plugins/x/server.key', // denylist
      'index.php', 'wp-content/themes/x/style.php', 'wp-content/plugins/x/data.csv', 'wp-content/plugins-old/x.php' // allowlist miss
    ]) {
      expect(await refusal(readFileHandler({ site: 'unreachable.example', path }))).toBe(NOT_AVAILABLE)
    }
    expect(sink.attempts()).toBe(0)
  })

  it('a valid path on the unreachable server does contact it and fails with E_REMOTE', async () => {
    const message = await refusal(readFileHandler({ site: 'unreachable.example', path: 'wp-content/plugins/x/readme.txt' }))
    expect(message).toBe('E_REMOTE: The remote server could not complete the request.')
    expect(sink.attempts()).toBeGreaterThan(0)
  })
})
