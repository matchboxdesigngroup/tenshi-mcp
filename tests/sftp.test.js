import { describe, it, expect, beforeAll, afterAll, afterEach } from 'vitest'
import { createServer } from 'net'
import { mkdtempSync, rmSync, writeFileSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import ssh2 from 'ssh2'
import {
  startFakeSftpServer,
  loadFakeRegistry,
  nonSftpRequests,
  NO_NON_SFTP_REQUESTS
} from './helpers/fake-sftp-server.js'
import { withSftpSession } from '../src/ssh/sftp.js'
import { closeAll } from '../src/ssh/client.js'
import { ERROR_CODES, ToolError } from '../src/errors.js'

const SERVER_ID = 'fake-server'
const FILE = '/srv/data/file.txt'
const BIG = '/srv/data/big.bin'

let fake
let restoreRegistry

beforeAll(async () => {
  fake = await startFakeSftpServer({
    files: {
      [FILE]: { content: 'hello sftp\n' },
      [BIG]: { content: Buffer.alloc(100 * 1024, 0x42) },
      '/srv/data/endless.log': { endless: true, size: 10 * 1024 * 1024 },
      '/srv/data/slow.log': { content: 'never served', hangRead: true }
    }
  })
  restoreRegistry = await loadFakeRegistry(fake, {
    'example.com': { wordpressRoot: '/srv/data', logDir: '/srv/data' }
  }, SERVER_ID)
})

afterEach(() => {
  // Guard for every test in this file: the fake must never see an exec,
  // shell or other non-SFTP request. Reset first so a failure is reported
  // only for the test that caused it.
  const seen = nonSftpRequests(fake)
  fake.resetEvents()
  expect(seen).toEqual(NO_NON_SFTP_REQUESTS)
})

afterAll(async () => {
  closeAll()
  restoreRegistry?.()
  await fake?.close()
})

describe('fake server self-check', () => {
  it('records an exec request, so the no-exec guard is not vacuous', async () => {
    const client = new ssh2.Client()
    await new Promise((resolve, reject) => {
      client.on('ready', resolve).on('error', reject).connect({
        host: fake.host, port: fake.port, username: fake.username, privateKey: fake.clientPrivateKey
      })
    })
    await new Promise(resolve => client.exec('true', () => resolve()))
    await fake.waitFor(() => fake.events.sessionRequests.length > 0)
    client.end()
    expect(fake.events.sessionRequests.map(r => r.type)).toEqual(['exec'])
    fake.resetEvents()
  })
})

describe('read-only SFTP session facade', () => {
  it('exposes only realpath, lstat and openRead, and handles expose only fstat, read and close', async () => {
    await withSftpSession(SERVER_ID, async session => {
      expect(Object.keys(session).sort()).toEqual(['lstat', 'openRead', 'realpath'])
      expect(Object.isFrozen(session)).toBe(true)
      const handle = await session.openRead(FILE)
      expect(Object.keys(handle).sort()).toEqual(['close', 'fstat', 'read'])
      expect(Object.isFrozen(handle)).toBe(true)
      await handle.close()
    })
  })

  it('reads a file and closes the SFTP session after the call', async () => {
    const text = await withSftpSession(SERVER_ID, async session => {
      const handle = await session.openRead(FILE)
      const buf = await handle.read(0, 1024)
      await handle.close()
      return buf.toString('utf8')
    })
    expect(text).toBe('hello sftp\n')
    await fake.waitFor(() => fake.openSftpSessions() === 0)
  })

  it('closes the SFTP session when the work fails and reports a plain error as E_INTERNAL', async () => {
    const err = await withSftpSession(SERVER_ID, async () => {
      throw new Error('boom /srv/data')
    }).catch(e => e)
    expect(err).toBeInstanceOf(ToolError)
    expect(err.code).toBe(ERROR_CODES.INTERNAL)
    expect(err.message).not.toContain('/srv/data')
    await fake.waitFor(() => fake.openSftpSessions() === 0)
  })

  it('maps a missing path to E_NOT_AVAILABLE with the fixed message', async () => {
    const err = await withSftpSession(SERVER_ID, s => s.realpath('/srv/data/missing.txt')).catch(e => e)
    expect(err).toBeInstanceOf(ToolError)
    expect(err.code).toBe(ERROR_CODES.NOT_AVAILABLE)
    expect(err.message).toBe('E_NOT_AVAILABLE: The requested resource is not available.')
  })

  it('stops an endless file at the requested length', async () => {
    const buf = await withSftpSession(SERVER_ID, async session => {
      const handle = await session.openRead('/srv/data/endless.log')
      return handle.read(0, 100000)
    })
    expect(buf.length).toBe(100000)
    expect(fake.events.readBytesServed).toBeLessThanOrEqual(100000)
    await fake.waitFor(() => fake.openSftpSessions() === 0)
  })

  it('enforces the per-call read budget as a backstop', async () => {
    const err = await withSftpSession(SERVER_ID, async session => {
      const handle = await session.openRead(BIG)
      await handle.read(0, 600)
      return handle.read(600, 600)
    }, { readBudgetBytes: 1000 }).catch(e => e)
    expect(err).toBeInstanceOf(ToolError)
    expect(err.code).toBe(ERROR_CODES.INTERNAL)
    expect(fake.events.readBytesServed).toBe(600)
  })

  it('pools the connection across calls', async () => {
    const before = fake.events.connections
    await withSftpSession(SERVER_ID, s => s.realpath(FILE))
    await withSftpSession(SERVER_ID, s => s.realpath(FILE))
    expect(fake.events.connections - before).toBeLessThanOrEqual(1)
  })

  it('shares one connection attempt between concurrent first calls', async () => {
    closeAll()
    const before = fake.events.connections
    const results = await Promise.all([1, 2, 3].map(() => withSftpSession(SERVER_ID, s => s.realpath(FILE))))
    expect(results).toEqual([FILE, FILE, FILE])
    expect(fake.events.connections - before).toBe(1)
    await fake.waitFor(() => fake.openSftpSessions() === 0)
  })

  it('closes a connection that completes after closeAll dropped it', async () => {
    closeAll()
    await fake.waitFor(() => fake.openConnections() === 0)
    const before = fake.events.connections
    const release = fake.holdAuthentication()
    const pending = withSftpSession(SERVER_ID, s => s.realpath(FILE)).catch(e => e)
    await fake.waitFor(() => fake.events.connections > before)
    closeAll()
    release()
    const err = await pending
    expect(err.code).toBe(ERROR_CODES.REMOTE)
    await fake.waitFor(() => fake.openConnections() === 0)
  })

  it('refuses an unknown server id before any network activity', async () => {
    const before = fake.events.connections
    const err = await withSftpSession('no-such-server', s => s.realpath('/')).catch(e => e)
    expect(err.code).toBe(ERROR_CODES.NOT_AVAILABLE)
    expect(err.message).not.toContain('no-such-server')
    expect(fake.events.connections).toBe(before)
  })
})

describe('per-call timeout', () => {
  it('aborts a read that never answers, returns E_TIMEOUT and closes the SFTP session', async () => {
    const started = Date.now()
    let session
    const err = await withSftpSession(SERVER_ID, async s => {
      session = s
      const handle = await s.openRead('/srv/data/slow.log')
      return handle.read(0, 1024)
    }, { timeoutMs: 300 }).catch(e => e)
    expect(err).toBeInstanceOf(ToolError)
    expect(err.code).toBe(ERROR_CODES.TIMEOUT)
    expect(err.message).toBe('E_TIMEOUT: The operation timed out.')
    expect(Date.now() - started).toBeLessThan(2000)
    expect(fake.events.pendingReads).toBe(1)
    await fake.waitFor(() => fake.openSftpSessions() === 0)
    // The facade is dead after the timeout: no further request reaches the server.
    const opsBefore = fake.events.ops.length
    await expect(session.realpath(FILE)).rejects.toMatchObject({ code: ERROR_CODES.TIMEOUT })
    expect(fake.events.ops.length).toBe(opsBefore)
  })

  it('times out a connection attempt that never completes the handshake', async () => {
    const sockets = new Set()
    const silent = createServer(socket => { sockets.add(socket) })
    await new Promise(resolve => silent.listen(0, '127.0.0.1', resolve))
    const dir = mkdtempSync(join(tmpdir(), 'tenshi-mcp-silent-'))
    const registryPath = join(dir, 'registry.json')
    writeFileSync(registryPath, JSON.stringify({
      servers: [
        {
          id: SERVER_ID, label: 'Fake', host: fake.host, port: fake.port,
          user: fake.username, privateKeyPath: fake.clientKeyPath, hostKeys: [fake.hostKeyFingerprint],
          sites: { 'example.com': { wordpressRoot: '/srv/data', logDir: '/srv/data' } }
        },
        {
          id: 'silent', label: 'Silent', host: '127.0.0.1', port: silent.address().port,
          user: fake.username, privateKeyPath: fake.clientKeyPath, hostKeys: [fake.hostKeyFingerprint], sites: {}
        }
      ]
    }))
    const previous = process.env.TENSHI_MCP_SERVERS_PATH
    process.env.TENSHI_MCP_SERVERS_PATH = registryPath
    const { loadRegistry } = await import('../src/config/servers.js')
    loadRegistry()
    try {
      const started = Date.now()
      const err = await withSftpSession('silent', s => s.realpath('/'), { timeoutMs: 300 }).catch(e => e)
      expect(err.code).toBe(ERROR_CODES.TIMEOUT)
      expect(Date.now() - started).toBeLessThan(2000)
    } finally {
      closeAll()
      for (const s of sockets) s.destroy()
      await new Promise(resolve => silent.close(resolve))
      process.env.TENSHI_MCP_SERVERS_PATH = previous
      loadRegistry()
      rmSync(dir, { recursive: true, force: true })
    }
  })
})
