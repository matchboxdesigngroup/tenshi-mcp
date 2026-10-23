import { describe, it, expect, beforeAll, afterAll, afterEach } from 'vitest'
import {
  startFakeSftpServer,
  startTcpForwarder,
  loadFakeRegistry,
  nonSftpRequests,
  NO_NON_SFTP_REQUESTS
} from './helpers/fake-sftp-server.js'
import { VECTORS, fingerprintOfByte } from './helpers/host-key-vectors.js'
import { readFileHandler } from '../src/tools/read-file.js'
import { openSftpChannel, closeAll } from '../src/ssh/client.js'
import { ERROR_CODES } from '../src/errors.js'

// Host-key pinning against the in-process SSH server fake. Every connection,
// including a reconnect after the pool dropped one, must present a host key
// pinned in the registry; a mismatch is refused during key exchange, before
// any authentication request (and so before any key material) is sent.

const ROOT = '/var/www/example.com/public'
const FILES = { [`${ROOT}/index.php`]: { content: '<?php echo 1;' } }
const SITES = { 'example.com': { wordpressRoot: ROOT, logDir: '/var/log/nginx' } }
const HOST_KEY_MESSAGE = 'E_HOST_KEY: The server host key did not match the registry; the connection was refused.'

let fake
let other
let restoreRegistry

beforeAll(async () => {
  fake = await startFakeSftpServer({ files: FILES })
  other = await startFakeSftpServer({ files: FILES })
})

afterEach(async () => {
  closeAll()
  restoreRegistry?.()
  restoreRegistry = undefined
  await fake.waitFor(() => fake.openConnections() === 0 && other.openConnections() === 0)
  for (const f of [fake, other]) {
    const seen = nonSftpRequests(f)
    f.resetEvents()
    expect(seen).toEqual(NO_NON_SFTP_REQUESTS)
  }
})

afterAll(async () => {
  closeAll()
  await fake?.close()
  await other?.close()
})

function snapshot(f) {
  return { connections: f.events.connections, authAttempts: f.events.authAttempts, sftp: f.events.sftpSessionsOpened }
}

function readIndex() {
  return readFileHandler({ site: 'example.com', path: 'index.php', maxBytes: 100 })
}

async function pin(hostKeys, options = {}) {
  restoreRegistry = await loadFakeRegistry(fake, SITES, 'fake-server', [], { hostKeys, ...options })
}

/** Strings that must never appear in an error shown to the model. */
function serverDetails(...extra) {
  const pinned = [fake.hostKeyFingerprint, other.hostKeyFingerprint, VECTORS.ed25519.fingerprint, VECTORS.ecdsa.fingerprint]
  const asHex = pinned.map(fp => Buffer.from(fp.slice('SHA256:'.length), 'base64').toString('hex'))
  const bodies = pinned.map(fp => fp.slice('SHA256:'.length))
  return [...bodies, ...asHex, fake.host, String(fake.port), String(other.port), ROOT, 'fake-server', ...extra]
}

function expectHostKeyRefusal(err, ...extra) {
  expect(err).toBeInstanceOf(Error)
  expect(err.code).toBe(ERROR_CODES.HOST_KEY)
  expect(err.message).toBe(HOST_KEY_MESSAGE)
  const visible = `${err.message} ${JSON.stringify(err)}`
  for (const detail of serverDetails(...extra)) expect(visible).not.toContain(detail)
}

describe('host-key pinning: matching pins', () => {
  it('connects and reads when the only pin matches', async () => {
    await pin([fake.hostKeyFingerprint])
    const result = await readIndex()
    expect(result.content).toBe('<?php echo 1;')
    expect(fake.events.authAttempts).toBeGreaterThan(0)
  })

  it('accepts the key when it is the first of several pins', async () => {
    await pin([fake.hostKeyFingerprint, fingerprintOfByte(1), fingerprintOfByte(2)])
    expect((await readIndex()).content).toBe('<?php echo 1;')
  })

  it('accepts the key when it is the last of five pins', async () => {
    await pin([1, 2, 3, 4].map(fingerprintOfByte).concat(fake.hostKeyFingerprint))
    expect((await readIndex()).content).toBe('<?php echo 1;')
  })

  it('rotation: two pins where only the second matches', async () => {
    await pin([other.hostKeyFingerprint, fake.hostKeyFingerprint])
    expect((await readIndex()).content).toBe('<?php echo 1;')
  })

  it('accepts the pin written with base64 padding (normalised at load)', async () => {
    await pin([fake.hostKeyFingerprint + '='])
    expect((await readIndex()).content).toBe('<?php echo 1;')
  })
})

describe('host-key pinning: mismatch', () => {
  it('refuses a host key that matches no pin, before authentication, with no SFTP channel', async () => {
    await pin([other.hostKeyFingerprint, VECTORS.ed25519.fingerprint])
    const before = snapshot(fake)
    const err = await readIndex().then(() => null, e => e)
    expectHostKeyRefusal(err)
    const after = snapshot(fake)
    // The server was reached (so the check ran), but no authentication
    // request arrived and no SFTP session was opened.
    expect(after.connections - before.connections).toBe(1)
    expect(after.authAttempts).toBe(before.authAttempts)
    expect(after.sftp).toBe(before.sftp)
    await fake.waitFor(() => fake.openConnections() === 0)
  })

  it('refuses with the fixed code on the channel API too, without server details', async () => {
    await pin([other.hostKeyFingerprint])
    const err = await openSftpChannel('fake-server').then(() => null, e => e)
    expectHostKeyRefusal(err)
  })

  it('does not keep a refused connection: the next call verifies again and is refused again', async () => {
    await pin([other.hostKeyFingerprint])
    const before = snapshot(fake)
    expectHostKeyRefusal(await readIndex().then(() => null, e => e))
    expectHostKeyRefusal(await readIndex().then(() => null, e => e))
    const after = snapshot(fake)
    expect(after.connections - before.connections).toBe(2)
    expect(after.authAttempts).toBe(before.authAttempts)
    expect(after.sftp).toBe(before.sftp)
  })

  it('logs nothing on a mismatch', async () => {
    await pin([other.hostKeyFingerprint])
    const methods = ['log', 'info', 'warn', 'error', 'debug']
    const original = methods.map(m => console[m])
    const calls = []
    for (const m of methods) console[m] = (...args) => calls.push([m, ...args])
    try {
      expectHostKeyRefusal(await readIndex().then(() => null, e => e))
    } finally {
      methods.forEach((m, i) => { console[m] = original[i] })
    }
    expect(calls).toEqual([])
  })
})

describe('host-key pinning: missing pins', () => {
  it('a registry with a server without pins refuses to load, so nothing is connected', async () => {
    const before = snapshot(fake)
    const err = await loadFakeRegistry(fake, SITES, 'fake-server', [], { hostKeys: [] }).then(() => null, e => e)
    expect(err?.name).toBe('RegistryError')
    // The refused load leaves the registry empty: the tool refuses before any
    // network activity.
    const refusal = await readIndex().then(() => null, e => e)
    expect(refusal.code).toBe(ERROR_CODES.NOT_AVAILABLE)
    const channel = await openSftpChannel('fake-server').then(() => null, e => e)
    expect(channel.code).toBe(ERROR_CODES.NOT_AVAILABLE)
    await new Promise(resolve => setTimeout(resolve, 50))
    expect(snapshot(fake)).toEqual(before)
  })
})

describe('host-key pinning: reconnect', () => {
  it('re-verifies after the pool drops a connection and refuses a different key behind the same entry', async () => {
    const forwarder = await startTcpForwarder(fake.port)
    try {
      await pin([fake.hostKeyFingerprint], { host: forwarder.host, port: forwarder.port })
      expect((await readIndex()).content).toBe('<?php echo 1;')
      expect(fake.openConnections()).toBe(1)

      // The server ends the connection; the pool sees it as no longer
      // connected and opens a new one on the next call.
      fake.disconnectClients()
      await fake.waitFor(() => fake.openConnections() === 0)
      await new Promise(resolve => setTimeout(resolve, 100))

      // Same registry entry, same address, different server (different key).
      forwarder.retarget(other.port)
      const otherBefore = snapshot(other)
      const fakeBefore = snapshot(fake)
      const err = await readIndex().then(() => null, e => e)
      expectHostKeyRefusal(err, String(forwarder.port))
      const otherAfter = snapshot(other)
      expect(otherAfter.connections - otherBefore.connections).toBe(1)
      expect(otherAfter.authAttempts).toBe(otherBefore.authAttempts)
      expect(otherAfter.sftp).toBe(otherBefore.sftp)
      expect(snapshot(fake)).toEqual(fakeBefore)

      // Back to the pinned server: accepted again on a fresh connection.
      forwarder.retarget(fake.port)
      expect((await readIndex()).content).toBe('<?php echo 1;')
    } finally {
      closeAll()
      await forwarder.close()
    }
  })
})
