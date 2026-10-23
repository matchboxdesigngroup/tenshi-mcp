import { describe, it, expect, vi, beforeEach } from 'vitest'
import { VECTORS, sha256Hex } from './helpers/host-key-vectors.js'

describe('openSftpChannel allowlist', () => {
  beforeEach(() => {
    vi.resetModules()
  })

  it('refuses an id not in the registry with E_NOT_AVAILABLE and does not echo it', async () => {
    vi.doMock('../src/config/servers.js', () => ({
      getServerConfig: (id) => { throw new Error(`Unknown server: ${id}`) }
    }))
    const { openSftpChannel } = await import('../src/ssh/client.js')
    const err = await openSftpChannel('phantom').catch(e => e)
    expect(err.code).toBe('E_NOT_AVAILABLE')
    expect(err.message).not.toContain('phantom')
  })
})

describe('hostVerifierFor', () => {
  beforeEach(() => {
    vi.resetModules()
  })

  it('always returns a verifier, so ssh2 never falls back to accepting any key', async () => {
    const { hostVerifierFor } = await import('../src/ssh/client.js')
    for (const server of [{ id: 'example-server' }, { id: 'example-server', hostKeys: [] }, undefined]) {
      const verify = hostVerifierFor(server)
      expect(typeof verify).toBe('function')
      expect(verify(sha256Hex(VECTORS.ed25519.publicKey))).toBe(false)
    }
  })

  it('accepts only keys pinned for that server', async () => {
    const { hostVerifierFor } = await import('../src/ssh/client.js')
    const verify = hostVerifierFor({ id: 'example-server', hostKeys: [VECTORS.ed25519.fingerprint] })
    expect(verify(sha256Hex(VECTORS.ed25519.publicKey))).toBe(true)
    expect(verify(sha256Hex(VECTORS.ecdsa.publicKey))).toBe(false)
  })
})
