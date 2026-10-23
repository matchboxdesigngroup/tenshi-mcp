import { describe, it, expect, vi, beforeEach } from 'vitest'

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

describe('host-key verification seam', () => {
  it('returns no verifier until pinning lands, so ssh2 keeps its current default', async () => {
    const { hostVerifierFor } = await import('../src/ssh/client.js')
    expect(hostVerifierFor({ id: 'example-server' })).toBeUndefined()
  })
})
