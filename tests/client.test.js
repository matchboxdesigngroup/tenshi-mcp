import { describe, it, expect, vi, beforeEach } from 'vitest'

describe('getConnection allowlist', () => {
  beforeEach(() => {
    vi.resetModules()
  })

  it('throws for an id not in the registry', async () => {
    vi.doMock('../src/config/servers.js', () => ({
      getServerConfig: (id) => { throw new Error(`Unknown server: ${id}`) }
    }))
    const { getConnection } = await import('../src/ssh/client.js')
    await expect(getConnection('phantom')).rejects.toThrow('Unknown server: phantom')
  })
})
