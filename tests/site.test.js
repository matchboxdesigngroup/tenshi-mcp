import { describe, it, expect, vi, beforeEach } from 'vitest'

// lookupSite must refuse a registry entry that lacks any field the tools
// rely on, including the allowlist, even though the loader already requires
// them: the tool layer does not trust the shape of what it is handed.

describe('lookupSite shape check', () => {
  beforeEach(() => {
    vi.resetModules()
  })

  const complete = {
    wordpressRoot: '/var/www/example.com/public',
    logDir: '/var/log/nginx',
    allow: { extensions: ['.php'], directories: ['.'] }
  }

  async function lookupWith(site) {
    vi.doMock('../src/config/servers.js', () => ({
      resolveServerForSite: () => ({ serverId: 'example-server', server: {}, site })
    }))
    const { lookupSite } = await import('../src/tools/site.js')
    return lookupSite('example.com')
  }

  it('returns a copy of a complete entry', async () => {
    const result = await lookupWith(complete)
    expect(result).toEqual({ serverId: 'example-server', ...complete })
    expect(result.allow.extensions).not.toBe(complete.allow.extensions)
  })

  it.each([
    ['no allow', { wordpressRoot: complete.wordpressRoot, logDir: complete.logDir }],
    ['allow without extensions', { ...complete, allow: { directories: ['.'] } }],
    ['allow without directories', { ...complete, allow: { extensions: ['.php'] } }],
    ['extensions not an array', { ...complete, allow: { extensions: '.php', directories: ['.'] } }],
    ['no wordpressRoot', { logDir: complete.logDir, allow: complete.allow }],
    ['no logDir', { wordpressRoot: complete.wordpressRoot, allow: complete.allow }]
  ])('refuses an entry with %s as E_NOT_AVAILABLE', async (_, site) => {
    const err = await lookupWith(site).then(() => null, e => e)
    expect(err?.code).toBe('E_NOT_AVAILABLE')
  })
})
