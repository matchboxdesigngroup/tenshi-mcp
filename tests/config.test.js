import { describe, it, expect, vi } from 'vitest'
import { writeFileSync, mkdirSync, rmSync } from 'fs'
import path from 'path'
import os from 'os'

async function withServersFile(data, fn) {
  const dir = path.join(os.tmpdir(), `mcp-test-${Date.now()}`)
  mkdirSync(dir, { recursive: true })
  const filePath = path.join(dir, 'servers.json')
  writeFileSync(filePath, JSON.stringify(data))
  const original = process.env.SSH_MCP_SERVERS_PATH
  process.env.SSH_MCP_SERVERS_PATH = filePath
  try {
    vi.resetModules()
    const mod = await import('../src/config/servers.js')
    return await fn(mod)
  } finally {
    process.env.SSH_MCP_SERVERS_PATH = original ?? ''
    rmSync(dir, { recursive: true })
    vi.resetModules()
  }
}

const VALID_CONFIG = {
  servers: [
    {
      id: 'testserver',
      label: 'Test Server',
      host: '1.2.3.4',
      port: 22,
      user: 'deploy',
      privateKeyPath: '~/.ssh/id_rsa',
      sites: {
        'example.com': {
          wordpressRoot: '/var/www/example.com/public',
          logDir: '/var/log/nginx'
        }
      }
    }
  ]
}

describe('getServerConfig', () => {
  it('returns server config for known id', async () => {
    await withServersFile(VALID_CONFIG, async ({ loadRegistry, getServerConfig }) => {
      loadRegistry()
      const server = getServerConfig('testserver')
      expect(server.host).toBe('1.2.3.4')
      expect(server.user).toBe('deploy')
    })
  })

  it('throws for unknown server id', async () => {
    await withServersFile(VALID_CONFIG, async ({ loadRegistry, getServerConfig }) => {
      loadRegistry()
      expect(() => getServerConfig('nonexistent')).toThrow('Unknown server: nonexistent')
    })
  })
})

describe('getSiteConfig', () => {
  it('returns site config for known server + site', async () => {
    await withServersFile(VALID_CONFIG, async ({ loadRegistry, getSiteConfig }) => {
      loadRegistry()
      const site = getSiteConfig('testserver', 'example.com')
      expect(site.wordpressRoot).toBe('/var/www/example.com/public')
      expect(site.logDir).toBe('/var/log/nginx')
    })
  })

  it('throws for unknown site', async () => {
    await withServersFile(VALID_CONFIG, async ({ loadRegistry, getSiteConfig }) => {
      loadRegistry()
      expect(() => getSiteConfig('testserver', 'unknown.com')).toThrow('Unknown site: unknown.com on server testserver')
    })
  })
})

describe('loadRegistry validation', () => {
  it('throws when servers array is missing', async () => {
    await withServersFile({ notServers: [] }, async ({ loadRegistry }) => {
      expect(() => loadRegistry()).toThrow()
    })
  })

  it('throws when a server entry is missing required fields', async () => {
    const bad = { servers: [{ id: 'x' }] }
    await withServersFile(bad, async ({ loadRegistry }) => {
      expect(() => loadRegistry()).toThrow()
    })
  })
})
