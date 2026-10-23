import { describe, it, expect, vi } from 'vitest'
import { writeFileSync, mkdirSync, rmSync } from 'fs'
import path from 'path'
import os from 'os'

// envVar: which variable carries the registry path. The other one is cleared
// so a value from the developer's shell cannot change the outcome.
async function withServersFile(data, fn, envVar = 'TENSHI_MCP_SERVERS_PATH') {
  const dir = path.join(os.tmpdir(), `mcp-test-${Date.now()}`)
  mkdirSync(dir, { recursive: true })
  const filePath = path.join(dir, 'servers.json')
  writeFileSync(filePath, JSON.stringify(data))
  vi.stubEnv('TENSHI_MCP_SERVERS_PATH', '')
  vi.stubEnv('SSH_MCP_SERVERS_PATH', '')
  vi.stubEnv(envVar, filePath)
  try {
    vi.resetModules()
    const mod = await import('../src/config/servers.js')
    return await fn(mod)
  } finally {
    vi.unstubAllEnvs()
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

describe('resolveServersPath (TENSHI_MCP_SERVERS_PATH with deprecated SSH_MCP_SERVERS_PATH fallback)', () => {
  const NEW = '/path/to/new/servers.json'
  const OLD = '/path/to/old/servers.json'

  async function resolveWith(env) {
    const { resolveServersPath } = await import('../src/config/servers.js')
    const warnings = []
    const result = resolveServersPath(env, msg => warnings.push(msg))
    return { result, warnings }
  }

  it('uses TENSHI_MCP_SERVERS_PATH when only the new name is set, without a warning', async () => {
    const { result, warnings } = await resolveWith({ TENSHI_MCP_SERVERS_PATH: NEW })
    expect(result).toBe(path.resolve(NEW))
    expect(warnings).toEqual([])
  })

  it('falls back to SSH_MCP_SERVERS_PATH when only the old name is set, with one warning', async () => {
    const { result, warnings } = await resolveWith({ SSH_MCP_SERVERS_PATH: OLD })
    expect(result).toBe(path.resolve(OLD))
    expect(warnings).toHaveLength(1)
    expect(warnings[0]).toContain('SSH_MCP_SERVERS_PATH')
    expect(warnings[0]).toContain('TENSHI_MCP_SERVERS_PATH')
    expect(warnings[0]).toContain('M5')
  })

  it('prefers the new name when both are set, and warns that the old one is ignored', async () => {
    const { result, warnings } = await resolveWith({ TENSHI_MCP_SERVERS_PATH: NEW, SSH_MCP_SERVERS_PATH: OLD })
    expect(result).toBe(path.resolve(NEW))
    expect(warnings).toHaveLength(1)
    expect(warnings[0]).toContain('ignored')
  })

  it('treats an empty new name as unset and falls back to the old name', async () => {
    const { result } = await resolveWith({ TENSHI_MCP_SERVERS_PATH: '', SSH_MCP_SERVERS_PATH: OLD })
    expect(result).toBe(path.resolve(OLD))
  })

  it('treats a whitespace-only new name as unset, so it cannot shadow the old name', async () => {
    const { result, warnings } = await resolveWith({ TENSHI_MCP_SERVERS_PATH: ' \t ', SSH_MCP_SERVERS_PATH: OLD })
    expect(result).toBe(path.resolve(OLD))
    expect(warnings).toHaveLength(1)
    expect(warnings[0]).toContain('is deprecated')
  })

  it('treats a whitespace-only old name as unset: default path, no warning', async () => {
    const { result, warnings } = await resolveWith({ SSH_MCP_SERVERS_PATH: '   ' })
    expect(result).toBe(path.resolve('./servers.json'))
    expect(warnings).toEqual([])
  })

  it('uses a space-padded value verbatim (not trimmed)', async () => {
    const padded = ` ${NEW} `
    const { result } = await resolveWith({ TENSHI_MCP_SERVERS_PATH: padded })
    expect(result).toBe(path.resolve(padded))
    expect(result).not.toBe(path.resolve(NEW))
  })

  it('defaults to ./servers.json when neither is set, without a warning', async () => {
    const { result, warnings } = await resolveWith({})
    expect(result).toBe(path.resolve('./servers.json'))
    expect(warnings).toEqual([])
  })

  it('never puts the variable values in the warning', async () => {
    const { warnings } = await resolveWith({ TENSHI_MCP_SERVERS_PATH: NEW, SSH_MCP_SERVERS_PATH: OLD })
    const { warnings: oldOnly } = await resolveWith({ SSH_MCP_SERVERS_PATH: OLD })
    for (const w of [...warnings, ...oldOnly]) {
      expect(w).not.toContain(NEW)
      expect(w).not.toContain(OLD)
      expect(w).not.toContain('\n')
    }
  })

  it('loadRegistry reads the registry through the deprecated name', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    try {
      await withServersFile(VALID_CONFIG, async ({ loadRegistry, getServerConfig }) => {
        loadRegistry()
        expect(getServerConfig('testserver').host).toBe('1.2.3.4')
      }, 'SSH_MCP_SERVERS_PATH')
      expect(warn).toHaveBeenCalledTimes(1)
    } finally {
      warn.mockRestore()
    }
  })
})
