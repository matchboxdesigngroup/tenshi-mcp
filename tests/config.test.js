import { describe, it, expect, vi } from 'vitest'
import { writeFileSync, mkdirSync, rmSync, readFileSync } from 'fs'
import path from 'path'
import os from 'os'
import { VECTORS, fingerprintOfByte } from './helpers/host-key-vectors.js'

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
      host: '192.0.2.10',
      port: 22,
      user: 'deploy',
      privateKeyPath: '~/.ssh/id_rsa',
      hostKeys: [VECTORS.ed25519.fingerprint],
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
      expect(server.host).toBe('192.0.2.10')
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

  it('validates every site entry and names the site and field', async () => {
    const server = {
      ...VALID_CONFIG.servers[0],
      sites: { ...VALID_CONFIG.servers[0].sites, 'broken.example': { wordpressRoot: '/var/www/broken' } }
    }
    const err = await loadError({ servers: [server] })
    const lines = err.message.split('\n')
    expect(lines).toHaveLength(2)
    expect(lines[1]).toMatch(/^ {2}server "testserver": sites\.broken\.example\.logDir: /)
  })

  for (const [name, sites] of Object.entries({ 'a list': [], 'a string': 'example.com', 'null': null })) {
    it(`refuses sites given as ${name}`, async () => {
      const err = await loadError({ servers: [{ ...VALID_CONFIG.servers[0], sites }] })
      const lines = err.message.split('\n')
      expect(lines).toHaveLength(2)
      expect(lines[1]).toMatch(/^ {2}server "testserver": sites: /)
    })
  }

  it('keeps the sites map keyed by domain', async () => {
    const sites = { ...VALID_CONFIG.servers[0].sites, 'second.example': { wordpressRoot: '/var/www/second', logDir: '/var/log/second' } }
    await withServersFile({ servers: [{ ...VALID_CONFIG.servers[0], sites }] }, async ({ loadRegistry, getSiteConfig }) => {
      loadRegistry()
      expect(getSiteConfig('testserver', 'second.example')).toEqual({ wordpressRoot: '/var/www/second', logDir: '/var/log/second', serverId: 'testserver' })
      expect(getSiteConfig('testserver', 'example.com').wordpressRoot).toBe('/var/www/example.com/public')
    })
  })
})

function withHostKeys(hostKeys, { id = 'testserver', omit = false } = {}) {
  const server = { ...VALID_CONFIG.servers[0], id }
  if (omit) delete server.hostKeys
  else server.hostKeys = hostKeys
  return { servers: [server] }
}

async function loadError(config) {
  return withServersFile(config, async ({ loadRegistry, getServerConfig, RegistryError }) => {
    let err
    try { loadRegistry() } catch (e) { err = e }
    expect(err, 'registry must refuse to load').toBeInstanceOf(RegistryError)
    // Nothing is reachable after a refused load.
    expect(() => getServerConfig(config.servers?.[0]?.id ?? 'testserver')).toThrow('Registry not initialized')
    return err
  })
}

const ED = VECTORS.ed25519.fingerprint
const ED_BODY = ED.slice('SHA256:'.length)
const ED_HEX = Buffer.from(ED_BODY, 'base64').toString('hex')

describe('loadRegistry host-key pins', () => {
  const invalid = {
    'missing field': [undefined, { omit: true }],
    'null': [null],
    'a string instead of an array': [ED],
    'empty array': [[]],
    'more than five pins': [[1, 2, 3, 4, 5, 6].map(fingerprintOfByte)],
    'duplicate pins': [[ED, ED]],
    'duplicates after normalising the padding': [[ED, ED + '=']],
    'a non-string pin': [[ED, 42]],
    'a null pin': [[null]],
    'an object pin': [[{ sha256: ED }]],
    'lowercase hex': [[ED_HEX]],
    'uppercase hex': [[ED_HEX.toUpperCase()]],
    'hex after the SHA256 prefix': [['SHA256:' + ED_HEX]],
    'double base64 padding': [[ED + '==']],
    'base64url alphabet': [['SHA256:' + Buffer.alloc(32, 0xfb).toString('base64url')]],
    'lowercase prefix': [['sha256:' + ED_BODY]],
    'a SHA1 fingerprint': [['SHA1:' + Buffer.alloc(20, 7).toString('base64').replace(/=+$/, '')]],
    'an MD5 fingerprint': [['MD5:' + Array.from({ length: 16 }, () => 'ab').join(':')]],
    'a bare MD5 colon-hex fingerprint': [[Array.from({ length: 16 }, () => 'cd').join(':')]],
    'one valid and one invalid pin': [[ED, 'SHA256:not-a-fingerprint']]
  }

  for (const [name, [hostKeys, options]] of Object.entries(invalid)) {
    it(`refuses to load a server with ${name}, naming the server and the field`, async () => {
      const err = await loadError(withHostKeys(hostKeys, options))
      expect(err.message).toContain('server "testserver"')
      expect(err.message).toContain('hostKeys')
    })
  }

  // The exact fixed texts, one issue each: zod 4 silently ignores the zod 3
  // required_error and invalid_type_error params (zod's default wording
  // would appear instead), and runs length checks on a string that is not
  // an array (a second issue would appear).
  const fixedMessages = {
    'missing field': [withHostKeys(undefined, { omit: true }), 'hostKeys: host-key pins are required (at least one SHA-256 fingerprint)'],
    'null': [withHostKeys(null), 'hostKeys: must be an array of SHA-256 fingerprints'],
    'a string instead of an array': [withHostKeys(ED), 'hostKeys: must be an array of SHA-256 fingerprints'],
    'an empty string instead of an array': [withHostKeys(''), 'hostKeys: must be an array of SHA-256 fingerprints'],
    'an object instead of an array': [withHostKeys({ 0: ED }), 'hostKeys: must be an array of SHA-256 fingerprints'],
    'empty array': [withHostKeys([]), 'hostKeys: at least one SHA-256 fingerprint is required'],
    'more than five pins': [withHostKeys([1, 2, 3, 4, 5, 6].map(fingerprintOfByte)), 'hostKeys: at most 5 fingerprints are allowed'],
    'duplicate pins': [withHostKeys([ED, ED]), 'hostKeys.1: duplicate fingerprint'],
    'an invalid pin': [withHostKeys([ED, 'SHA256:not-a-fingerprint']), 'hostKeys.1: not a SHA-256 fingerprint in the OpenSSH form SHA256:<base64>']
  }

  for (const [name, [config, issue]] of Object.entries(fixedMessages)) {
    it(`reports ${name} with the fixed message only`, async () => {
      const err = await loadError(config)
      expect(err.message).toBe(`Registry is invalid:\n  server "testserver": ${issue}`)
    })
  }

  it('never puts a pin value into the error message', async () => {
    const values = ['SHA256:' + ED_HEX, ED + '==', 'sha256:' + ED_BODY, 'MD5:' + Array.from({ length: 16 }, () => 'ab').join(':')]
    for (const value of values) {
      const err = await loadError(withHostKeys([ED, value]))
      expect(err.message).not.toContain(value)
      expect(err.message).not.toContain(ED_BODY)
    }
    const dup = await loadError(withHostKeys([ED, ED]))
    expect(dup.message).toContain('duplicate')
    expect(dup.message).not.toContain(ED_BODY)
  })

  it('names a server without a usable id by its position', async () => {
    const err = await loadError(withHostKeys([], { id: '' }))
    expect(err.message).toContain('servers[0]')
  })

  it('refuses the whole registry when one of several servers has no pins', async () => {
    const good = { ...VALID_CONFIG.servers[0], id: 'good-server' }
    const bad = { ...VALID_CONFIG.servers[0], id: 'unpinned-server', sites: {} }
    delete bad.hostKeys
    const err = await loadError({ servers: [good, bad] })
    expect(err.message).toContain('server "unpinned-server"')
    expect(err.message).not.toContain('good-server')
  })

  it('empties a previously loaded registry when a reload fails', async () => {
    await withServersFile(VALID_CONFIG, async ({ loadRegistry, getServerConfig }) => {
      loadRegistry()
      expect(getServerConfig('testserver').hostKeys).toEqual([ED])
      writeFileSync(process.env.TENSHI_MCP_SERVERS_PATH, JSON.stringify(withHostKeys([])))
      expect(() => loadRegistry()).toThrow()
      expect(() => getServerConfig('testserver')).toThrow('Registry not initialized')
    })
  })

  it('accepts one to five pins and stores them in the unpadded OpenSSH form', async () => {
    const five = [ED + '=', ...[1, 2, 3, 4].map(fingerprintOfByte)]
    await withServersFile(withHostKeys(five), async ({ loadRegistry, getServerConfig }) => {
      loadRegistry()
      expect(getServerConfig('testserver').hostKeys).toEqual([ED, ...[1, 2, 3, 4].map(fingerprintOfByte)])
    })
    await withServersFile(withHostKeys([VECTORS.ecdsa.fingerprint]), async ({ loadRegistry, getServerConfig }) => {
      loadRegistry()
      expect(getServerConfig('testserver').hostKeys).toEqual([VECTORS.ecdsa.fingerprint])
    })
  })

  it('loads servers.json.example (placeholder pins are well formed)', async () => {
    const example = JSON.parse(readFileSync(new URL('../servers.json.example', import.meta.url), 'utf8'))
    await withServersFile(example, async ({ loadRegistry, getServerConfig }) => {
      loadRegistry()
      expect(getServerConfig('example-server').hostKeys).toHaveLength(1)
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
    expect(warnings[0]).toContain('SSH_MCP_SERVERS_PATH')
    expect(warnings[0]).toContain('M5')
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

  it('uses the default path, without a warning, when both names are whitespace only', async () => {
    const { result, warnings } = await resolveWith({ TENSHI_MCP_SERVERS_PATH: '  ', SSH_MCP_SERVERS_PATH: '\t' })
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
        expect(getServerConfig('testserver').host).toBe('192.0.2.10')
      }, 'SSH_MCP_SERVERS_PATH')
      expect(warn).toHaveBeenCalledTimes(1)
    } finally {
      warn.mockRestore()
    }
  })
})
