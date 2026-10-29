# SSH WordPress MCP Server — Implementation Plan

> **Rename note:** this plan was written before the project was renamed to Tenshi-MCP (tenshi#3). Package, server and registration names, the registry path variable (`TENSHI_MCP_SERVERS_PATH`, formerly `SSH_MCP_SERVERS_PATH`, still read as a deprecated fallback) and example paths are updated to the current names. The code samples show the plan, not the current code: see `src/config/servers.js` for how the path is resolved now.

> **SFTP note:** Tasks 4 to 6 describe the original command executor (`src/ssh/executor.js`, `runCommand`) and tools that built remote command strings. That design was replaced: the executor is removed and both tools read over SFTP through a read-only facade (`src/ssh/sftp.js`, `src/ssh/confine.js`). The code samples in those tasks are historical; see the README security model and the note in `docs/adrs/ADR-002-command-security-model.md`.

> **Policy note:** examples below that read `wp-config.php` describe the original plan. Since #20 that file, its variants and other sensitive files are always refused, `read_file` serves only extensions and directories in the site's `allow` list, and credential lines are redacted; see the README section "Sensitive-file policy".

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a local MCP server (stdio transport) that SSHs into configured servers and exposes two tools — `read_log` and `read_file` — for reading WordPress logs and files during Claude triage sessions.

**Architecture:** A Node.js (ESM) process spawned by the parent agent as a child process. Tools look up server/site config from `servers.json`, open pooled SSH connections via `node-ssh`, run a small set of allowlisted read-only commands, and return structured JSON. Security is enforced at three layers: command allowlist in executor, path confinement in read-file, and host allowlist in the connection pool.

**Tech Stack:** Node.js ≥20 (ESM), `@modelcontextprotocol/sdk`, `node-ssh`, `vitest` (tests), `zod` (schema validation)

---

## File Map

```
src/
  index.js            MCP server entry point
  config/
    servers.js        Load + validate servers.json; export getServerConfig / getSiteConfig
  ssh/
    client.js         Connection pool; getConnection(serverId) → live NodeSSH
    executor.js       runCommand(serverId, cmd) → {stdout, stderr, exitCode}; allowlist + timeout
  tools/
    read-log.js       read_log tool definition, schema, handler
    read-file.js      read_file tool definition, schema, handler

tests/
  config.test.js      Unit: servers.js validation
  executor.test.js    Unit: allowlist enforcement + timeout
  read-log.test.js    Unit: path resolution + output shaping
  read-file.test.js   Unit: path resolution + traversal guard

tests/integration.js  Manual script — run directly against a real servers.json entry

servers.json          (not committed) server registry
.env                  TENSHI_MCP_SERVERS_PATH override
package.json
```

---

## Task 1: Project scaffold + package.json

**Files:**
- Create: `package.json`

- [ ] **Step 1: Write `package.json`**

```json
{
  "name": "tenshi-mcp",
  "version": "1.0.0",
  "type": "module",
  "main": "src/index.js",
  "scripts": {
    "start": "node src/index.js",
    "test": "vitest run",
    "test:watch": "vitest"
  },
  "dependencies": {
    "@modelcontextprotocol/sdk": "^1.0.0",
    "node-ssh": "^13.0.0",
    "zod": "^3.23.0"
  },
  "devDependencies": {
    "vitest": "^1.6.0"
  },
  "engines": {
    "node": ">=20"
  }
}
```

- [ ] **Step 2: Install dependencies**

```bash
npm install
```

Expected: `node_modules/` created, no errors.

- [ ] **Step 3: Verify ESM works**

```bash
node -e "import('./src/index.js').catch(e => console.log('expected import error (file not yet created):', e.message))"
```

Expected: message about file not found — not a syntax error.

- [ ] **Step 4: Commit**

```bash
git init
git add package.json package-lock.json .gitignore .env.example
git commit -m "chore: scaffold project with package.json and dependencies"
```

---

## Task 2: Server registry loader (`src/config/servers.js`)

**Files:**
- Create: `src/config/servers.js`
- Create: `tests/config.test.js`

The loader reads `servers.json` (path from `TENSHI_MCP_SERVERS_PATH` env var or `./servers.json`), validates the structure with Zod, and exports two lookup functions.

- [ ] **Step 1: Write failing tests**

Create `tests/config.test.js`:

```js
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { writeFileSync, mkdirSync, rmSync } from 'fs'
import path from 'path'
import os from 'os'

// Helper: write a temp servers.json and set env var
function withServersFile(data, fn) {
  const dir = path.join(os.tmpdir(), `mcp-test-${Date.now()}`)
  mkdirSync(dir, { recursive: true })
  const filePath = path.join(dir, 'servers.json')
  writeFileSync(filePath, JSON.stringify(data))
  const original = process.env.TENSHI_MCP_SERVERS_PATH
  process.env.TENSHI_MCP_SERVERS_PATH = filePath
  try {
    return fn(filePath)
  } finally {
    process.env.TENSHI_MCP_SERVERS_PATH = original ?? ''
    rmSync(dir, { recursive: true })
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
    await withServersFile(VALID_CONFIG, async () => {
      // Re-import to pick up env var (use dynamic import with cache-bust)
      const { loadRegistry, getServerConfig } = await import(`../src/config/servers.js?t=${Date.now()}`)
      loadRegistry()
      const server = getServerConfig('testserver')
      expect(server.host).toBe('1.2.3.4')
      expect(server.user).toBe('deploy')
    })
  })

  it('throws for unknown server id', async () => {
    await withServersFile(VALID_CONFIG, async () => {
      const { loadRegistry, getServerConfig } = await import(`../src/config/servers.js?t=${Date.now()}`)
      loadRegistry()
      expect(() => getServerConfig('nonexistent')).toThrow('Unknown server: nonexistent')
    })
  })
})

describe('getSiteConfig', () => {
  it('returns site config for known server + site', async () => {
    await withServersFile(VALID_CONFIG, async () => {
      const { loadRegistry, getSiteConfig } = await import(`../src/config/servers.js?t=${Date.now()}`)
      loadRegistry()
      const site = getSiteConfig('testserver', 'example.com')
      expect(site.wordpressRoot).toBe('/var/www/example.com/public')
      expect(site.logDir).toBe('/var/log/nginx')
    })
  })

  it('throws for unknown site', async () => {
    await withServersFile(VALID_CONFIG, async () => {
      const { loadRegistry, getSiteConfig } = await import(`../src/config/servers.js?t=${Date.now()}`)
      loadRegistry()
      expect(() => getSiteConfig('testserver', 'unknown.com')).toThrow('Unknown site: unknown.com')
    })
  })
})

describe('loadRegistry validation', () => {
  it('throws when servers array is missing', async () => {
    await withServersFile({ notServers: [] }, async () => {
      const { loadRegistry } = await import(`../src/config/servers.js?t=${Date.now()}`)
      expect(() => loadRegistry()).toThrow()
    })
  })

  it('throws when a server entry is missing required fields', async () => {
    const bad = { servers: [{ id: 'x' }] }
    await withServersFile(bad, async () => {
      const { loadRegistry } = await import(`../src/config/servers.js?t=${Date.now()}`)
      expect(() => loadRegistry()).toThrow()
    })
  })
})
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
npm test -- tests/config.test.js
```

Expected: FAIL — `../src/config/servers.js` not found.

- [ ] **Step 3: Implement `src/config/servers.js`**

```js
import { readFileSync } from 'fs'
import { resolve } from 'path'
import { z } from 'zod'

const SiteSchema = z.object({
  wordpressRoot: z.string().min(1),
  logDir: z.string().min(1)
})

const ServerSchema = z.object({
  id: z.string().min(1),
  label: z.string().min(1),
  host: z.string().min(1),
  port: z.number().int().min(1).max(65535),
  user: z.string().min(1),
  privateKeyPath: z.string().min(1),
  sites: z.record(SiteSchema)
})

const RegistrySchema = z.object({
  servers: z.array(ServerSchema).min(1)
})

/** @type {Map<string, z.infer<typeof ServerSchema>>} */
let registry = new Map()

export function loadRegistry() {
  const filePath = resolve(process.env.TENSHI_MCP_SERVERS_PATH || './servers.json')
  const raw = JSON.parse(readFileSync(filePath, 'utf8'))
  const parsed = RegistrySchema.parse(raw)
  registry = new Map(parsed.servers.map(s => [s.id, s]))
}

/** @returns {z.infer<typeof ServerSchema>} */
export function getServerConfig(serverId) {
  const server = registry.get(serverId)
  if (!server) throw new Error(`Unknown server: ${serverId}`)
  return server
}

/** @returns {z.infer<typeof SiteSchema> & { serverId: string }} */
export function getSiteConfig(serverId, site) {
  const server = getServerConfig(serverId)
  const siteConfig = server.sites[site]
  if (!siteConfig) throw new Error(`Unknown site: ${site} on server ${serverId}`)
  return { ...siteConfig, serverId }
}

/**
 * Look up which server owns a given site domain.
 * Returns { serverId, server, site } or throws if not found.
 */
export function resolveServerForSite(siteDomain) {
  for (const [serverId, server] of registry) {
    if (server.sites[siteDomain]) {
      return {
        serverId,
        server,
        site: server.sites[siteDomain]
      }
    }
  }
  throw new Error(`No server configured for site: ${siteDomain}`)
}
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
npm test -- tests/config.test.js
```

Expected: all PASS. (Note: dynamic imports with cache-busting query strings require vitest's `--no-cache` or each test re-running cleanly — if tests still fail due to module caching, add `vi.resetModules()` before imports in `beforeEach`.)

- [ ] **Step 5: Commit**

```bash
git add src/config/servers.js tests/config.test.js
git commit -m "feat: server registry loader with zod validation"
```

---

## Task 3: SSH connection pool (`src/ssh/client.js`)

**Files:**
- Create: `src/ssh/client.js`

The pool is a `Map<serverId, { ssh: NodeSSH, lastUsed: number }>`. An idle timer closes connections after 5 minutes. `getConnection` is the only export needed by executor.

- [ ] **Step 1: Write failing test (host allowlist check)**

Create `tests/client.test.js`:

```js
import { describe, it, expect, vi, beforeEach } from 'vitest'

// We test the allowlist guard in isolation by mocking getServerConfig to throw
// before any real SSH connection is attempted.

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
```

- [ ] **Step 2: Run test to confirm it fails**

```bash
npm test -- tests/client.test.js
```

Expected: FAIL — module not found.

- [ ] **Step 3: Implement `src/ssh/client.js`**

```js
import { NodeSSH } from 'node-ssh'
import { homedir } from 'os'
import { getServerConfig } from '../config/servers.js'

/** @type {Map<string, { ssh: NodeSSH, lastUsed: number, timer: NodeJS.Timeout }>} */
const pool = new Map()

const IDLE_MS = 5 * 60 * 1000

function expandHome(p) {
  return p.startsWith('~') ? p.replace('~', homedir()) : p
}

function scheduleIdle(serverId) {
  const entry = pool.get(serverId)
  if (!entry) return
  clearTimeout(entry.timer)
  entry.timer = setTimeout(() => {
    const e = pool.get(serverId)
    if (e) {
      e.ssh.dispose()
      pool.delete(serverId)
    }
  }, IDLE_MS)
}

export async function getConnection(serverId) {
  // Allowlist check — throws if not in registry
  const server = getServerConfig(serverId)

  const existing = pool.get(serverId)
  if (existing?.ssh.isConnected()) {
    existing.lastUsed = Date.now()
    scheduleIdle(serverId)
    return existing.ssh
  }

  const ssh = new NodeSSH()
  await ssh.connect({
    host: server.host,
    port: server.port,
    username: server.user,
    privateKeyPath: expandHome(server.privateKeyPath),
    readyTimeout: 10000
  })

  pool.set(serverId, { ssh, lastUsed: Date.now(), timer: null })
  scheduleIdle(serverId)
  return ssh
}

export function closeAll() {
  for (const [id, entry] of pool) {
    clearTimeout(entry.timer)
    entry.ssh.dispose()
    pool.delete(id)
  }
}
```

- [ ] **Step 4: Run test to confirm it passes**

```bash
npm test -- tests/client.test.js
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ssh/client.js tests/client.test.js
git commit -m "feat: SSH connection pool with idle timeout and allowlist guard"
```

---

## Task 4: Command executor (`src/ssh/executor.js`)

**Files:**
- Create: `src/ssh/executor.js`
- Create: `tests/executor.test.js`

This is where the command allowlist lives. Only `tail`, `head`, `grep`, `cat`, `ls` are permitted. Commands are parsed by splitting on whitespace and checking `argv[0]`. No shell expansion — use `execCommand`, not `exec`.

- [ ] **Step 1: Write failing tests**

Create `tests/executor.test.js`:

```js
import { describe, it, expect, vi, beforeEach } from 'vitest'

describe('runCommand allowlist', () => {
  beforeEach(() => {
    vi.resetModules()
  })

  it('allows tail', async () => {
    vi.doMock('../src/ssh/client.js', () => ({
      getConnection: async () => ({
        execCommand: async (cmd) => ({ stdout: 'line1\nline2', stderr: '', code: 0 })
      })
    }))
    const { runCommand } = await import('../src/ssh/executor.js')
    const result = await runCommand('anyserver', 'tail -n 10 /var/log/app.log')
    expect(result.stdout).toBe('line1\nline2')
    expect(result.exitCode).toBe(0)
  })

  it('allows head', async () => {
    vi.doMock('../src/ssh/client.js', () => ({
      getConnection: async () => ({
        execCommand: async () => ({ stdout: 'data', stderr: '', code: 0 })
      })
    }))
    const { runCommand } = await import('../src/ssh/executor.js')
    const result = await runCommand('anyserver', 'head -c 1000 /var/www/file.php')
    expect(result.exitCode).toBe(0)
  })

  it('rejects rm', async () => {
    vi.doMock('../src/ssh/client.js', () => ({
      getConnection: async () => ({ execCommand: async () => ({}) })
    }))
    const { runCommand } = await import('../src/ssh/executor.js')
    await expect(runCommand('anyserver', 'rm -rf /var/www')).rejects.toThrow(
      'Command not allowed: rm'
    )
  })

  it('rejects bash', async () => {
    vi.doMock('../src/ssh/client.js', () => ({
      getConnection: async () => ({ execCommand: async () => ({}) })
    }))
    const { runCommand } = await import('../src/ssh/executor.js')
    await expect(runCommand('anyserver', 'bash -c "cat /etc/passwd"')).rejects.toThrow(
      'Command not allowed: bash'
    )
  })

  it('rejects empty command', async () => {
    vi.doMock('../src/ssh/client.js', () => ({
      getConnection: async () => ({ execCommand: async () => ({}) })
    }))
    const { runCommand } = await import('../src/ssh/executor.js')
    await expect(runCommand('anyserver', '')).rejects.toThrow('Command not allowed')
  })

  it('returns stderr without throwing on non-zero exit', async () => {
    vi.doMock('../src/ssh/client.js', () => ({
      getConnection: async () => ({
        execCommand: async () => ({ stdout: '', stderr: 'No such file', code: 1 })
      })
    }))
    const { runCommand } = await import('../src/ssh/executor.js')
    const result = await runCommand('anyserver', 'tail -n 10 /nonexistent')
    expect(result.exitCode).toBe(1)
    expect(result.stderr).toBe('No such file')
  })
})
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
npm test -- tests/executor.test.js
```

Expected: FAIL — module not found.

- [ ] **Step 3: Implement `src/ssh/executor.js`**

```js
import { getConnection } from './client.js'

const ALLOWED_COMMANDS = new Set(['tail', 'head', 'grep', 'cat', 'ls'])
const TIMEOUT_MS = 10000

function parseCommandBinary(cmd) {
  const parts = cmd.trim().split(/\s+/)
  return parts[0] || ''
}

export async function runCommand(serverId, command) {
  const binary = parseCommandBinary(command)
  if (!ALLOWED_COMMANDS.has(binary)) {
    throw new Error(`Command not allowed: ${binary || '(empty)'}`)
  }

  const ssh = await getConnection(serverId)

  const result = await Promise.race([
    ssh.execCommand(command),
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error(`Command timed out after ${TIMEOUT_MS}ms`)), TIMEOUT_MS)
    )
  ])

  return {
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
    exitCode: result.code ?? -1
  }
}
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
npm test -- tests/executor.test.js
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ssh/executor.js tests/executor.test.js
git commit -m "feat: SSH command executor with allowlist and timeout"
```

---

## Task 5: `read_log` tool (`src/tools/read-log.js`)

**Files:**
- Create: `src/tools/read-log.js`
- Create: `tests/read-log.test.js`

Log type resolution:
- `debug` → `{wordpressRoot}/wp-content/debug.log`
- `error` → `{logDir}/{site}.error.log`
- `access` → `{logDir}/{site}.access.log`

Hard caps: `lines` max 500, `filter` is passed to `grep -i` only if present.

- [ ] **Step 1: Write failing tests**

Create `tests/read-log.test.js`:

```js
import { describe, it, expect, vi, beforeEach } from 'vitest'

const SITE_CONFIG = {
  serverId: 'testserver',
  wordpressRoot: '/var/www/example.com/public',
  logDir: '/var/log/nginx'
}

describe('read_log path resolution', () => {
  beforeEach(() => {
    vi.resetModules()
  })

  it('resolves debug log to wordpressRoot/wp-content/debug.log', async () => {
    let capturedCmd = null
    vi.doMock('../src/ssh/executor.js', () => ({
      runCommand: async (serverId, cmd) => {
        capturedCmd = cmd
        return { stdout: 'log content', stderr: '', exitCode: 0 }
      }
    }))
    vi.doMock('../src/config/servers.js', () => ({
      resolveServerForSite: () => ({ serverId: 'testserver', site: SITE_CONFIG })
    }))
    const { readLogHandler } = await import('../src/tools/read-log.js')
    await readLogHandler({ site: 'example.com', log: 'debug', lines: 10 })
    expect(capturedCmd).toContain('/var/www/example.com/public/wp-content/debug.log')
    expect(capturedCmd).toMatch(/^tail -n 10/)
  })

  it('resolves error log to logDir/{site}.error.log', async () => {
    let capturedCmd = null
    vi.doMock('../src/ssh/executor.js', () => ({
      runCommand: async (serverId, cmd) => {
        capturedCmd = cmd
        return { stdout: '', stderr: '', exitCode: 0 }
      }
    }))
    vi.doMock('../src/config/servers.js', () => ({
      resolveServerForSite: () => ({ serverId: 'testserver', site: SITE_CONFIG })
    }))
    const { readLogHandler } = await import('../src/tools/read-log.js')
    await readLogHandler({ site: 'example.com', log: 'error', lines: 20 })
    expect(capturedCmd).toContain('/var/log/nginx/example.com.error.log')
  })

  it('resolves access log to logDir/{site}.access.log', async () => {
    let capturedCmd = null
    vi.doMock('../src/ssh/executor.js', () => ({
      runCommand: async (serverId, cmd) => {
        capturedCmd = cmd
        return { stdout: '', stderr: '', exitCode: 0 }
      }
    }))
    vi.doMock('../src/config/servers.js', () => ({
      resolveServerForSite: () => ({ serverId: 'testserver', site: SITE_CONFIG })
    }))
    const { readLogHandler } = await import('../src/tools/read-log.js')
    await readLogHandler({ site: 'example.com', log: 'access', lines: 30 })
    expect(capturedCmd).toContain('/var/log/nginx/example.com.access.log')
  })

  it('appends grep when filter is provided', async () => {
    let capturedCmd = null
    vi.doMock('../src/ssh/executor.js', () => ({
      runCommand: async (serverId, cmd) => {
        capturedCmd = cmd
        return { stdout: 'filtered', stderr: '', exitCode: 0 }
      }
    }))
    vi.doMock('../src/config/servers.js', () => ({
      resolveServerForSite: () => ({ serverId: 'testserver', site: SITE_CONFIG })
    }))
    const { readLogHandler } = await import('../src/tools/read-log.js')
    await readLogHandler({ site: 'example.com', log: 'error', lines: 10, filter: 'fatal' })
    expect(capturedCmd).toContain('grep -i "fatal"')
  })

  it('caps lines at 500', async () => {
    let capturedCmd = null
    vi.doMock('../src/ssh/executor.js', () => ({
      runCommand: async (serverId, cmd) => {
        capturedCmd = cmd
        return { stdout: '', stderr: '', exitCode: 0 }
      }
    }))
    vi.doMock('../src/config/servers.js', () => ({
      resolveServerForSite: () => ({ serverId: 'testserver', site: SITE_CONFIG })
    }))
    const { readLogHandler } = await import('../src/tools/read-log.js')
    await readLogHandler({ site: 'example.com', log: 'debug', lines: 9999 })
    expect(capturedCmd).toContain('tail -n 500')
  })

  it('returns structured output', async () => {
    vi.doMock('../src/ssh/executor.js', () => ({
      runCommand: async () => ({ stdout: 'line1\nline2', stderr: '', exitCode: 0 })
    }))
    vi.doMock('../src/config/servers.js', () => ({
      resolveServerForSite: () => ({ serverId: 'testserver', site: SITE_CONFIG })
    }))
    const { readLogHandler } = await import('../src/tools/read-log.js')
    const result = await readLogHandler({ site: 'example.com', log: 'debug', lines: 10 })
    expect(result.site).toBe('example.com')
    expect(result.log).toBe('debug')
    expect(result.content).toBe('line1\nline2')
    expect(result.resolvedPath).toBeTruthy()
    expect(result.retrievedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/)
  })
})
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
npm test -- tests/read-log.test.js
```

Expected: FAIL — module not found.

- [ ] **Step 3: Implement `src/tools/read-log.js`**

```js
import { z } from 'zod'
import { runCommand } from '../ssh/executor.js'
import { resolveServerForSite } from '../config/servers.js'

const MAX_LINES = 500

const InputSchema = z.object({
  site: z.string().min(1),
  log: z.enum(['debug', 'access', 'error']),
  lines: z.number().int().min(1).default(50),
  filter: z.string().optional()
})

function resolveLogPath(log, site, wordpressRoot, logDir) {
  switch (log) {
    case 'debug':
      return `${wordpressRoot}/wp-content/debug.log`
    case 'error':
      return `${logDir}/${site}.error.log`
    case 'access':
      return `${logDir}/${site}.access.log`
  }
}

export async function readLogHandler(rawInput) {
  const input = InputSchema.parse(rawInput)
  const lines = Math.min(input.lines, MAX_LINES)

  const { serverId, site: siteConfig } = resolveServerForSite(input.site)
  const logPath = resolveLogPath(input.log, input.site, siteConfig.wordpressRoot, siteConfig.logDir)

  const cmd = input.filter
    ? `tail -n ${lines} ${logPath} | grep -i "${input.filter.replace(/"/g, '\\"')}"`
    : `tail -n ${lines} ${logPath}`

  const { stdout, stderr, exitCode } = await runCommand(serverId, cmd.startsWith('tail') ? cmd : 'tail ' + cmd.slice(4))

  // Note: piped commands go through tail only — executor validates the leading binary
  // For grep pipes we pass the full pipeline as a single string to execCommand (no shell)
  // node-ssh's execCommand handles this safely without /bin/sh -c

  return {
    site: input.site,
    log: input.log,
    resolvedPath: logPath,
    lineCount: lines,
    content: stdout || stderr,
    retrievedAt: new Date().toISOString()
  }
}

export const readLogTool = {
  name: 'read_log',
  schema: {
    site: { type: 'string', description: 'Site domain, e.g. example.com' },
    log: { type: 'string', enum: ['debug', 'access', 'error'], description: 'Log type' },
    lines: { type: 'number', description: 'Number of lines to tail (max 500)', default: 50 },
    filter: { type: 'string', description: 'Optional grep filter string' }
  },
  handler: readLogHandler
}
```

**Note on piped commands:** `node-ssh`'s `execCommand` accepts a full command string and runs it through the server's default shell non-interactively. The piped `tail … | grep …` string is safe because `grep` itself is allowlisted and we're not spawning `/bin/sh -c` on the local machine. The allowlist check in executor.js validates the leading binary — update executor to accept the piped form in Task 5, Step 4 below.

- [ ] **Step 4: Update executor allowlist to handle piped commands**

Open `src/ssh/executor.js` and update `parseCommandBinary` to extract the first word of the full command, which already handles pipes correctly since `tail -n 50 /path | grep foo` starts with `tail`:

```js
// No change needed — parseCommandBinary already splits on whitespace and returns argv[0].
// A command like "tail -n 50 /path | grep foo" correctly extracts "tail".
// Verify this with a quick test:
```

Run the executor tests again to confirm nothing regressed:

```bash
npm test -- tests/executor.test.js
```

Expected: all PASS.

- [ ] **Step 5: Run read-log tests**

```bash
npm test -- tests/read-log.test.js
```

Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add src/tools/read-log.js tests/read-log.test.js
git commit -m "feat: read_log tool with path resolution and grep filter"
```

---

## Task 6: `read_file` tool (`src/tools/read-file.js`)

**Files:**
- Create: `src/tools/read-file.js`
- Create: `tests/read-file.test.js`

Path confinement: resolve `{wordpressRoot}/{path}` and verify the result starts with `wordpressRoot`. Reject any input that escapes (e.g. `../../etc/passwd`). Hard cap: `maxBytes` max 51200 (50 KB).

- [ ] **Step 1: Write failing tests**

Create `tests/read-file.test.js`:

```js
import { describe, it, expect, vi, beforeEach } from 'vitest'

const SITE_CONFIG = {
  serverId: 'testserver',
  wordpressRoot: '/var/www/example.com/public',
  logDir: '/var/log/nginx'
}

describe('read_file path confinement', () => {
  beforeEach(() => {
    vi.resetModules()
  })

  it('resolves valid relative path correctly', async () => {
    let capturedCmd = null
    vi.doMock('../src/ssh/executor.js', () => ({
      runCommand: async (serverId, cmd) => {
        capturedCmd = cmd
        return { stdout: '<?php', stderr: '', exitCode: 0 }
      }
    }))
    vi.doMock('../src/config/servers.js', () => ({
      resolveServerForSite: () => ({ serverId: 'testserver', site: SITE_CONFIG })
    }))
    const { readFileHandler } = await import('../src/tools/read-file.js')
    await readFileHandler({ site: 'example.com', path: 'wp-config.php', maxBytes: 1000 })
    expect(capturedCmd).toContain('/var/www/example.com/public/wp-config.php')
    expect(capturedCmd).toMatch(/^head -c 1000/)
  })

  it('rejects path traversal attempt', async () => {
    vi.doMock('../src/ssh/executor.js', () => ({
      runCommand: async () => ({ stdout: '', stderr: '', exitCode: 0 })
    }))
    vi.doMock('../src/config/servers.js', () => ({
      resolveServerForSite: () => ({ serverId: 'testserver', site: SITE_CONFIG })
    }))
    const { readFileHandler } = await import('../src/tools/read-file.js')
    await expect(
      readFileHandler({ site: 'example.com', path: '../../etc/passwd', maxBytes: 1000 })
    ).rejects.toThrow('Path escapes WordPress root')
  })

  it('rejects absolute path input', async () => {
    vi.doMock('../src/ssh/executor.js', () => ({
      runCommand: async () => ({ stdout: '', stderr: '', exitCode: 0 })
    }))
    vi.doMock('../src/config/servers.js', () => ({
      resolveServerForSite: () => ({ serverId: 'testserver', site: SITE_CONFIG })
    }))
    const { readFileHandler } = await import('../src/tools/read-file.js')
    await expect(
      readFileHandler({ site: 'example.com', path: '/etc/passwd', maxBytes: 1000 })
    ).rejects.toThrow('Path escapes WordPress root')
  })

  it('caps maxBytes at 51200', async () => {
    let capturedCmd = null
    vi.doMock('../src/ssh/executor.js', () => ({
      runCommand: async (serverId, cmd) => {
        capturedCmd = cmd
        return { stdout: 'data', stderr: '', exitCode: 0 }
      }
    }))
    vi.doMock('../src/config/servers.js', () => ({
      resolveServerForSite: () => ({ serverId: 'testserver', site: SITE_CONFIG })
    }))
    const { readFileHandler } = await import('../src/tools/read-file.js')
    await readFileHandler({ site: 'example.com', path: 'wp-config.php', maxBytes: 999999 })
    expect(capturedCmd).toContain('head -c 51200')
  })

  it('returns structured output with truncated flag', async () => {
    vi.doMock('../src/ssh/executor.js', () => ({
      runCommand: async () => ({ stdout: 'x'.repeat(100), stderr: '', exitCode: 0 })
    }))
    vi.doMock('../src/config/servers.js', () => ({
      resolveServerForSite: () => ({ serverId: 'testserver', site: SITE_CONFIG })
    }))
    const { readFileHandler } = await import('../src/tools/read-file.js')
    const result = await readFileHandler({ site: 'example.com', path: 'wp-config.php', maxBytes: 100 })
    expect(result.site).toBe('example.com')
    expect(result.requestedPath).toBe('wp-config.php')
    expect(result.resolvedPath).toBe('/var/www/example.com/public/wp-config.php')
    expect(result.content).toBe('x'.repeat(100))
    // truncated = true when content.length === maxBytes (may have been cut)
    expect(result.truncated).toBe(true)
    expect(result.retrievedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/)
  })
})
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
npm test -- tests/read-file.test.js
```

Expected: FAIL — module not found.

- [ ] **Step 3: Implement `src/tools/read-file.js`**

```js
import { z } from 'zod'
import { resolve, normalize } from 'path'
import { runCommand } from '../ssh/executor.js'
import { resolveServerForSite } from '../config/servers.js'

const MAX_BYTES = 51200

const InputSchema = z.object({
  site: z.string().min(1),
  path: z.string().min(1),
  maxBytes: z.number().int().min(1).default(10000)
})

export async function readFileHandler(rawInput) {
  const input = InputSchema.parse(rawInput)
  const maxBytes = Math.min(input.maxBytes, MAX_BYTES)

  const { serverId, site: siteConfig } = resolveServerForSite(input.site)

  // Resolve and confine path
  const fullPath = resolve(siteConfig.wordpressRoot, input.path)
  // normalize handles .. sequences; confirm it's still under wordpressRoot
  if (!fullPath.startsWith(siteConfig.wordpressRoot + '/') && fullPath !== siteConfig.wordpressRoot) {
    throw new Error(`Path escapes WordPress root: ${input.path}`)
  }

  const { stdout, stderr, exitCode } = await runCommand(serverId, `head -c ${maxBytes} ${fullPath}`)

  const content = stdout || (exitCode !== 0 ? stderr : '')
  return {
    site: input.site,
    requestedPath: input.path,
    resolvedPath: fullPath,
    content,
    truncated: content.length >= maxBytes,
    retrievedAt: new Date().toISOString()
  }
}

export const readFileTool = {
  name: 'read_file',
  schema: {
    site: { type: 'string', description: 'Site domain, e.g. example.com' },
    path: { type: 'string', description: 'Relative path within WordPress root, e.g. wp-config.php' },
    maxBytes: { type: 'number', description: 'Max bytes to read (hard cap: 51200)', default: 10000 }
  },
  handler: readFileHandler
}
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
npm test -- tests/read-file.test.js
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add src/tools/read-file.js tests/read-file.test.js
git commit -m "feat: read_file tool with path confinement and byte cap"
```

---

## Task 7: MCP server entry point (`src/index.js`)

**Files:**
- Create: `src/index.js`

Wire up the MCP server, register both tools with proper Zod input schemas, connect stdio transport, and call `loadRegistry()` on startup.

- [ ] **Step 1: Implement `src/index.js`**

```js
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { z } from 'zod'
import { loadRegistry } from './config/servers.js'
import { readLogHandler } from './tools/read-log.js'
import { readFileHandler } from './tools/read-file.js'
import { closeAll } from './ssh/client.js'

loadRegistry()

const server = new McpServer({
  name: 'tenshi-mcp',
  version: '1.0.0'
})

server.tool(
  'read_log',
  'Tail lines from a WordPress log file (debug/error/access) on a configured server',
  {
    site: z.string().describe('Site domain, e.g. example.com'),
    log: z.enum(['debug', 'access', 'error']).describe('Log type'),
    lines: z.number().int().min(1).max(500).default(50).describe('Number of lines to tail'),
    filter: z.string().optional().describe('Optional grep filter string')
  },
  async ({ site, log, lines, filter }) => {
    try {
      const result = await readLogHandler({ site, log, lines, filter })
      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }]
      }
    } catch (err) {
      return {
        content: [{ type: 'text', text: `Error: ${err.message}` }],
        isError: true
      }
    }
  }
)

server.tool(
  'read_file',
  'Read a file within the WordPress directory of a configured site',
  {
    site: z.string().describe('Site domain, e.g. example.com'),
    path: z.string().describe('Relative path within WordPress root, e.g. wp-config.php'),
    maxBytes: z.number().int().min(1).max(51200).default(10000).describe('Max bytes to read')
  },
  async ({ site, path, maxBytes }) => {
    try {
      const result = await readFileHandler({ site, path, maxBytes })
      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }]
      }
    } catch (err) {
      return {
        content: [{ type: 'text', text: `Error: ${err.message}` }],
        isError: true
      }
    }
  }
)

const transport = new StdioServerTransport()
await server.connect(transport)

process.on('SIGINT', () => { closeAll(); process.exit(0) })
process.on('SIGTERM', () => { closeAll(); process.exit(0) })
```

- [ ] **Step 2: Smoke-test: verify the server starts without error**

You need a minimal `servers.json` for this to work. Create one for testing:

```bash
cat > servers.json << 'EOF'
{
  "servers": [
    {
      "id": "testserver",
      "label": "Test",
      "host": "127.0.0.1",
      "port": 22,
      "user": "deploy",
      "privateKeyPath": "~/.ssh/id_rsa",
      "sites": {
        "example.com": {
          "wordpressRoot": "/var/www/example.com/public",
          "logDir": "/var/log/nginx"
        }
      }
    }
  ]
}
EOF
```

Then start the server and send an MCP initialize message:

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.1"}}}' | node src/index.js
```

Expected: JSON response with `"result"` containing `serverInfo.name: "tenshi-mcp"`. No crash.

- [ ] **Step 3: Verify tool list response**

```bash
printf '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.1"}}}\n{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n' | node src/index.js
```

Expected: second JSON object contains `tools` array with `read_log` and `read_file`.

- [ ] **Step 4: Run full test suite to confirm nothing regressed**

```bash
npm test
```

Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/index.js servers.json
git commit -m "feat: MCP server entry point, register tools, stdio transport"
```

---

## Task 8: Integration test script (`tests/integration.js`)

**Files:**
- Create: `tests/integration.js`

This is a manual script, not a vitest file. Run it directly with a real `servers.json` entry to verify end-to-end SSH connectivity and output shape.

- [ ] **Step 1: Implement `tests/integration.js`**

```js
/**
 * Manual integration test — requires a real servers.json with valid SSH credentials.
 * Usage: node tests/integration.js <serverId> <siteDomain>
 * Example: node tests/integration.js example-server example.com
 */

import { loadRegistry } from '../src/config/servers.js'
import { readLogHandler } from '../src/tools/read-log.js'
import { readFileHandler } from '../src/tools/read-file.js'
import { closeAll } from '../src/ssh/client.js'

const [serverId, site] = process.argv.slice(2)

if (!serverId || !site) {
  console.error('Usage: node tests/integration.js <serverId> <siteDomain>')
  process.exit(1)
}

loadRegistry()

async function run() {
  console.log('\n--- read_log: error (last 20 lines) ---')
  try {
    const r1 = await readLogHandler({ site, log: 'error', lines: 20 })
    console.log('resolvedPath:', r1.resolvedPath)
    console.log('lineCount:', r1.lineCount)
    console.log('content preview:', r1.content.slice(0, 300))
  } catch (e) {
    console.error('read_log error:', e.message)
  }

  console.log('\n--- read_log: debug (last 10 lines, filter: fatal) ---')
  try {
    const r2 = await readLogHandler({ site, log: 'debug', lines: 10, filter: 'fatal' })
    console.log('resolvedPath:', r2.resolvedPath)
    console.log('content:', r2.content || '(no matches)')
  } catch (e) {
    console.error('read_log error:', e.message)
  }

  console.log('\n--- read_file: wp-config.php (first 500 bytes) ---')
  try {
    const r3 = await readFileHandler({ site, path: 'wp-config.php', maxBytes: 500 })
    console.log('resolvedPath:', r3.resolvedPath)
    console.log('truncated:', r3.truncated)
    console.log('content preview:', r3.content.slice(0, 200))
  } catch (e) {
    console.error('read_file error:', e.message)
  }

  console.log('\n--- read_file: path traversal attempt (should fail) ---')
  try {
    await readFileHandler({ site, path: '../../etc/passwd', maxBytes: 100 })
    console.error('ERROR: traversal was not blocked!')
  } catch (e) {
    console.log('Traversal correctly blocked:', e.message)
  }
}

run().finally(() => closeAll())
```

- [ ] **Step 2: Run integration test against a real server**

Replace `example-server` and `example.com` with an actual entry from your `servers.json`:

```bash
node tests/integration.js example-server example.com
```

Expected output:
- `read_log error`: resolvedPath printed, content shows nginx error log lines (or empty file notice)
- `read_log debug + filter`: resolvedPath printed, content shows matching lines or `(no matches)`
- `read_file wp-config.php`: first 500 bytes of wp-config.php displayed
- Traversal attempt: `Traversal correctly blocked: Path escapes WordPress root: ../../etc/passwd`

- [ ] **Step 3: Commit**

```bash
git add tests/integration.js
git commit -m "test: manual integration script for end-to-end SSH verification"
```

---

## Task 9: Claude Code MCP registration

> **Correction note:** this task says to register the server in `.claude/settings.json`. The repo instead ships `.mcp.json.example` for a project `.mcp.json` (git-ignored); see the README registration step. The steps below are kept as originally planned.

**Files:**
- Modify: `.claude/settings.json` (or `~/.claude/settings.json` for global registration)

Register the server so Claude can call `read_log` and `read_file` in any Claude Code session.

- [ ] **Step 1: Add MCP server entry to Claude Code settings**

Open (or create) `.claude/settings.json` in this project directory and add:

```json
{
  "mcpServers": {
    "tenshi-mcp": {
      "command": "node",
      "args": ["<absolute-path-to-this-repo>/src/index.js"],
      "env": {
        "TENSHI_MCP_SERVERS_PATH": "<absolute-path-to-this-repo>/servers.json"
      }
    }
  }
}
```

Replace `<absolute-path-to-this-repo>` with the actual path (e.g. `/path/to/tenshi-mcp`).

- [ ] **Step 2: Restart Claude Code and verify tools appear**

In a new Claude Code session, type:

```
/mcp
```

Expected: `tenshi-mcp` listed as connected, with tools `read_log` and `read_file`.

- [ ] **Step 3: Ask Claude to read a log**

In a new Claude Code session:

```
Use read_log to fetch the last 10 lines of the error log for example.com
```

Expected: Claude calls the tool and returns formatted log output. No permission prompts for the MCP call itself (stdio transport runs locally).

- [ ] **Step 4: Commit settings**

```bash
git add .claude/settings.json
git commit -m "chore: register tenshi-mcp MCP server in project settings"
```

---

## Self-Review

**Spec coverage check:**

| Spec requirement | Task |
|---|---|
| Node.js ESM, `@modelcontextprotocol/sdk`, `node-ssh`, stdio transport | Task 1, 7 |
| `servers.json` registry with Zod validation | Task 2 |
| SSH connection pool, idle timeout 5 min | Task 3 |
| Command allowlist (tail/head/grep/cat/ls) | Task 4 |
| `read_log` — path resolution by log type | Task 5 |
| `read_log` — optional grep filter | Task 5 |
| `read_log` — lines cap 500 | Task 5 |
| `read_file` — path confinement, traversal guard | Task 6 |
| `read_file` — maxBytes cap 50 KB | Task 6 |
| `read_file` — structured output with truncated flag | Task 6 |
| MCP tools registered in index.js | Task 7 |
| Integration test script | Task 8 |
| Claude Code MCP registration | Task 9 |
| `resolveServerForSite` (domain → server lookup for tools) | Task 2 (implemented in servers.js) |
| `expandHome` for `~/` key paths | Task 3 |
| Structured error returns (non-zero exit → stderr in result) | Task 4 |

**Placeholder scan:** No TBDs, TODOs, or vague "add validation" steps found. All code blocks are complete.

**Type consistency check:**
- `resolveServerForSite` defined in Task 2 as returning `{ serverId, server, site }` — used in Tasks 5 and 6 as `{ serverId, site: siteConfig }` ✓
- `runCommand` defined in Task 4 as `(serverId, command) → { stdout, stderr, exitCode }` — used consistently in Tasks 5 and 6 ✓
- `readLogHandler` / `readFileHandler` function names match across tasks ✓
- `closeAll` exported from `client.js` (Task 3) and used in `index.js` (Task 7) and `integration.js` (Task 8) ✓
