import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { copyFileSync, mkdtempSync, readFileSync, rmSync } from 'fs'
import os from 'os'
import path from 'path'
import { fileURLToPath } from 'url'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StdioClientTransport, getDefaultEnvironment } from '@modelcontextprotocol/sdk/client/stdio.js'

// Starts the real server (src/index.js) as a child process over stdio and
// talks to it with the SDK client. No SSH connection is opened: the registry
// is a copy of servers.json.example and no tool is called.

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const entry = path.join(repoRoot, 'src', 'index.js')

let tmpDir
let serversPath

beforeAll(() => {
  tmpDir = mkdtempSync(path.join(os.tmpdir(), 'tenshi-mcp-server-test-'))
  // Not named servers.json, so the ./servers.json default cannot pick it up.
  serversPath = path.join(tmpDir, 'registry.json')
  copyFileSync(path.join(repoRoot, 'servers.json.example'), serversPath)
})

afterAll(() => {
  rmSync(tmpDir, { recursive: true, force: true })
})

/**
 * Connects an SDK client to a freshly spawned server. `env` replaces the
 * inherited environment apart from the SDK's safe defaults, so variables
 * from the developer's shell cannot leak into the test.
 */
async function connect(env) {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [entry],
    cwd: tmpDir,
    env: { ...getDefaultEnvironment(), ...env },
    stderr: 'pipe'
  })
  let stderr = ''
  transport.stderr?.on('data', chunk => { stderr += chunk.toString() })
  const client = new Client({ name: 'tenshi-mcp-test', version: '0.0.0' })
  await client.connect(transport)
  return { client, getStderr: () => stderr }
}

describe('MCP server over stdio', () => {
  it('reports the server name tenshi-mcp and keeps the tool names', async () => {
    const { client, getStderr } = await connect({ TENSHI_MCP_SERVERS_PATH: serversPath })
    try {
      expect(client.getServerVersion()?.name).toBe('tenshi-mcp')
      const { tools } = await client.listTools()
      expect(tools.map(t => t.name).sort()).toEqual(['read_file', 'read_log'])
      expect(getStderr()).not.toContain('SSH_MCP_SERVERS_PATH')
    } finally {
      await client.close()
    }
  }, 20000)

  // tests/fixtures/tools-list.json is the tools/list result recorded with
  // zod 3.25.76 before the move to zod 4. The SDK turns each tool's zod
  // schema into the JSON Schema clients see, with a different converter per
  // zod major, so a dependency update can change what clients are told
  // without any source change. Update the fixture only for an intended
  // change to the tool interface, and say so in the PR.
  it('lists exactly the recorded tool definitions and input schemas', async () => {
    const expected = JSON.parse(readFileSync(path.join(repoRoot, 'tests', 'fixtures', 'tools-list.json'), 'utf8'))
    const { client } = await connect({ TENSHI_MCP_SERVERS_PATH: serversPath })
    try {
      const { tools } = await client.listTools()
      expect(tools).toStrictEqual(expected)
    } finally {
      await client.close()
    }
  }, 20000)

  // The SDK validates arguments against the registered schema before a
  // handler runs. These pin which arguments it refuses and at which path,
  // not zod's wording, which differs between zod majors. SDK 1.30.1 lists
  // one issue per line as "<zod message> at <dot path>" (1.29.0 printed the
  // zod issues as a JSON array). Over the wire an unknown key can only be
  // seen not to be refused; tests/schema.test.js checks that toolInputSchema
  // strips it from the parsed arguments.
  it('refuses out-of-contract arguments in the SDK and does not refuse unknown keys', async () => {
    const refused = [
      ['read_log', { site: 'unknown.example', log: 'not-a-log', lines: 5 }, ['log']],
      ['read_log', { site: 'unknown.example', log: 'debug', lines: 0 }, ['lines']],
      ['read_log', { site: 'unknown.example', log: 'debug', lines: 501 }, ['lines']],
      ['read_log', { site: 'unknown.example', log: 'debug', lines: 1.5 }, ['lines']],
      ['read_log', { site: 'unknown.example', log: 'debug', filter: 'x'.repeat(201) }, ['filter']],
      ['read_log', { log: 'debug' }, ['site']],
      ['read_file', { site: 'unknown.example', path: 'p'.repeat(1025) }, ['path']],
      ['read_file', { site: 'unknown.example', path: 'a.php', maxBytes: 0 }, ['maxBytes']],
      ['read_file', { site: 'unknown.example', path: 'a.php', maxBytes: 51201 }, ['maxBytes']],
      ['read_file', { site: 'unknown.example', path: 'a.php', maxBytes: '100' }, ['maxBytes']],
      ['read_file', { site: 42, path: 'a.php' }, ['site']]
    ]
    // Valid, or valid apart from unknown keys: they reach the handler, which
    // refuses the unknown site. With zod 3 an own "constructor" key was
    // answered with JSON-RPC -32603 (an "expected record" issue on the
    // arguments) before any handler ran; with zod 4 it is an unknown key
    // like any other.
    const accepted = [
      ['read_log', { site: 'unknown.example', log: 'debug' }],
      ['read_log', { site: 'unknown.example', log: 'access', lines: 500, filter: 'x'.repeat(200), extra: 1 }],
      ['read_file', { site: 'unknown.example', path: 'a.php' }],
      ['read_file', { site: 'unknown.example', path: 'a.php', maxBytes: 51200, extra: 'ignored' }],
      ['read_log', JSON.parse('{"site":"unknown.example","log":"debug","constructor":"x","toString":"y"}')],
      ['read_file', JSON.parse('{"site":"unknown.example","path":"a.php","constructor":"x"}')]
    ]
    const { client } = await connect({ TENSHI_MCP_SERVERS_PATH: serversPath })
    try {
      for (const [name, args, issuePath] of refused) {
        const result = await client.callTool({ name, arguments: args })
        expect(result.isError, JSON.stringify(args)).toBe(true)
        const prefix = `MCP error -32602: Input validation error: Invalid arguments for tool ${name}: `
        const text = result.content[0].text
        expect(text.startsWith(prefix), text).toBe(true)
        const issues = text.slice(prefix.length).split('\n')
        expect(issues, text).toHaveLength(1)
        expect(issues[0].endsWith(` at ${issuePath.join('.')}`), text).toBe(true)
      }
      for (const [name, args] of accepted) {
        const result = await client.callTool({ name, arguments: args })
        expect(result.content, JSON.stringify(args)).toEqual([
          { type: 'text', text: 'Error: E_NOT_AVAILABLE: The requested resource is not available.' }
        ])
      }
    } finally {
      await client.close()
    }
  }, 20000)

  it('returns the fixed refusal for an unknown site without echoing the arguments', async () => {
    // The site is not in the registry, so no SSH connection is attempted.
    const { client } = await connect({ TENSHI_MCP_SERVERS_PATH: serversPath })
    try {
      for (const [name, args] of [
        ['read_file', { site: 'unknown-marker.example', path: 'path-marker.php' }],
        ['read_log', { site: 'unknown-marker.example', log: 'debug', lines: 5, filter: 'filter-marker' }]
      ]) {
        const result = await client.callTool({ name, arguments: args })
        expect(result.isError).toBe(true)
        expect(result.content).toEqual([
          { type: 'text', text: 'Error: E_NOT_AVAILABLE: The requested resource is not available.' }
        ])
      }
    } finally {
      await client.close()
    }
  }, 20000)

  it('starts with only the deprecated SSH_MCP_SERVERS_PATH and warns on stderr', async () => {
    const { client, getStderr } = await connect({ SSH_MCP_SERVERS_PATH: serversPath })
    try {
      expect(client.getServerVersion()?.name).toBe('tenshi-mcp')
      const { tools } = await client.listTools()
      expect(tools.map(t => t.name).sort()).toEqual(['read_file', 'read_log'])
      const stderr = getStderr()
      expect(stderr).toContain('SSH_MCP_SERVERS_PATH is deprecated')
      expect(stderr).toContain('TENSHI_MCP_SERVERS_PATH')
      expect(stderr).not.toContain(serversPath)
    } finally {
      await client.close()
    }
  }, 20000)
})
