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
