import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { copyFileSync, mkdtempSync, rmSync } from 'fs'
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
  serversPath = path.join(tmpDir, 'servers.json')
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
    const { client } = await connect({ SSH_MCP_SERVERS_PATH: serversPath })
    try {
      expect(client.getServerVersion()?.name).toBe('tenshi-mcp')
      const { tools } = await client.listTools()
      expect(tools.map(t => t.name).sort()).toEqual(['read_file', 'read_log'])
    } finally {
      await client.close()
    }
  }, 20000)
})
