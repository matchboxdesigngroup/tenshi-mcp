import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest'
import { copyFileSync, mkdtempSync, rmSync, writeFileSync } from 'fs'
import os from 'os'
import path from 'path'
import { fileURLToPath } from 'url'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StdioClientTransport, getDefaultEnvironment } from '@modelcontextprotocol/sdk/client/stdio.js'
import { readLogHandler, MAX_FILTER_LENGTH } from '../src/tools/read-log.js'
import { readFileHandler, MAX_PATH_LENGTH } from '../src/tools/read-file.js'
import { VECTORS } from './helpers/host-key-vectors.js'

// String length bounds count UTF-16 code units (`value.length`), as zod 3
// did. zod 4's own .min()/.max() count code points, which would let a string
// of astral characters (two units each) run to twice the cap. This file uses
// only the public surfaces (the tool handlers, the server over stdio and
// loadRegistry), so it runs unchanged against the zod 3 code as well: the
// expected outcomes below are the zod 3 outcomes.

const ASTRAL = '\u{1F600}' // one code point, two UTF-16 units
const HIGH = '\uD83D' // lone high surrogate, one unit
const LOW = '\uDE00' // lone low surrogate, one unit

/** [label, value, accepted] around an upper cap of `max` UTF-16 units (max even). */
function maxCases(max) {
  return [
    ['max ASCII', 'a'.repeat(max), true],
    ['max + 1 ASCII', 'a'.repeat(max + 1), false],
    ['max/2 astral (max units)', ASTRAL.repeat(max / 2), true],
    ['max/2 astral + 1 ASCII (max + 1 units, max/2 + 1 code points)', ASTRAL.repeat(max / 2) + 'a', false],
    ['max/2 + 1 astral (max + 2 units)', ASTRAL.repeat(max / 2 + 1), false],
    ['max astral (2 * max units, max code points)', ASTRAL.repeat(max), false],
    ['pair ending at the cap (max - 2 ASCII + astral)', 'a'.repeat(max - 2) + ASTRAL, true],
    ['pair straddling the cap (max - 1 ASCII + astral)', 'a'.repeat(max - 1) + ASTRAL, false],
    ['max lone high surrogates', HIGH.repeat(max), true],
    ['max + 1 lone high surrogates', HIGH.repeat(max + 1), false],
    ['max - 1 ASCII + lone low surrogate', 'a'.repeat(max - 1) + LOW, true],
    ['max ASCII + lone low surrogate', 'a'.repeat(max) + LOW, false],
    ['max/2 reversed pairs (low, high)', (LOW + HIGH).repeat(max / 2), true],
    ['max/2 reversed pairs + lone low surrogate', (LOW + HIGH).repeat(max / 2) + LOW, false]
  ]
}

/** [label, value, accepted] around a lower bound of one UTF-16 unit. */
const MIN_ONE_CASES = [
  ['empty', '', false],
  ['one lone high surrogate', HIGH, true],
  ['one lone low surrogate', LOW, true],
  ['one astral character', ASTRAL, true]
]

const NOT_AVAILABLE = 'E_NOT_AVAILABLE: The requested resource is not available.'
const INVALID_INPUT = 'E_INVALID_INPUT: The tool arguments are invalid.'

/** Runs a handler; returns the refusal message and the [path, code] of each schema issue. */
async function handlerOutcome(promise) {
  const err = await promise.then(() => null, e => e)
  expect(err, 'an unknown site is never served').not.toBeNull()
  const issues = err.cause?.issues?.map(issue => [issue.path, issue.code]) ?? []
  return { message: err.message, issues }
}

describe('tool handlers count string bounds in UTF-16 units', () => {
  // No registry is loaded, so a value the schema accepts ends at the site
  // lookup as E_NOT_AVAILABLE; a refused value is E_INVALID_INPUT.
  const table = [
    ...maxCases(MAX_FILTER_LENGTH).map(([label, filter, ok]) => [`read_log filter: ${label}`, () => readLogHandler({ site: 'unknown.example', log: 'debug', filter }), ok, ['filter'], 'too_big']),
    ...MIN_ONE_CASES.map(([label, site, ok]) => [`read_log site: ${label}`, () => readLogHandler({ site, log: 'debug' }), ok, ['site'], 'too_small']),
    ...maxCases(MAX_PATH_LENGTH).map(([label, p, ok]) => [`read_file path: ${label}`, () => readFileHandler({ site: 'unknown.example', path: p }), ok, ['path'], 'too_big']),
    ...MIN_ONE_CASES.map(([label, p, ok]) => [`read_file path: ${label}`, () => readFileHandler({ site: 'unknown.example', path: p }), ok, ['path'], 'too_small']),
    ...MIN_ONE_CASES.map(([label, site, ok]) => [`read_file site: ${label}`, () => readFileHandler({ site, path: 'index.php' }), ok, ['site'], 'too_small'])
  ]

  it.each(table)('%s', async (_label, call, accepted, issuePath, code) => {
    const { message, issues } = await handlerOutcome(call())
    if (accepted) {
      expect(message).toBe(NOT_AVAILABLE)
    } else {
      expect(message).toBe(INVALID_INPUT)
      expect(issues).toEqual([[issuePath, code]])
    }
  })
})

describe('the SDK counts listed string bounds in UTF-16 units', () => {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
  let tmpDir
  let client

  beforeAll(async () => {
    tmpDir = mkdtempSync(path.join(os.tmpdir(), 'tenshi-mcp-bounds-test-'))
    const serversPath = path.join(tmpDir, 'registry.json')
    copyFileSync(path.join(repoRoot, 'servers.json.example'), serversPath)
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [path.join(repoRoot, 'src', 'index.js')],
      cwd: tmpDir,
      env: { ...getDefaultEnvironment(), TENSHI_MCP_SERVERS_PATH: serversPath },
      stderr: 'pipe'
    })
    client = new Client({ name: 'tenshi-mcp-test', version: '0.0.0' })
    await client.connect(transport)
  }, 20000)

  afterAll(async () => {
    await client?.close()
    rmSync(tmpDir, { recursive: true, force: true })
  })

  const table = [
    ...maxCases(MAX_FILTER_LENGTH).map(([label, filter, ok]) => [`read_log filter: ${label}`, 'read_log', { site: 'unknown.example', log: 'debug', filter }, ok, ['filter']]),
    ...maxCases(MAX_PATH_LENGTH).map(([label, p, ok]) => [`read_file path: ${label}`, 'read_file', { site: 'unknown.example', path: p }, ok, ['path']])
  ]

  it.each(table)('%s', async (_label, name, args, accepted, issuePath) => {
    const result = await client.callTool({ name, arguments: args })
    expect(result.isError).toBe(true)
    const text = result.content[0].text
    if (accepted) {
      // Past the SDK and the handler schema, refused only at the site lookup.
      expect(text).toBe(`Error: ${NOT_AVAILABLE}`)
    } else {
      const prefix = `MCP error -32602: Input validation error: Invalid arguments for tool ${name}: `
      expect(text.startsWith(prefix), text.slice(0, 120)).toBe(true)
      expect(JSON.parse(text.slice(prefix.length)).map(issue => [issue.path, issue.code])).toEqual([[issuePath, 'too_big']])
    }
  })
})

describe('the registry counts non-empty fields in UTF-16 units', () => {
  const server = {
    id: 'testserver',
    label: 'Test Server',
    host: '192.0.2.10',
    port: 22,
    user: 'deploy',
    privateKeyPath: '~/.ssh/id_rsa',
    hostKeys: [VECTORS.ed25519.fingerprint],
    sites: { 'example.com': { wordpressRoot: '/var/www/example.com/public', logDir: '/var/log/nginx' } }
  }
  const fields = [
    ['id', value => ({ ...server, id: value }), 'id'],
    ['label', value => ({ ...server, label: value }), 'label'],
    ['host', value => ({ ...server, host: value }), 'host'],
    ['user', value => ({ ...server, user: value }), 'user'],
    ['privateKeyPath', value => ({ ...server, privateKeyPath: value }), 'privateKeyPath'],
    ['wordpressRoot', value => ({ ...server, sites: { 'example.com': { ...server.sites['example.com'], wordpressRoot: value } } }), 'sites.example.com.wordpressRoot'],
    ['logDir', value => ({ ...server, sites: { 'example.com': { ...server.sites['example.com'], logDir: value } } }), 'sites.example.com.logDir']
  ]
  const table = fields.flatMap(([field, build, issuePath]) =>
    MIN_ONE_CASES.map(([label, value, ok]) => [`${field}: ${label}`, build(value), ok, issuePath]))

  it.each(table)('%s', async (_label, entry, accepted, issuePath) => {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'tenshi-mcp-bounds-registry-'))
    const file = path.join(dir, 'servers.json')
    writeFileSync(file, JSON.stringify({ servers: [entry] }))
    vi.stubEnv('SSH_MCP_SERVERS_PATH', '')
    vi.stubEnv('TENSHI_MCP_SERVERS_PATH', file)
    try {
      vi.resetModules()
      const { loadRegistry } = await import('../src/config/servers.js')
      if (accepted) {
        expect(() => loadRegistry()).not.toThrow()
      } else {
        let err
        try { loadRegistry() } catch (e) { err = e }
        expect(err?.name).toBe('RegistryError')
        const lines = err.message.split('\n')
        expect(lines).toHaveLength(2)
        // A server with an empty id is named by position.
        const label = entry.id === '' ? 'servers[0]' : 'server "testserver"'
        expect(lines[1].startsWith(`  ${label}: ${issuePath}: `), lines[1]).toBe(true)
      }
    } finally {
      vi.unstubAllEnvs()
      vi.resetModules()
      rmSync(dir, { recursive: true, force: true })
    }
  })
})
