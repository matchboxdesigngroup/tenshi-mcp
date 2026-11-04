import { describe, it, expect, beforeAll, afterAll, afterEach } from 'vitest'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import {
  startFakeSftpServer,
  loadFakeRegistry,
  fakeServerEntry,
  nonSftpRequests,
  NO_NON_SFTP_REQUESTS
} from './helpers/fake-sftp-server.js'
import { VECTORS } from './helpers/host-key-vectors.js'
import { mkdtempSync, openSync, closeSync, readFileSync, rmSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { createAuditLog, MAX_RECORD_BYTES, AUDIT_EVENT, JOB_ID_META_KEY } from '../src/audit/log.js'
import { createFdSink, FILE_BATCH_BYTES } from '../src/audit/sink.js'
import { createServer, AUDITED_TOOLS, resolveSiteIds } from '../src/server.js'
import { closeAll } from '../src/ssh/client.js'
import { MAX_PATH_LENGTH } from '../src/tools/read-file.js'
import { MAX_FILTER_LENGTH } from '../src/tools/read-log.js'

// Every tools/call answered by the server produces exactly one audit record
// with the right outcome, and no record ever carries content, caller strings,
// registry secrets or host-key material. Runs the real server (createServer)
// over an in-memory MCP transport against the in-process SFTP fake.

const ROOT = '/var/www/example.com/public'
const LOG_DIR = '/var/log/example'
// Synthetic secrets: none may appear in any record.
const SECRET_PASSWORD = 'zqPASSWORDv4lu3'
const CONTENT_MARKER = 'zqCONTENTmarker'
const SECRET_PATH_WORD = 'zqcustomername'
const SECRET_FILTER = 'zqfilter-person@example.com'
const SECRET_SITE = 'zqunknown-site.example'
const SECRET_TOOL = 'zq_unknown_tool'

const FILES = {
  [`${ROOT}/wp-config.php`]: { content: `<?php define('DB_PASSWORD', '${SECRET_PASSWORD}');\n` },
  [`${ROOT}/wp-content/notes.txt`]: { content: `${CONTENT_MARKER}\npassword = ${SECRET_PASSWORD}\nplain line\n` },
  [`${ROOT}/wp-content/${SECRET_PATH_WORD}.txt`]: { content: `${CONTENT_MARKER}\n` },
  [`${ROOT}/wp-content/slow.txt`]: { content: CONTENT_MARKER, hangRead: true },
  [`${ROOT}/wp-content/fifo.txt`]: { content: CONTENT_MARKER, fstatType: 'fifo' },
  [`${ROOT}/wp-content/swap.txt`]: { content: CONTENT_MARKER },
  [`${ROOT}/wp-content/odd.php`]: { content: 'x', realpathReply: `${ROOT}/wp-content/a/../odd.php` },
  [`${ROOT}/wp-content/link-out.txt`]: { symlink: '/srv/canary/secret.txt' },
  [`${ROOT}/wp-content/dir.txt`]: { dir: true },
  [`${ROOT}/wp-content/debug.log`]: { content: `${CONTENT_MARKER} one\napi_key=${SECRET_PASSWORD}\n${CONTENT_MARKER} two\n` },
  [`${LOG_DIR}/example.com.error.log`]: { content: `short\n${'L'.repeat(3000)}\n` },
  '/srv/canary/secret.txt': { content: CONTENT_MARKER }
}

let fake
let restoreRegistry
let registryStrings

beforeAll(async () => {
  fake = await startFakeSftpServer({ files: FILES })
  const badPin = fakeServerEntry(fake, { 'badpin.example': { wordpressRoot: ROOT, logDir: LOG_DIR } }, 'badpin-server', {
    hostKeys: [VECTORS.ed25519.fingerprint]
  })
  restoreRegistry = await loadFakeRegistry(fake, { 'example.com': { wordpressRoot: ROOT, logDir: LOG_DIR } }, 'fake-server', [badPin])
  // Registry values that must never reach a record.
  registryStrings = [fake.host, String(fake.port), fake.username, fake.clientKeyPath, fake.hostKeyFingerprint,
    fake.hostKeyFingerprint.slice('SHA256:'.length), VECTORS.ed25519.fingerprint, VECTORS.ed25519.fingerprint.slice('SHA256:'.length),
    ROOT, LOG_DIR]
})

afterEach(() => {
  const seen = nonSftpRequests(fake)
  fake.resetEvents()
  expect(seen).toEqual(NO_NON_SFTP_REQUESTS)
})

afterAll(async () => {
  closeAll()
  restoreRegistry?.()
  await fake?.close()
})

function memorySink() {
  const lines = []
  return { lines, dropped: 0, write(line) { lines.push(line); return true } }
}

async function connect({ sink = memorySink(), timeoutMs } = {}) {
  const audit = createAuditLog({ sink, tools: AUDITED_TOOLS, resolveSite: resolveSiteIds })
  const server = createServer({ audit, timeoutMs })
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
  await server.connect(serverTransport)
  const client = new Client({ name: 'audit-test', version: '0.0.0' })
  await client.connect(clientTransport)
  return {
    client,
    sink,
    records: () => sink.lines.map(line => JSON.parse(line)),
    close: () => client.close()
  }
}

/** One call; returns the result text and the single record it produced. */
async function callOnce(conn, name, args, meta) {
  const before = conn.sink.lines.length
  const params = { name, arguments: args }
  if (meta !== undefined) params._meta = meta
  const result = await conn.client.callTool(params)
  const added = conn.sink.lines.slice(before)
  expect(added).toHaveLength(1)
  return { result, text: result.content.map(c => c.text).join(''), record: JSON.parse(added[0]), line: added[0] }
}

let conn
beforeAll(async () => { conn = await connect({ timeoutMs: 300 }) })
afterAll(async () => { await conn?.close() })

const NOT_AVAILABLE = 'Error: E_NOT_AVAILABLE: The requested resource is not available.'

describe('audit record per outcome', () => {
  it('records a successful read_file with counts and no content', async () => {
    const { result, text, record, line } = await callOnce(conn, 'read_file', { site: 'example.com', path: 'wp-content/notes.txt' }, { [JOB_ID_META_KEY]: 'hs-0123abcd' })
    expect(result.isError).toBeFalsy()
    expect(text).toContain(CONTENT_MARKER)
    expect(record).toMatchObject({
      event: AUDIT_EVENT,
      v: 1,
      jobId: 'hs-0123abcd',
      jobIdInvalid: false,
      tool: 'read_file',
      site: 'example.com',
      server: 'fake-server',
      outcome: 'ok',
      code: null,
      reason: null,
      bytesReturned: Buffer.byteLength(text, 'utf8'),
      redactedLines: 1,
      truncated: false,
      returnedLines: null,
      auditDropped: 0
    })
    expect(record.request).toEqual({
      site: { type: 'string', length: 11, hash: expect.stringMatching(/^[0-9a-f]{16}$/) },
      path: { type: 'string', length: 20, hash: expect.stringMatching(/^[0-9a-f]{16}$/), segments: 2, ext: 'txt' },
      otherKeys: 0
    })
    expect(new Date(record.ts).toISOString()).toBe(record.ts)
    expect(Number.isInteger(record.durationMs) && record.durationMs >= 0).toBe(true)
    expect(record.instance).toMatch(/^[0-9a-f]{16}$/)
    expect(line).not.toContain(CONTENT_MARKER)
    expect(line).not.toContain('notes')
  })

  it('records truncation when maxBytes cuts the file', async () => {
    const { record } = await callOnce(conn, 'read_file', { site: 'example.com', path: 'wp-content/notes.txt', maxBytes: 5 })
    expect(record).toMatchObject({ outcome: 'ok', truncated: true, redactedLines: 0 })
    expect(record.request.maxBytes).toEqual({ type: 'number', value: 5 })
  })

  it('records a successful read_log with line counts and the filter as length and hash', async () => {
    const { text, record, line } = await callOnce(conn, 'read_log', { site: 'example.com', log: 'debug', lines: 10, filter: SECRET_FILTER })
    expect(record).toMatchObject({ tool: 'read_log', outcome: 'ok', returnedLines: 0, redactedLines: 0, truncated: false })
    expect(record.request.log).toEqual({ value: 'debug' })
    expect(record.request.lines).toEqual({ type: 'number', value: 10 })
    expect(record.request.filter).toEqual({ type: 'string', length: SECRET_FILTER.length, hash: expect.stringMatching(/^[0-9a-f]{16}$/) })
    expect(record.bytesReturned).toBe(Buffer.byteLength(text, 'utf8'))
    expect(line).not.toContain('zqfilter')

    const all = await callOnce(conn, 'read_log', { site: 'example.com', log: 'debug' })
    expect(all.record).toMatchObject({ outcome: 'ok', returnedLines: 3, redactedLines: 1 })

    const long = await callOnce(conn, 'read_log', { site: 'example.com', log: 'error', lines: 1 })
    expect(long.record).toMatchObject({ outcome: 'ok', returnedLines: 1, truncated: true })
  })

  const refusals = [
    ['unknown site', { site: SECRET_SITE, path: 'wp-content/notes.txt' }, 'refused', 'unknown_site'],
    ['prototype site name', { site: 'constructor', path: 'wp-content/notes.txt' }, 'refused', 'unknown_site'],
    ['control characters in the path', { site: 'example.com', path: 'wp-content/\nnotes.txt' }, 'refused', 'path_syntax'],
    ['percent encoding', { site: 'example.com', path: 'wp-content/%2e%2e/notes.txt' }, 'refused', 'path_syntax'],
    ['lexical traversal', { site: 'example.com', path: '../outside.txt' }, 'refused', 'outside_root'],
    ['absolute path', { site: 'example.com', path: '/etc/passwd' }, 'refused', 'outside_root'],
    ['denied file', { site: 'example.com', path: 'wp-config.php' }, 'refused', 'denied'],
    ['extension not allowed', { site: 'example.com', path: 'wp-content/readme.md' }, 'refused', 'not_allowed'],
    ['symlink out of the root', { site: 'example.com', path: 'wp-content/link-out.txt' }, 'refused', 'outside_root'],
    ['non-canonical realpath reply', { site: 'example.com', path: 'wp-content/odd.php' }, 'refused', 'bad_reply'],
    ['directory', { site: 'example.com', path: 'wp-content/dir.txt' }, 'refused', 'not_regular_file'],
    ['fstat type differs', { site: 'example.com', path: 'wp-content/fifo.txt' }, 'refused', 'not_regular_file'],
    ['missing file', { site: 'example.com', path: 'wp-content/missing.txt' }, 'not_available', 'not_found']
  ]

  it.each(refusals)('records %s with its reason, and the model sees only the shared refusal', async (_label, args, outcome, reason) => {
    const { text, record } = await callOnce(conn, 'read_file', args)
    expect(text).toBe(NOT_AVAILABLE)
    expect(record).toMatchObject({ tool: 'read_file', outcome, code: 'E_NOT_AVAILABLE', reason, redactedLines: null, truncated: null })
    expect(record.bytesReturned).toBe(Buffer.byteLength(NOT_AVAILABLE, 'utf8'))
  })

  it('records a file whose owner changed between lstat and open as file_changed', async () => {
    const target = `${ROOT}/wp-content/swap.txt`
    fake.afterOp('LSTAT', target, () => fake.setEntry(target, { content: CONTENT_MARKER, uid: 0, gid: 0, perm: 0o600 }))
    try {
      const { text, record } = await callOnce(conn, 'read_file', { site: 'example.com', path: 'wp-content/swap.txt' })
      expect(text).toBe(NOT_AVAILABLE)
      expect(record).toMatchObject({ outcome: 'refused', code: 'E_NOT_AVAILABLE', reason: 'file_changed' })
    } finally {
      fake.setEntry(target, { content: CONTENT_MARKER })
    }
  })

  it('records the site id for a known site even when the path is refused', async () => {
    const { record } = await callOnce(conn, 'read_file', { site: 'example.com', path: 'wp-config.php' })
    expect(record).toMatchObject({ site: 'example.com', server: 'fake-server' })
    const unknown = await callOnce(conn, 'read_file', { site: SECRET_SITE, path: 'x.txt' })
    expect(unknown.record).toMatchObject({ site: null, server: null })
    expect(unknown.line).not.toContain('zqunknown')
  })

  it('records a timeout as an error', async () => {
    const { text, record } = await callOnce(conn, 'read_file', { site: 'example.com', path: 'wp-content/slow.txt' })
    expect(text).toBe('Error: E_TIMEOUT: The operation timed out.')
    expect(record).toMatchObject({ outcome: 'error', code: 'E_TIMEOUT', reason: 'timeout' })
  })

  it('records an E_HOST_KEY refusal without any key, pin, host or user', async () => {
    const { text, record, line } = await callOnce(conn, 'read_file', { site: 'badpin.example', path: 'wp-content/notes.txt' })
    expect(text).toBe('Error: E_HOST_KEY: The server host key did not match the registry; the connection was refused.')
    expect(record).toMatchObject({ outcome: 'refused', code: 'E_HOST_KEY', reason: 'host_key', site: 'badpin.example', server: 'badpin-server' })
    for (const value of registryStrings) expect(line).not.toContain(value)
  })

  it('records arguments the SDK refuses before any handler runs', async () => {
    const { result, record } = await callOnce(conn, 'read_file', { site: 'example.com', path: 'x.txt', maxBytes: 0 })
    expect(result.isError).toBe(true)
    expect(record).toMatchObject({ tool: 'read_file', outcome: 'refused', code: 'E_INVALID_INPUT', reason: 'invalid_input' })
    expect(record.request.maxBytes).toEqual({ type: 'number', value: 0 })

    const wrongType = await callOnce(conn, 'read_log', { site: ['example.com'], log: 'nope' })
    expect(wrongType.record).toMatchObject({ outcome: 'refused', reason: 'invalid_input', site: null })
    expect(wrongType.record.request).toMatchObject({ site: { type: 'array' }, log: { type: 'string', length: 4 } })
  })

  it('records an unknown tool by length and hash only', async () => {
    const { result, record, line } = await callOnce(conn, SECRET_TOOL, { site: 'example.com' })
    expect(result.isError).toBe(true)
    expect(record).toMatchObject({ tool: null, outcome: 'refused', code: 'E_INVALID_INPUT', reason: 'unknown_tool', site: null })
    expect(record.toolName).toEqual({ type: 'string', length: SECRET_TOOL.length, hash: expect.stringMatching(/^[0-9a-f]{16}$/) })
    expect(record.request).toEqual({ otherKeys: 1 })
    expect(line).not.toContain('zq_unknown')
  })

  it('counts unknown argument keys without recording their names or values', async () => {
    const { record, line } = await callOnce(conn, 'read_file', { site: 'example.com', path: 'wp-content/notes.txt', zqextra: SECRET_PASSWORD })
    expect(record.request.otherKeys).toBe(1)
    expect(line).not.toContain('zqextra')
    expect(line).not.toContain(SECRET_PASSWORD)
  })

  it.each([
    ['absent', undefined, { jobId: null, jobIdInvalid: false }],
    ['valid', { [JOB_ID_META_KEY]: 'hs-' + 'a'.repeat(64) }, { jobId: 'hs-' + 'a'.repeat(64), jobIdInvalid: false }],
    ['with a newline', { [JOB_ID_META_KEY]: 'hs-1\n{"event":"forged"}' }, { jobId: null, jobIdInvalid: true }],
    ['not a string', { [JOB_ID_META_KEY]: 42 }, { jobId: null, jobIdInvalid: true }],
    ['too long', { [JOB_ID_META_KEY]: 'a'.repeat(129) }, { jobId: null, jobIdInvalid: true }],
    ['other meta keys only', { other: 'x' }, { jobId: null, jobIdInvalid: false }]
  ])('records a job id that is %s', async (_label, meta, expected) => {
    const { record, line } = await callOnce(conn, 'read_file', { site: SECRET_SITE, path: 'x.txt' }, meta)
    expect(record).toMatchObject(expected)
    expect(line).not.toContain('forged')
  })
})

describe('one record per call', () => {
  it('writes exactly one record for each of many concurrent mixed calls, with distinct sequence numbers', async () => {
    const c = await connect({ timeoutMs: 300 })
    try {
      const calls = []
      for (let i = 0; i < 12; i++) {
        calls.push(c.client.callTool({ name: 'read_file', arguments: { site: 'example.com', path: 'wp-content/notes.txt' } }))
        calls.push(c.client.callTool({ name: 'read_file', arguments: { site: 'example.com', path: 'wp-config.php' } }))
        calls.push(c.client.callTool({ name: 'read_log', arguments: { site: 'example.com', log: 'debug' } }))
        calls.push(c.client.callTool({ name: SECRET_TOOL, arguments: {} }))
        calls.push(c.client.callTool({ name: 'read_log', arguments: { site: 'example.com', log: 'nope' } }))
      }
      await Promise.all(calls)
      const records = c.records()
      expect(records).toHaveLength(calls.length)
      expect(records.map(r => r.seq).sort((a, b) => a - b)).toEqual(calls.map((_, i) => i + 1))
      const outcomes = {}
      for (const r of records) outcomes[r.reason ?? 'ok'] = (outcomes[r.reason ?? 'ok'] ?? 0) + 1
      expect(outcomes).toEqual({ ok: 24, denied: 12, unknown_tool: 12, invalid_input: 12 })
    } finally {
      await c.close()
    }
  })

  it('writes no record for tools/list', async () => {
    const c = await connect()
    try {
      await c.client.listTools()
      expect(c.sink.lines).toEqual([])
    } finally {
      await c.close()
    }
  })
})

describe('requests the SDK refuses before the dispatcher', () => {
  // Driven over a raw in-memory transport: the SDK client would refuse to
  // send most of these.
  async function rawSession() {
    const sink = memorySink()
    const audit = createAuditLog({ sink, tools: AUDITED_TOOLS, resolveSite: resolveSiteIds })
    const server = createServer({ audit })
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
    await server.connect(serverTransport)
    const replies = new Map()
    clientTransport.onmessage = message => { if ('id' in message) replies.set(message.id, message) }
    await clientTransport.start()
    let id = 0
    async function request(method, params) {
      const mine = ++id
      await clientTransport.send({ jsonrpc: '2.0', id: mine, method, params })
      for (let i = 0; i < 200 && !replies.has(mine); i++) await new Promise(r => setTimeout(r, 5))
      return replies.get(mine)
    }
    await request('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'raw', version: '0' } })
    await clientTransport.send({ jsonrpc: '2.0', method: 'notifications/initialized' })
    return { sink, request, close: () => clientTransport.close() }
  }

  const kinds = [
    ['no name', { arguments: { site: 'example.com', path: SECRET_PATH_WORD } }, { tool: null, toolName: { type: 'undefined' } }],
    ['a name that is not a string', { name: { zq: SECRET_TOOL }, arguments: { site: 'example.com' } }, { tool: null, toolName: { type: 'object' } }],
    ['arguments that are not an object', { name: 'read_file', arguments: SECRET_PATH_WORD }, { tool: 'read_file', request: { arguments: 'string' } }],
    ['task creation', { name: 'read_file', arguments: { site: 'example.com', path: 'wp-content/notes.txt' }, task: { ttl: 1000 } }, { tool: 'read_file', site: 'example.com' }]
  ]

  it.each(kinds)('records a tools/call with %s once, as invalid_input, without running tool code', async (_label, params, expected) => {
    const s = await rawSession()
    try {
      const reply = await s.request('tools/call', { ...params, _meta: { [JOB_ID_META_KEY]: 'hs-raw' } })
      expect(reply.error).toBeDefined()
      expect(s.sink.lines).toHaveLength(1)
      const record = JSON.parse(s.sink.lines[0])
      expect(record).toMatchObject({ outcome: 'refused', code: 'E_INVALID_INPUT', reason: 'invalid_input', jobId: 'hs-raw', redactedLines: null, ...expected })
      expect(record.bytesReturned).toBe(Buffer.byteLength(reply.error.message, 'utf8'))
      expect(s.sink.lines[0]).not.toContain('zq')
      expect(fake.events.opens).toEqual([])
    } finally {
      await s.close()
    }
  })

  it('records one line per call when refused and accepted requests are mixed, and none for other methods', async () => {
    const s = await rawSession()
    try {
      await s.request('tools/list', {})
      await s.request('tools/call', { name: 'read_file', arguments: { site: SECRET_SITE, path: 'x.txt' } })
      await s.request('tools/call', { arguments: {} })
      await s.request('tools/call', { name: 'read_file', arguments: { site: SECRET_SITE, path: 'x.txt' } })
      expect(s.sink.lines.map(l => JSON.parse(l).reason)).toEqual(['unknown_site', 'invalid_input', 'unknown_site'])
      expect(s.sink.lines.map(l => JSON.parse(l).seq)).toEqual([1, 2, 3])
    } finally {
      await s.close()
    }
  })
})

describe('no content and no secrets in any record', () => {
  // Deterministic pseudo-random strings with a prefix that is not hex, so a
  // match can only be the value itself, never part of a hash.
  function* strings(seed, count) {
    let x = seed
    const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789-_.'
    for (let i = 0; i < count; i++) {
      let s = 'zq'
      for (let j = 0; j < 10; j++) {
        x = (x * 1103515245 + 12345) % 2147483648
        s += alphabet[x % alphabet.length]
      }
      yield s
    }
  }

  it('never writes a caller string, file content, credential or registry value', async () => {
    const c = await connect({ timeoutMs: 300 })
    try {
      const sent = []
      for (const word of strings(7, 40)) {
        sent.push(word)
        const variants = [
          ['read_file', { site: 'example.com', path: `wp-content/${word}.txt` }],
          ['read_file', { site: 'example.com', path: `${word}/../../${word}.php` }],
          ['read_file', { site: word, path: `${word}.txt` }],
          ['read_log', { site: 'example.com', log: 'debug', filter: word }],
          ['read_log', { site: 'example.com', log: word }],
          [word, { [word]: word }]
        ]
        for (const [name, args] of variants) {
          await c.client.callTool({ name, arguments: args, _meta: { [JOB_ID_META_KEY]: `${word}\n` } })
        }
      }
      // Calls that return content and redact credentials.
      await c.client.callTool({ name: 'read_file', arguments: { site: 'example.com', path: 'wp-content/notes.txt' } })
      await c.client.callTool({ name: 'read_file', arguments: { site: 'example.com', path: `wp-content/${SECRET_PATH_WORD}.txt` } })
      await c.client.callTool({ name: 'read_log', arguments: { site: 'example.com', log: 'debug' } })
      await c.client.callTool({ name: 'read_file', arguments: { site: 'badpin.example', path: 'wp-content/notes.txt' } })

      const forbidden = [...sent, SECRET_PASSWORD, CONTENT_MARKER, SECRET_PATH_WORD, ...registryStrings, 'notes', 'wp-config', 'wp-content', 'debug.log']
      expect(c.sink.lines.length).toBe(40 * 6 + 4)
      for (const line of c.sink.lines) {
        for (const value of forbidden) expect(line, value).not.toContain(value)
      }
    } finally {
      await c.close()
    }
  })
})

describe('log injection and size bounds', () => {
  const hostile = [
    'wp-content/a\n{"event":"forged"}.txt',
    'wp-content/a\r\nb.txt',
    'wp-content/\u001b[31mred\u001b[0m.txt',
    'wp-content/\u009b31m.txt',
    'wp-content/a\u2028b\u2029.txt',
    'wp-content/\u202etxt.php',
    'wp-content/\u0000.txt',
    'wp-content/\ud800.txt'
  ]

  it.each(hostile)('keeps a hostile path out of the record and the record on one printable line (%j)', async path => {
    const { record, line } = await callOnce(conn, 'read_file', { site: 'example.com', path })
    expect(line.endsWith('\n')).toBe(true)
    expect(line.slice(0, -1)).toMatch(/^[\x20-\x7e]+$/)
    expect(line).not.toContain('forged')
    expect(record.request.path.length).toBe(path.length)
  })

  it('stays under the record bound with every argument at its maximum size', async () => {
    const path = ('a'.repeat(99) + '/').repeat(10) + 'b'.repeat(MAX_PATH_LENGTH - 1000 - 4) + '.txt'
    expect(path.length).toBe(MAX_PATH_LENGTH)
    const jobId = 'h' + '-'.repeat(127)
    const file = await callOnce(conn, 'read_file', { site: 'example.com', path, maxBytes: 51200 }, { [JOB_ID_META_KEY]: jobId })
    expect(file.record.jobId).toBe(jobId)
    expect(file.record.oversize).toBeUndefined()
    expect(Buffer.byteLength(file.line)).toBeLessThanOrEqual(MAX_RECORD_BYTES)
    const log = await callOnce(conn, 'read_log', { site: 'example.com', log: 'debug', lines: 500, filter: '\u{1F600}'.repeat(MAX_FILTER_LENGTH / 2) }, { [JOB_ID_META_KEY]: jobId })
    expect(log.record.oversize).toBeUndefined()
    expect(Buffer.byteLength(log.line)).toBeLessThanOrEqual(MAX_RECORD_BYTES)
  })
})

describe('bursts', () => {
  it('records every call of a burst within the queue bound, with no drops', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'tenshi-mcp-burst-'))
    const file = join(dir, 'audit.jsonl')
    const fd = openSync(file, 'a', 0o600)
    const sink = createFdSink(fd, { batchBytes: FILE_BATCH_BYTES })
    const c = await connect({ sink })
    try {
      const n = 3000
      await Promise.all(Array.from({ length: n }, () => c.client.callTool({ name: 'read_file', arguments: { site: SECRET_SITE, path: 'x.txt' } })))
      await sink.flush(10000)
      const records = readFileSync(file, 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l))
      expect(sink.dropped).toBe(0)
      expect(records).toHaveLength(n)
      expect(records.map(r => r.seq).sort((a, b) => a - b)).toEqual(Array.from({ length: n }, (_, i) => i + 1))
      expect(records.every(r => r.auditDropped === 0)).toBe(true)
    } finally {
      await c.close()
      closeSync(fd)
      rmSync(dir, { recursive: true, force: true })
    }
  }, 30000)

  it('counts the records of a burst beyond the queue bound', async () => {
    let release
    const gate = new Promise(resolve => { release = resolve })
    const lines = []
    const write = (fd, buf, off, len, pos, cb) => { gate.then(() => { lines.push(buf.toString()); cb(null, len) }) }
    const sink = createFdSink(99, { write, maxPending: 20, batchBytes: FILE_BATCH_BYTES })
    const c = await connect({ sink })
    try {
      await Promise.all(Array.from({ length: 50 }, () => c.client.callTool({ name: 'read_file', arguments: { site: SECRET_SITE, path: 'x.txt' } })))
      expect(sink.dropped).toBe(30)
      release()
      await sink.flush(5000)
      await c.client.callTool({ name: 'read_file', arguments: { site: SECRET_SITE, path: 'x.txt' } })
      await sink.flush(5000)
      const records = lines.join('').split('\n').filter(Boolean).map(l => JSON.parse(l))
      expect(records).toHaveLength(21)
      expect(records.at(-1)).toMatchObject({ seq: 51, auditDropped: 30 })
    } finally {
      await c.close()
    }
  })
})

describe('sink failure', () => {
  it('returns the tool result unchanged when the sink throws, and counts the loss in the next record', async () => {
    let fail = true
    const lines = []
    const sink = { dropped: 0, write(line) { if (fail) throw new Error(`disk full at ${ROOT}`); lines.push(line); return true } }
    const c = await connect({ sink })
    try {
      const first = await c.client.callTool({ name: 'read_file', arguments: { site: 'example.com', path: 'wp-content/notes.txt' } })
      expect(first.isError).toBeFalsy()
      expect(first.content[0].text).toContain(CONTENT_MARKER)
      fail = false
      await c.client.callTool({ name: 'read_file', arguments: { site: 'example.com', path: 'wp-config.php' } })
      expect(lines).toHaveLength(1)
      expect(JSON.parse(lines[0])).toMatchObject({ seq: 2, auditDropped: 1, reason: 'denied' })
    } finally {
      await c.close()
    }
  })

  it('reports drops counted by the sink itself', async () => {
    const lines = []
    const sink = { dropped: 3, write(line) { lines.push(line); return true } }
    const c = await connect({ sink })
    try {
      await c.client.callTool({ name: 'read_file', arguments: { site: SECRET_SITE, path: 'x.txt' } })
      expect(JSON.parse(lines[0]).auditDropped).toBe(3)
    } finally {
      await c.close()
    }
  })
})
