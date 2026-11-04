import { describe, it, expect, afterAll } from 'vitest'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { execFileSync } from 'child_process'
import {
  createAuditLog, serializeRecord, extensionClass, outcomeOf, MAX_RECORD_BYTES, AUDIT_EVENT, MAX_PENDING_CALLS
} from '../src/audit/log.js'
import {
  createFdSink, openAuditSink, AuditConfigError, AUDIT_CONFIG_MESSAGE, AUDIT_LOG_ENV, FILE_BATCH_BYTES
} from '../src/audit/sink.js'
import { ERROR_CODES, REASONS, ToolError, toToolError } from '../src/errors.js'

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tenshi-mcp-audit-'))
afterAll(() => fs.rmSync(tmp, { recursive: true, force: true }))

describe('serializeRecord', () => {
  it('writes one line of printable ASCII that parses back to the same values', () => {
    const hostile = 'a\nb\r\u0000\u001b[2J\u007f\u009b31m\u2028\u2029\u202e\u200b\ud800x\u{1F600}"\\'
    const line = serializeRecord({ event: AUDIT_EVENT, value: hostile })
    expect(line.endsWith('\n')).toBe(true)
    expect(line.slice(0, -1)).toMatch(/^[\x20-\x7e]+$/)
    expect(line.indexOf('\n')).toBe(line.length - 1)
    expect(JSON.parse(line).value).toBe(hostile)
  })

  it('replaces a record over the size bound with its fixed fields only', () => {
    const record = { event: AUDIT_EVENT, v: 1, ts: '2026-01-01T00:00:00.000Z', seq: 4, instance: 'abcd', outcome: 'ok', code: null, reason: null, durationMs: 1, auditDropped: 0, extra: 'x'.repeat(MAX_RECORD_BYTES) }
    const line = serializeRecord(record)
    expect(line.length).toBeLessThanOrEqual(MAX_RECORD_BYTES)
    const parsed = JSON.parse(line)
    expect(parsed).toEqual({ event: AUDIT_EVENT, v: 1, ts: record.ts, seq: 4, instance: 'abcd', outcome: 'ok', code: null, reason: null, durationMs: 1, auditDropped: 0, oversize: true })
  })

  it('counts escaped characters toward the bound', () => {
    // 400 control characters become 2400 bytes once escaped.
    const line = serializeRecord({ event: AUDIT_EVENT, v: 1, value: '\u0001'.repeat(400) })
    expect(JSON.parse(line).oversize).toBe(true)
  })
})

describe('field helpers', () => {
  it.each([
    ['wp-content/a.PHP', 'php'],
    ['a/b/readme.txt', 'txt'],
    ['backup.sql', 'sql'],
    ['uploads/john.smith', 'other'],
    ['a/b', 'none'],
    ['a/.env', 'none'],
    ['a/trailing.', 'none'],
    ['a.b/c', 'none']
  ])('classifies the extension of %j as %s', (p, expected) => {
    expect(extensionClass(p)).toBe(expected)
  })

  it('maps every reason to an outcome', () => {
    const outcomes = Object.fromEntries(REASONS.map(r => [r, outcomeOf(r)]))
    expect(outcomes).toEqual({
      invalid_input: 'refused', unknown_tool: 'refused', unknown_site: 'refused', path_syntax: 'refused',
      outside_root: 'refused', denied: 'refused', not_allowed: 'refused', bad_reply: 'refused',
      not_regular_file: 'refused', file_changed: 'refused', host_key: 'refused',
      not_found: 'not_available', permission_denied: 'not_available', remote_status: 'not_available',
      timeout: 'error', remote: 'error', internal: 'error'
    })
  })
})

describe('audit reasons never reach the model', () => {
  it('keeps the reason out of the message and out of JSON', () => {
    const a = new ToolError(ERROR_CODES.NOT_AVAILABLE, { reason: 'denied' })
    const b = new ToolError(ERROR_CODES.NOT_AVAILABLE, { reason: 'not_found' })
    expect(a.message).toBe(b.message)
    expect(a.reason).toBe('denied')
    expect(Object.keys(a)).not.toContain('reason')
    expect(JSON.stringify(a)).not.toContain('denied')
  })

  it('drops a reason that is not in the list', () => {
    expect(new ToolError(ERROR_CODES.NOT_AVAILABLE, { reason: '/etc/passwd' }).reason).toBeUndefined()
  })

  it('gives schema failures the invalid_input reason', async () => {
    const { z } = await import('zod')
    expect(toToolError(z.string().safeParse(1).error).reason).toBe('invalid_input')
  })
})

describe('createAuditLog', () => {
  const tools = { t: { site: 'text', path: 'path' } }
  const sinkOf = () => ({ lines: [], dropped: 0, write(l) { this.lines.push(l); return true } })

  async function run(audit, request, report) {
    const extra = {}
    await audit.wrapCallHandler(async (_req, ex) => {
      if (report) audit.report(ex, report)
      return { content: [{ type: 'text', text: 'abc' }] }
    })(request, extra)
  }

  it('keys hashes per process: equal within one log, different across keys', async () => {
    const one = sinkOf()
    const two = sinkOf()
    const a = createAuditLog({ sink: one, tools, resolveSite: () => null })
    const b = createAuditLog({ sink: two, tools, resolveSite: () => null })
    const req = { params: { name: 't', arguments: { path: 'wp-config.php' } } }
    await run(a, req, { redactedLines: 0, truncated: false })
    await run(a, req, { redactedLines: 0, truncated: false })
    await run(b, req, { redactedLines: 0, truncated: false })
    const [r1, r2] = one.lines.map(l => JSON.parse(l))
    const r3 = JSON.parse(two.lines[0])
    expect(r1.request.path.hash).toBe(r2.request.path.hash)
    expect(r1.request.path.hash).not.toBe(r3.request.path.hash)
    expect(r1.instance).not.toBe(r3.instance)
  })

  it('bounds the table of unanswered requests and counts what it evicts', async () => {
    const sink = sinkOf()
    const audit = createAuditLog({ sink, tools, resolveSite: () => null })
    const inner = { start: async () => {}, close: async () => {}, send: async () => {} }
    const wrapped = audit.wrapTransport(inner)
    wrapped.onmessage = () => {}
    for (let id = 1; id <= MAX_PENDING_CALLS + 3; id++) inner.onmessage({ jsonrpc: '2.0', id, method: 'tools/call', params: { name: 't' } })
    // The oldest three were evicted: answering one of them writes nothing.
    await wrapped.send({ jsonrpc: '2.0', id: 1, error: { code: -32602, message: 'x' } })
    expect(sink.lines).toHaveLength(0)
    await wrapped.send({ jsonrpc: '2.0', id: MAX_PENDING_CALLS + 3, error: { code: -32602, message: 'bad' } })
    expect(JSON.parse(sink.lines[0])).toMatchObject({ reason: 'invalid_input', bytesReturned: 3, auditDropped: 3 })
  })

  it('records a handler that throws as an internal error and rethrows', async () => {
    const sink = sinkOf()
    const audit = createAuditLog({ sink, tools, resolveSite: () => null })
    const boom = new Error('boom /secret/path')
    await expect(audit.wrapCallHandler(async () => { throw boom })({ params: { name: 't', arguments: {} } }, {})).rejects.toBe(boom)
    const record = JSON.parse(sink.lines[0])
    expect(record).toMatchObject({ outcome: 'error', code: 'E_INTERNAL', reason: 'internal', bytesReturned: 0 })
    expect(sink.lines[0]).not.toContain('secret')
  })

  it.each([
    [ERROR_CODES.REMOTE, 'remote', 'error'],
    [ERROR_CODES.INTERNAL, 'internal', 'error'],
    [ERROR_CODES.NOT_AVAILABLE, 'unspecified', 'refused']
  ])('records a reported %s without a reason as %s', async (code, reason, outcome) => {
    const sink = sinkOf()
    const audit = createAuditLog({ sink, tools, resolveSite: () => null })
    await run(audit, { params: { name: 't', arguments: {} } }, { error: new ToolError(code) })
    expect(JSON.parse(sink.lines[0])).toMatchObject({ code, reason, outcome, redactedLines: null })
  })

  it('records a result no tool reported as an internal error', async () => {
    const sink = sinkOf()
    const audit = createAuditLog({ sink, tools, resolveSite: () => null })
    await run(audit, { params: { name: 't', arguments: {} } })
    expect(JSON.parse(sink.lines[0])).toMatchObject({ outcome: 'error', code: 'E_INTERNAL', reason: 'internal' })
  })

  it('rejects counts that are not non-negative safe integers', async () => {
    const sink = sinkOf()
    const audit = createAuditLog({ sink, tools, resolveSite: () => null })
    await run(audit, { params: { name: 't', arguments: {} } }, { redactedLines: -1, truncated: 'yes', returnedLines: 1.5 })
    expect(JSON.parse(sink.lines[0])).toMatchObject({ outcome: 'ok', redactedLines: null, truncated: null, returnedLines: null })
  })

  it('describes non-object arguments by type only', async () => {
    const sink = sinkOf()
    const audit = createAuditLog({ sink, tools, resolveSite: () => null })
    await run(audit, { params: { name: 't', arguments: 'zqsecret' } }, { redactedLines: 0 })
    await run(audit, { params: { name: 't' } }, { redactedLines: 0 })
    expect(JSON.parse(sink.lines[0]).request).toEqual({ arguments: 'string' })
    expect(JSON.parse(sink.lines[1]).request).toEqual({ arguments: 'absent' })
    expect(sink.lines.join('')).not.toContain('zqsecret')
  })
})

/** A write function that completes each call by the script given. */
function scriptedWrite(steps) {
  const written = []
  let call = 0
  const write = (fd, buf, off, len, pos, cb) => {
    const step = steps[Math.min(call++, steps.length - 1)]
    const chunk = Buffer.from(buf.subarray(off, off + len))
    if (step === 'hang') return
    if (step === 'throw') throw new Error('EBADF')
    setImmediate(() => {
      if (typeof step === 'string' && step !== 'all') {
        const err = new Error(step)
        err.code = step
        return cb(err)
      }
      const n = step === 'all' || step === undefined ? chunk.length : Math.min(step, chunk.length)
      written.push(chunk.subarray(0, n).toString())
      cb(null, n)
    })
  }
  return { write, written, calls: () => call }
}

describe('createFdSink', () => {
  it('writes queued lines in order, one write at a time', async () => {
    const w = scriptedWrite(['all'])
    const sink = createFdSink(99, { write: w.write })
    sink.write('a\n')
    sink.write('b\n')
    sink.write('c\n')
    await sink.flush(1000)
    expect(w.written.join('')).toBe('a\nb\nc\n')
    expect(sink.dropped).toBe(0)
  })

  it('finishes a partial write before the next line', async () => {
    const w = scriptedWrite([3, 'all'])
    const sink = createFdSink(99, { write: w.write })
    sink.write('hello\n')
    sink.write('x\n')
    await sink.flush(1000)
    expect(w.written.join('')).toBe('hello\nx\n')
  })

  it('retries a line refused with EAGAIN', async () => {
    const w = scriptedWrite(['EAGAIN', 'all'])
    const sink = createFdSink(99, { write: w.write })
    sink.write('a\n')
    await sink.flush(1000)
    expect(w.written).toEqual(['a\n'])
    expect(sink.dropped).toBe(0)
  })

  it('drops and counts the lines of a write that fails, then carries on', async () => {
    const w = scriptedWrite(['EPIPE', 'throw', 'all'])
    const sink = createFdSink(99, { write: w.write })
    // a is written alone (EPIPE); b and c are queued meanwhile and go out
    // together in the next write, which throws.
    expect(() => { sink.write('a\n'); sink.write('b\n'); sink.write('c\n') }).not.toThrow()
    await sink.flush(1000)
    expect(sink.dropped).toBe(3)
    sink.write('d\n')
    await sink.flush(1000)
    expect(w.written).toEqual(['d\n'])
    expect(sink.dropped).toBe(3)
  })

  it('writes several queued records per write, whole records only, within the batch size', async () => {
    const w = scriptedWrite(['all'])
    const sink = createFdSink(99, { write: w.write, batchBytes: 10 })
    for (const line of ['aaaa\n', 'bbbb\n', 'cccc\n', 'dd\n', 'eeeeeeeeeeeeeeee\n', 'f\n']) sink.write(line)
    await sink.flush(1000)
    // The first record goes out alone; then whole records up to 10 bytes,
    // and a record longer than the batch size on its own.
    expect(w.written).toEqual(['aaaa\n', 'bbbb\ncccc\n', 'dd\n', 'eeeeeeeeeeeeeeee\n', 'f\n'])
    expect(sink.dropped).toBe(0)
  })

  it('completes a partial write that ends inside a batch', async () => {
    const w = scriptedWrite(['all', 7, 'all'])
    const sink = createFdSink(99, { write: w.write, batchBytes: 100 })
    for (const line of ['a\n', 'bbbb\n', 'cccc\n', 'dddd\n']) sink.write(line)
    await sink.flush(1000)
    expect(w.written.join('')).toBe('a\nbbbb\ncccc\ndddd\n')
  })

  it('keeps a burst within the queue bound without loss and counts what is beyond it', async () => {
    let release
    const gate = new Promise(resolve => { release = resolve })
    const lines = []
    const write = (fd, buf, off, len, pos, cb) => { gate.then(() => { lines.push(buf.toString()); cb(null, len) }) }
    const sink = createFdSink(99, { write, maxPending: 100, batchBytes: 64 * 1024 })
    for (let i = 0; i < 100; i++) sink.write(`${i}\n`)
    expect(sink.dropped).toBe(0)
    for (let i = 0; i < 7; i++) sink.write('over\n')
    expect(sink.dropped).toBe(7)
    release()
    await sink.flush(1000)
    expect(lines.join('').split('\n').filter(Boolean)).toEqual(Array.from({ length: 100 }, (_, i) => String(i)))
  })

  it('writes a burst of 4000 records to a real file without loss', async () => {
    const file = path.join(tmp, 'burst.jsonl')
    const fd = fs.openSync(file, 'a', 0o600)
    const sink = createFdSink(fd, { batchBytes: FILE_BATCH_BYTES })
    const record = 'x'.repeat(600) + '\n'
    for (let i = 0; i < 4000; i++) sink.write(record)
    await sink.flush(10000)
    fs.closeSync(fd)
    expect(sink.dropped).toBe(0)
    expect(fs.statSync(file).size).toBe(4000 * record.length)
  })

  it('never blocks on a write that does not complete: the queue is bounded and the rest is counted', async () => {
    const w = scriptedWrite(['hang'])
    const sink = createFdSink(99, { write: w.write, maxPending: 5 })
    const started = Date.now()
    const accepted = Array.from({ length: 20 }, (_, i) => sink.write(`${i}\n`))
    expect(Date.now() - started).toBeLessThan(100)
    expect(accepted.filter(Boolean)).toHaveLength(5)
    expect(sink.dropped).toBe(15)
    expect(sink.pending).toBe(5)
    expect(w.calls()).toBe(1)
    const flushStarted = Date.now()
    await sink.flush(50)
    expect(Date.now() - flushStarted).toBeLessThan(1000)
  })
})

describe('openAuditSink', () => {
  it('uses stderr when the variable is unset, empty or whitespace only', () => {
    for (const value of [undefined, '', '  \t']) {
      expect(openAuditSink({ [AUDIT_LOG_ENV]: value }).target).toBe('stderr')
    }
  })

  it('creates the file with mode 0600 and appends one line per record', async () => {
    const file = path.join(tmp, 'audit.jsonl')
    const { sink, target } = openAuditSink({ [AUDIT_LOG_ENV]: file })
    expect(target).toBe('file')
    sink.write('{"a":1}\n')
    sink.write('{"a":2}\n')
    await sink.flush(1000)
    expect(fs.readFileSync(file, 'utf8')).toBe('{"a":1}\n{"a":2}\n')
    expect(fs.statSync(file).mode & 0o777).toBe(0o600)
    // Reopening appends.
    const again = openAuditSink({ [AUDIT_LOG_ENV]: file }).sink
    again.write('{"a":3}\n')
    await again.flush(1000)
    expect(fs.readFileSync(file, 'utf8').split('\n')).toHaveLength(4)
  })

  function refused(value) {
    let error
    try { openAuditSink({ [AUDIT_LOG_ENV]: value }) } catch (err) { error = err }
    expect(error).toBeInstanceOf(AuditConfigError)
    expect(error.message).toBe(AUDIT_CONFIG_MESSAGE)
    if (value.length > 1) expect(error.message).not.toContain(value)
  }

  it('refuses a relative path, also one that would resolve to a usable file', () => {
    refused('relative/audit.jsonl')
    refused(path.relative(process.cwd(), path.join(tmp, 'relative.jsonl')))
    expect(fs.existsSync(path.join(tmp, 'relative.jsonl'))).toBe(false)
  })

  it('refuses a file with group or other permissions', () => {
    const file = path.join(tmp, 'wide.jsonl')
    fs.writeFileSync(file, '')
    fs.chmodSync(file, 0o640)
    refused(file)
  })

  it('refuses a file with a second hard link', () => {
    const real = path.join(tmp, 'linked.jsonl')
    fs.writeFileSync(real, '', { mode: 0o600 })
    const other = path.join(tmp, 'linked-again.jsonl')
    fs.linkSync(real, other)
    refused(real)
    refused(other)
  })

  it('refuses a file in a directory others can write to, unless the directory is sticky', () => {
    const open = path.join(tmp, 'open-dir')
    fs.mkdirSync(open)
    fs.chmodSync(open, 0o777)
    refused(path.join(open, 'audit.jsonl'))
    const group = path.join(tmp, 'group-dir')
    fs.mkdirSync(group)
    fs.chmodSync(group, 0o770)
    refused(path.join(group, 'audit.jsonl'))
    const sticky = path.join(tmp, 'sticky-dir')
    fs.mkdirSync(sticky)
    fs.chmodSync(sticky, 0o1777)
    expect(openAuditSink({ [AUDIT_LOG_ENV]: path.join(sticky, 'audit.jsonl') }).target).toBe('file')
  })

  it('refuses a symlink, even to an acceptable file', () => {
    const real = path.join(tmp, 'real.jsonl')
    fs.writeFileSync(real, '', { mode: 0o600 })
    const link = path.join(tmp, 'link.jsonl')
    fs.symlinkSync(real, link)
    refused(link)
  })

  it('refuses a directory, a missing parent and a character device', () => {
    refused(tmp)
    refused(path.join(tmp, 'missing', 'audit.jsonl'))
    refused('/dev/null')
  })

  it('refuses a FIFO without blocking', () => {
    const fifo = path.join(tmp, 'audit.fifo')
    execFileSync('mkfifo', ['-m', '600', fifo])
    // In a child process with a timeout: a blocking open on a FIFO without a
    // reader would otherwise hang the test runner instead of failing.
    const sinkUrl = new URL('../src/audit/sink.js', import.meta.url).href
    const script = `import(${JSON.stringify(sinkUrl)}).then(m => { try { m.openAuditSink({ ${AUDIT_LOG_ENV}: process.argv[1] }); console.log('opened') } catch (e) { console.log(e.name) } })`
    const out = execFileSync(process.execPath, ['--input-type=module', '-e', script, fifo], { timeout: 5000, encoding: 'utf8' })
    expect(out.trim()).toBe('AuditConfigError')
  })
})
