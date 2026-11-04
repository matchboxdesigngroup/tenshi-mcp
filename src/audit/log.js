import { createHmac, randomBytes } from 'crypto'
import { ERROR_CODES } from '../errors.js'

// Structured audit log: exactly one JSON record per `tools/call` request the
// server answers, including refusals, calls the SDK's dispatcher rejects
// before a handler runs (unknown tool, invalid arguments) and requests the
// SDK rejects before the dispatcher (no or non-string name, non-object
// arguments, task creation). Two hooks: wrapTransport sees every request
// and response; wrapCallHandler sees every call that reaches the
// dispatcher, where tool callbacks add counts through report(). The record field
// list in README.md ("Audit log") is the contract for consumers; bump
// AUDIT_VERSION when a field changes meaning or is removed.
//
// What a record never contains: file or log content, caller strings (paths,
// filters, unknown site names, unknown tool names: only their length and a
// keyed hash), credentials, host names, users, key paths, host-key pins or
// fingerprints, remote error text. Every value is either a fixed token from
// this module, a registry id, a number, a boolean, a job id matching
// JOB_ID_PATTERN, or a keyed hash.

export const AUDIT_EVENT = 'tenshi-mcp.tool_call'
export const AUDIT_VERSION = 1
/** Key in the request `_meta` that carries the caller's job id. */
export const JOB_ID_META_KEY = 'tenshi/jobId'
/** Job ids that are recorded; anything else is recorded as invalid. */
export const JOB_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/
/**
 * Upper bound on one serialized record including its newline. Below the
 * 4096-byte PIPE_BUF on Linux, so a record written to a pipe in one write is
 * never interleaved with other writers.
 */
export const MAX_RECORD_BYTES = 2048
export const HASH_HEX_CHARS = 16
/**
 * Most tools/call requests waiting for an answer that are tracked at once.
 * A request over the bound evicts the oldest; that one is never recorded and
 * is counted in auditDropped.
 */
export const MAX_PENDING_CALLS = 4096

/**
 * Extension classes recorded for a path argument. Any other extension is
 * `other` (an extension can be part of a name, so it is never recorded as
 * typed), and a last segment without one is `none`.
 */
export const EXTENSION_CLASSES = Object.freeze([
  'php', 'js', 'css', 'txt', 'md', 'html', 'htm', 'json', 'xml', 'log', 'ini', 'yml', 'yaml',
  'po', 'pot', 'mo', 'csv', 'svg', 'png', 'jpg', 'jpeg', 'gif', 'webp', 'ico',
  'sql', 'env', 'conf', 'bak', 'old', 'zip', 'gz', 'tar', 'pem', 'key'
])

// Reasons whose outcome is not `refused`. Every other reason (the policy,
// confinement, registry, input and host-key refusals) is `refused`.
const NOT_AVAILABLE_REASONS = new Set(['not_found', 'permission_denied', 'remote_status'])
const ERROR_REASONS = new Set(['timeout', 'remote', 'internal'])

const DEFAULT_REASON_BY_CODE = Object.freeze({
  [ERROR_CODES.INVALID_INPUT]: 'invalid_input',
  [ERROR_CODES.NOT_AVAILABLE]: 'unspecified',
  [ERROR_CODES.HOST_KEY]: 'host_key',
  [ERROR_CODES.TIMEOUT]: 'timeout',
  [ERROR_CODES.REMOTE]: 'remote',
  [ERROR_CODES.INTERNAL]: 'internal'
})

/** @param {string} reason */
export function outcomeOf(reason) {
  if (NOT_AVAILABLE_REASONS.has(reason)) return 'not_available'
  if (ERROR_REASONS.has(reason)) return 'error'
  return 'refused'
}

/**
 * Extension class of the last path segment (see EXTENSION_CLASSES).
 * @param {string} path
 */
export function extensionClass(path) {
  const last = path.slice(path.lastIndexOf('/') + 1)
  const dot = last.lastIndexOf('.')
  if (dot <= 0 || dot === last.length - 1) return 'none'
  const ext = last.slice(dot + 1).toLowerCase()
  return EXTENSION_CLASSES.includes(ext) ? ext : 'other'
}

/**
 * One JSON line for `record`: every character outside printable ASCII is
 * written as a \u escape (JSON.stringify already escapes C0 controls, quotes
 * and backslashes; this also covers DEL, C1 controls such as CSI, bidi and
 * zero-width characters and U+2028/U+2029), so a line holds no terminal
 * control sequence and no line break. A line over MAX_RECORD_BYTES is
 * replaced by a record of the fixed fields only, marked `oversize`.
 * @param {Record<string, unknown>} record
 * @returns {string} the line, ending in "\n"
 */
export function serializeRecord(record) {
  const line = escapeJson(record)
  if (line.length + 1 <= MAX_RECORD_BYTES) return line + '\n'
  const { event, v, ts, seq, instance, outcome, code, reason, durationMs, auditDropped } = record
  return escapeJson({ event, v, ts, seq, instance, outcome, code, reason, durationMs, auditDropped, oversize: true }) + '\n'
}

function escapeJson(value) {
  // The output is ASCII only, so its length is its UTF-8 byte length.
  return JSON.stringify(value).replace(/[^\x20-\x7e]/g, c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'))
}

function safeCount(n) {
  return Number.isSafeInteger(n) && n >= 0 ? n : null
}

function typeName(value) {
  if (value === null) return 'null'
  return Array.isArray(value) ? 'array' : typeof value
}

/**
 * The audit log. `tools` maps each registered tool name to its argument
 * kinds: 'text' (length and hash), 'path' (length, hash, segment count,
 * extension class), 'number' (the value), or an array of allowed values
 * (recorded as given when it is one of them, else like text).
 *
 * @param {{
 *   sink: { write(line: string): boolean, readonly dropped: number },
 *   tools: Record<string, Record<string, 'text' | 'path' | 'number' | readonly string[]>>,
 *   resolveSite: (name: string) => { site: string, server: string } | null,
 *   now?: () => number,
 *   clock?: () => bigint,
 *   hashKey?: Buffer,
 *   instance?: string
 * }} options
 */
export function createAuditLog({ sink, tools, resolveSite, now = Date.now, clock = process.hrtime.bigint, hashKey, instance }) {
  // Hashes are keyed with a per-process secret that is never written out, so
  // a recorded hash cannot be reversed by guessing common paths or
  // addresses; hashes are comparable only between records of one `instance`.
  const key = hashKey ?? randomBytes(32)
  const instanceId = instance ?? randomBytes(8).toString('hex')
  const contexts = new WeakMap()
  /** tools/call requests seen on the transport and not yet answered, by JSON-RPC id. */
  const pending = new Map()
  let seq = 0
  let failures = 0
  let installed = false

  const hash = value => createHmac('sha256', key).update(value, 'utf8').digest('hex').slice(0, HASH_HEX_CHARS)

  function describeString(value, kind) {
    const shape = { type: 'string', length: value.length, hash: hash(value) }
    if (kind === 'path') {
      shape.segments = value.split('/').length
      shape.ext = extensionClass(value)
    }
    return shape
  }

  function describeArg(kind, value) {
    if (Array.isArray(kind) && kind.includes(value)) return { value }
    if (typeof value === 'number') return { type: 'number', value: Number.isFinite(value) ? value : null }
    if (typeof value === 'string') return describeString(value, kind)
    return { type: typeName(value) }
  }

  function describeRequest(spec, args) {
    if (args === undefined) return { arguments: 'absent' }
    if (typeName(args) !== 'object') return { arguments: typeName(args) }
    const shape = {}
    let otherKeys = 0
    for (const name of Object.keys(args)) {
      if (spec && Object.hasOwn(spec, name)) shape[name] = describeArg(spec[name], args[name])
      else otherKeys++
    }
    shape.otherKeys = otherKeys
    return shape
  }

  function jobIdOf(meta) {
    if (typeName(meta) !== 'object' || !Object.hasOwn(meta, JOB_ID_META_KEY)) return { jobId: null, jobIdInvalid: false }
    const raw = meta[JOB_ID_META_KEY]
    const valid = typeof raw === 'string' && JOB_ID_PATTERN.test(raw)
    return { jobId: valid ? raw : null, jobIdInvalid: !valid }
  }

  function buildRecord({ request, ctx, result, thrown, rejected, ts, durationMs }) {
    const params = typeName(request?.params) === 'object' ? request.params : {}
    const tool = typeof params.name === 'string' && Object.hasOwn(tools, params.name) ? params.name : null
    const args = params.arguments
    const located = tool && typeName(args) === 'object' && typeof args.site === 'string' ? resolveSite(args.site) : null

    let code = null
    let reason = null
    if (thrown !== undefined) {
      code = ERROR_CODES.INTERNAL
      reason = 'internal'
    } else if (rejected) {
      // Answered by the SDK before the dispatcher: no tool code ran.
      code = rejected.error ? ERROR_CODES.INVALID_INPUT : ERROR_CODES.INTERNAL
      reason = rejected.error ? 'invalid_input' : 'internal'
    } else if (ctx.error) {
      code = ctx.error.code
      reason = ctx.error.reason ?? DEFAULT_REASON_BY_CODE[code] ?? 'internal'
    } else if (ctx.reported) {
      // A handler that reported success.
    } else if (result?.isError === true) {
      // The SDK answered before any tool code ran.
      code = ERROR_CODES.INVALID_INPUT
      reason = tool ? 'invalid_input' : 'unknown_tool'
    } else {
      // A result no tool reported: never expected, recorded as a failure.
      code = ERROR_CODES.INTERNAL
      reason = 'internal'
    }
    const ok = code === null

    let bytesReturned = rejected ? rejected.bytes : 0
    for (const item of Array.isArray(result?.content) ? result.content : []) {
      if (item?.type === 'text' && typeof item.text === 'string') bytesReturned += Buffer.byteLength(item.text, 'utf8')
    }

    seq++
    return {
      event: AUDIT_EVENT,
      v: AUDIT_VERSION,
      ts: new Date(ts).toISOString(),
      seq,
      instance: instanceId,
      ...jobIdOf(params._meta),
      tool,
      toolName: tool ? undefined : describeArg('text', params.name),
      site: located?.site ?? null,
      server: located?.server ?? null,
      request: tool ? describeRequest(tools[tool], args) : { otherKeys: typeName(args) === 'object' ? Object.keys(args).length : 0 },
      outcome: ok ? 'ok' : outcomeOf(reason),
      code,
      reason,
      durationMs,
      bytesReturned,
      redactedLines: ok ? safeCount(ctx.info?.redactedLines) : null,
      truncated: ok && typeof ctx.info?.truncated === 'boolean' ? ctx.info.truncated : null,
      returnedLines: ok ? safeCount(ctx.info?.returnedLines) : null,
      auditDropped: sink.dropped + failures
    }
  }

  function emit(details) {
    try {
      if (!sink.write(serializeRecord(buildRecord(details)))) return
    } catch {
      // Never let the audit log break a tool call; the loss is counted and
      // shows in the next record's auditDropped (and as a gap in seq).
      failures++
    }
  }

  return {
    get instance() { return instanceId },
    /** True once a tools/call handler was wrapped (see src/server.js). */
    get installed() { return installed },

    /**
     * Wrap the SDK's `tools/call` handler so that every request it answers
     * produces one record, whatever the outcome. The wrapper never changes
     * the result or the error.
     * @template {(request: any, extra: any) => Promise<any>} H
     * @param {H} handler
     * @returns {H}
     */
    wrapCallHandler(handler) {
      installed = true
      return /** @type {H} */ (async (request, extra) => {
        // The transport hook saw the request first: take its arrival time.
        // The entry is removed below, before the answer is sent, so the
        // transport hook does not record this request a second time.
        const key = callKey({ id: extra?.requestId })
        const entry = key === null ? undefined : pending.get(key)
        const ts = entry ? entry.ts : now()
        const started = entry ? entry.started : clock()
        const ctx = { reported: false, error: null, info: null }
        if (extra !== null && typeof extra === 'object') contexts.set(extra, ctx)
        let result
        let thrown
        try {
          result = await handler(request, extra)
          return result
        } catch (err) {
          thrown = err ?? null
          throw err
        } finally {
          const durationMs = Math.max(0, Math.round(Number(clock() - started) / 1e6))
              if (entry && pending.get(key) === entry) pending.delete(key)
          emit({ request, ctx, result, thrown, ts, durationMs })
        }
      })
    },

    /**
     * Wrap an MCP transport so that a tools/call request the SDK answers
     * without running the dispatcher (it fails the SDK's request schema, or
     * asks for task creation) is recorded when its answer is sent. Messages
     * pass through unchanged; an audit failure never affects them.
     * @param {import('@modelcontextprotocol/sdk/shared/transport.js').Transport} transport
     */
    wrapTransport(transport) {
      return new AuditedTransport(transport, {
        received(message) {
          const key = callKey(message)
          if (key === null || typeName(message.method) !== 'string' || message.method !== 'tools/call') return
          if (pending.size >= MAX_PENDING_CALLS) {
            pending.delete(pending.keys().next().value)
            failures++
          }
          pending.set(key, { ts: now(), started: clock(), request: message })
        },
        sending(message) {
          if (message === null || typeof message !== 'object' || 'method' in message) return
          const key = callKey(message)
          const entry = key === null ? undefined : pending.get(key)
          if (!entry) return
          pending.delete(key)
          const error = typeName(message.error) === 'object'
          const bytes = error ? Buffer.byteLength(String(message.error.message ?? ''), 'utf8') : 0
          const durationMs = Math.max(0, Math.round(Number(clock() - entry.started) / 1e6))
          emit({ request: entry.request, ctx: { reported: false, error: null, info: null }, rejected: { error, bytes }, ts: entry.ts, durationMs })
        }
      })
    },

    /**
     * Called by a tool callback with what it is about to return: either
     * `{ error }` (a ToolError) or counts from the result. Never content.
     * @param {unknown} extra the SDK request extra passed to the callback
     * @param {{ error?: import('../errors.js').ToolError, redactedLines?: number, truncated?: boolean, returnedLines?: number }} info
     */
    report(extra, info) {
      const ctx = extra !== null && typeof extra === 'object' ? contexts.get(extra) : undefined
      if (!ctx) return
      ctx.reported = true
      if (info?.error) ctx.error = info.error
      else ctx.info = info
    }
  }
}

/** Map key for a JSON-RPC id (string or number), or null without one. */
function callKey(message) {
  const id = message?.id
  if (typeof id === 'string') return `s:${id}`
  if (typeof id === 'number') return `n:${id}`
  return null
}

/**
 * A transport that passes every message through and lets the audit log see
 * incoming requests and outgoing responses. Hook failures are swallowed.
 */
class AuditedTransport {
  constructor(inner, hooks) {
    this._inner = inner
    this._hooks = hooks
    /** @type {((message: any, extra?: any) => void) | undefined} */
    this.onmessage = undefined
    /** @type {(() => void) | undefined} */
    this.onclose = undefined
    /** @type {((error: Error) => void) | undefined} */
    this.onerror = undefined
    inner.onmessage = (message, extra) => {
      try { hooks.received(message) } catch { /* never block a message */ }
      this.onmessage?.(message, extra)
    }
    inner.onclose = () => this.onclose?.()
    inner.onerror = error => this.onerror?.(error)
  }

  get sessionId() { return this._inner.sessionId }

  start() { return this._inner.start() }

  close() { return this._inner.close() }

  send(message, options) {
    try { this._hooks.sending(message) } catch { /* never block a message */ }
    return this._inner.send(message, options)
  }

  setProtocolVersion(version) { this._inner.setProtocolVersion?.(version) }
}
