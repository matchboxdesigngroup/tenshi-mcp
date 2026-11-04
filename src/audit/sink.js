import fs from 'fs'
import { posix } from 'path'

// Where audit records go: stderr (fd 2) by default, or the file named by
// TENSHI_MCP_AUDIT_LOG. Never stdout, which carries the MCP protocol.
//
// Writes never block the event loop and never hold up a tool call: records
// are queued (at most MAX_PENDING_RECORDS) and written one at a time with
// asynchronous fs.write, which runs the syscall off the event loop. A record
// that cannot be queued or written is dropped and counted (`dropped`, shown
// in the next record as auditDropped), and the tool call goes on: the tools
// are read-only, so availability is kept rather than refusing reads because
// a log sink is full or broken. A write that never completes (a reader that
// stops draining a pipe) stalls only the queue; later records are dropped
// and counted once it is full. Write errors are never printed.

export const AUDIT_LOG_ENV = 'TENSHI_MCP_AUDIT_LOG'
export const MAX_PENDING_RECORDS = 1024
/** Delay before retrying a write that the fd refused with EAGAIN. */
export const RETRY_MS = 20

export const AUDIT_CONFIG_MESSAGE =
  `${AUDIT_LOG_ENV} must be an absolute path to a regular file (not a symlink) owned by this user with no group or other permissions; the server will not start.`

export class AuditConfigError extends Error {
  constructor() {
    super(AUDIT_CONFIG_MESSAGE)
    this.name = 'AuditConfigError'
  }
}

/**
 * A bounded, non-blocking line sink on an open file descriptor.
 * @param {number} fd
 * @param {{ write?: typeof fs.write, maxPending?: number }} [options] `write` is a test hook
 */
export function createFdSink(fd, { write = fs.write, maxPending = MAX_PENDING_RECORDS } = {}) {
  /** @type {Buffer[]} */
  const queue = []
  const waiters = []
  let busy = false
  let dropped = 0

  function settle() {
    if (busy || queue.length > 0) return
    while (waiters.length > 0) waiters.shift()()
  }

  function pump() {
    if (busy) return
    if (queue.length === 0) return settle()
    busy = true
    const buf = queue[0]
    let called = false
    const done = (err, written) => {
      if (called) return
      called = true
      if (err && (err.code === 'EAGAIN' || err.code === 'EWOULDBLOCK')) {
        // The fd is non-blocking and full: try the same record again later.
        setTimeout(() => { busy = false; pump() }, RETRY_MS).unref()
        return
      }
      busy = false
      if (err || !Number.isInteger(written) || written <= 0) {
        queue.shift()
        dropped++
      } else if (written < buf.length) {
        queue[0] = buf.subarray(written)
      } else {
        queue.shift()
      }
      pump()
    }
    try {
      write(fd, buf, 0, buf.length, null, done)
    } catch (err) {
      done(err ?? new Error('write failed'))
    }
  }

  return {
    /**
     * Queue one line. Returns false when it was dropped (queue full).
     * @param {string} line
     */
    write(line) {
      if (queue.length >= maxPending) {
        dropped++
        return false
      }
      queue.push(Buffer.from(line, 'utf8'))
      pump()
      return true
    },
    /** Records lost so far (queue full or write failed). */
    get dropped() { return dropped },
    get pending() { return queue.length },
    /**
     * Resolves when the queue is empty or after `timeoutMs`, whichever is
     * first. Used before exit.
     * @param {number} timeoutMs
     */
    flush(timeoutMs) {
      return new Promise(resolve => {
        if (!busy && queue.length === 0) return resolve()
        const timer = setTimeout(resolve, timeoutMs)
        timer.unref()
        waiters.push(() => { clearTimeout(timer); resolve() })
      })
    }
  }
}

/**
 * The sink chosen by the environment. Unset, empty or whitespace only: stderr.
 * Otherwise the value is used as given (never trimmed) and must be an
 * absolute path; the file is opened for appending without following a
 * symlink in the last component (O_NOFOLLOW) and without blocking on a FIFO
 * (O_NONBLOCK), created with mode 0600, and must then be a regular file
 * owned by this user with no group or other permission bits. Anything else
 * throws AuditConfigError, whose fixed message names the variable, never the
 * value: an audit log that was asked for but cannot be used stops the server
 * instead of running unaudited.
 *
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {{ sink: ReturnType<typeof createFdSink>, target: 'stderr' | 'file' }}
 */
export function openAuditSink(env = process.env) {
  const raw = env[AUDIT_LOG_ENV]
  if (raw === undefined || raw.trim() === '') return { sink: createFdSink(2), target: 'stderr' }
  if (!posix.isAbsolute(raw) || raw.includes('\0')) throw new AuditConfigError()
  const { O_WRONLY, O_APPEND, O_CREAT, O_NOFOLLOW, O_NONBLOCK } = fs.constants
  let fd
  try {
    fd = fs.openSync(raw, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_NONBLOCK, 0o600)
    const stats = fs.fstatSync(fd)
    const ownerOk = typeof process.getuid !== 'function' || stats.uid === process.getuid()
    if (!stats.isFile() || (stats.mode & 0o077) !== 0 || !ownerOk) throw new AuditConfigError()
  } catch {
    if (fd !== undefined) {
      try { fs.closeSync(fd) } catch { /* already closed */ }
    }
    throw new AuditConfigError()
  }
  return { sink: createFdSink(fd), target: 'file' }
}
