import fs from 'fs'
import { posix } from 'path'

// Where audit records go: stderr (fd 2) by default, or the file named by
// TENSHI_MCP_AUDIT_LOG. Never stdout, which carries the MCP protocol.
//
// Writes never block the event loop and never hold up a tool call: records
// are queued (at most MAX_PENDING_RECORDS, each at most 2048 bytes, so at
// most 8 MiB) and written with asynchronous fs.write, which runs the syscall
// off the event loop. One write at a time carries as many whole queued
// records as fit in the batch size (64 KiB for a regular file; PIPE_BATCH_BYTES
// for a pipe or anything else, so a batch stays within the Linux PIPE_BUF and
// is not interleaved with other writers). A record that cannot be queued or
// written is dropped and counted (`dropped`, shown in the next record as
// auditDropped), and the tool call goes on: the tools are read-only, so
// availability is kept rather than refusing reads because a log sink is full
// or broken. A write that never completes (a reader that stops draining a
// pipe) stalls only the queue; later records are dropped and counted once it
// is full. Write errors are never printed.

export const AUDIT_LOG_ENV = 'TENSHI_MCP_AUDIT_LOG'
export const MAX_PENDING_RECORDS = 4096
/** Largest single write to a regular file. */
export const FILE_BATCH_BYTES = 64 * 1024
/** Largest single write to a pipe, terminal or other non-file fd (Linux PIPE_BUF). */
export const PIPE_BATCH_BYTES = 4096
/** Delay before retrying a write that the fd refused with EAGAIN. */
export const RETRY_MS = 20

export const AUDIT_CONFIG_MESSAGE =
  `${AUDIT_LOG_ENV} must be an absolute path to a regular file (not a symlink, one link) owned by this user with no group or other permissions, in a directory other users cannot write to; the server will not start.`

export class AuditConfigError extends Error {
  constructor() {
    super(AUDIT_CONFIG_MESSAGE)
    this.name = 'AuditConfigError'
  }
}

/**
 * A bounded, non-blocking line sink on an open file descriptor.
 * @param {number} fd
 * @param {{ write?: typeof fs.write, maxPending?: number, batchBytes?: number }} [options]
 *   `write` is a test hook; `batchBytes` caps one write (whole records only,
 *   at least one record)
 */
export function createFdSink(fd, { write = fs.write, maxPending = MAX_PENDING_RECORDS, batchBytes = PIPE_BATCH_BYTES } = {}) {
  /** @type {Buffer[]} */
  const queue = []
  const waiters = []
  let busy = false
  let dropped = 0

  function settle() {
    if (busy || queue.length > 0) return
    while (waiters.length > 0) waiters.shift()()
  }

  /** Remove `n` written bytes from the front of the queue. */
  function consume(n) {
    while (n > 0 && queue.length > 0) {
      if (n >= queue[0].length) {
        n -= queue[0].length
        queue.shift()
      } else {
        queue[0] = queue[0].subarray(n)
        n = 0
      }
    }
  }

  function pump() {
    if (busy) return
    if (queue.length === 0) return settle()
    busy = true
    let count = 1
    let size = queue[0].length
    while (count < queue.length && size + queue[count].length <= batchBytes) size += queue[count++].length
    const buf = count === 1 ? queue[0] : Buffer.concat(queue.slice(0, count), size)
    let called = false
    const done = (err, written) => {
      if (called) return
      called = true
      if (err && (err.code === 'EAGAIN' || err.code === 'EWOULDBLOCK')) {
        // The fd is non-blocking and full: try the same records again later.
        setTimeout(() => { busy = false; pump() }, RETRY_MS).unref()
        return
      }
      busy = false
      if (err || !Number.isInteger(written) || written <= 0) {
        queue.splice(0, count)
        dropped += count
      } else {
        consume(Math.min(written, size))
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
 * owned by this user with no group or other permission bits and a link
 * count of 1, in a directory owned by this user or root that is not group
 * or other writable unless it has the sticky bit (only the immediate parent
 * is checked; symlinks in parent directories are followed). Anything else
 * throws AuditConfigError, whose fixed message names the variable, never the
 * value: an audit log that was asked for but cannot be used stops the server
 * instead of running unaudited.
 *
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {{ sink: ReturnType<typeof createFdSink>, target: 'stderr' | 'file' }}
 */
export function openAuditSink(env = process.env) {
  const raw = env[AUDIT_LOG_ENV]
  if (raw === undefined || raw.trim() === '') return { sink: createFdSink(2, { batchBytes: batchBytesFor(2) }), target: 'stderr' }
  if (!posix.isAbsolute(raw) || raw.includes('\0')) throw new AuditConfigError()
  const { O_WRONLY, O_APPEND, O_CREAT, O_NOFOLLOW, O_NONBLOCK } = fs.constants
  let fd
  try {
    fd = fs.openSync(raw, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_NONBLOCK, 0o600)
    const stats = fs.fstatSync(fd)
    const uid = typeof process.getuid === 'function' ? process.getuid() : null
    const ownerOk = uid === null || stats.uid === uid
    // A second name (a hard link) would let whoever placed it point the log
    // at another file of this user.
    if (!stats.isFile() || (stats.mode & 0o077) !== 0 || !ownerOk || stats.nlink !== 1) throw new AuditConfigError()
    // The directory must not let other users replace or add the name: owned
    // by this user or root, and not group or other writable unless sticky.
    const dir = fs.statSync(posix.dirname(raw))
    const dirOwnerOk = uid === null || dir.uid === uid || dir.uid === 0
    const sticky = (dir.mode & 0o1000) !== 0
    if (!dir.isDirectory() || !dirOwnerOk || ((dir.mode & 0o022) !== 0 && !sticky)) throw new AuditConfigError()
  } catch {
    if (fd !== undefined) {
      try { fs.closeSync(fd) } catch { /* already closed */ }
    }
    throw new AuditConfigError()
  }
  return { sink: createFdSink(fd, { batchBytes: FILE_BATCH_BYTES }), target: 'file' }
}

/** Batch size for an fd: FILE_BATCH_BYTES for a regular file, else PIPE_BATCH_BYTES. */
function batchBytesFor(fd) {
  try {
    return fs.fstatSync(fd).isFile() ? FILE_BATCH_BYTES : PIPE_BATCH_BYTES
  } catch {
    return PIPE_BATCH_BYTES
  }
}
