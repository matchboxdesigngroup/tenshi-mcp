import { openSftpChannel } from './client.js'
import { ERROR_CODES, ToolError } from '../errors.js'

// Read-only SFTP layer. Tools get a session facade with exactly the
// operations they need (realpath, lstat, open for reading, fstat, bounded
// read, close). The facade never exposes the SSH connection, the raw SFTP
// channel, or any exec, shell or write path.

/** Per-call budget, from acquiring the channel to the last read. */
export const CALL_TIMEOUT_MS = 10000
/** Largest single SFTP read request. */
export const READ_CHUNK_BYTES = 32 * 1024
/** Backstop on the total bytes one call may read, whatever the tool asks. */
export const SESSION_READ_BUDGET_BYTES = 320 * 1024

// SFTP status codes (draft-ietf-secsh-filexfer-02) as reported by ssh2.
const SFTP_EOF = 1

function isSftpStatus(err) {
  return Number.isInteger(err?.code) && err.code > 0
}

/**
 * Path operations: any SFTP status (no such file, permission denied, failure)
 * is reported as not available, so outside-root, missing and forbidden look
 * the same. Anything else (channel lost, protocol error) is a remote error.
 */
function pathError(err) {
  if (err instanceof ToolError) return err
  return new ToolError(isSftpStatus(err) ? ERROR_CODES.NOT_AVAILABLE : ERROR_CODES.REMOTE, { cause: err })
}

function handleError(err) {
  if (err instanceof ToolError) return err
  return new ToolError(ERROR_CODES.REMOTE, { cause: err })
}

function callback(fn) {
  return new Promise((resolve, reject) => {
    fn((err, value) => (err ? reject(err) : resolve(value)))
  })
}

function createDeadline(ms) {
  let timer = null
  let expired = false
  const expiry = new Promise((_, reject) => {
    timer = setTimeout(() => {
      expired = true
      reject(new ToolError(ERROR_CODES.TIMEOUT))
    }, ms)
  })
  // Observed through race(); this keeps an unraced expiry from being reported
  // as an unhandled rejection.
  expiry.catch(() => {})
  return {
    get expired() { return expired },
    race: promise => Promise.race([promise, expiry]),
    clear: () => clearTimeout(timer)
  }
}

function createSession(channel, deadline, limits) {
  let closed = false
  let bytesRead = 0

  async function op(run, mapError) {
    if (closed) throw new ToolError(deadline.expired ? ERROR_CODES.TIMEOUT : ERROR_CODES.REMOTE)
    try {
      return await deadline.race(callback(run))
    } catch (err) {
      throw mapError(err)
    }
  }

  function wrapHandle(handle) {
    let handleClosed = false
    return Object.freeze({
      /** @returns {Promise<import('ssh2').Stats>} */
      fstat: () => op(cb => channel.fstat(handle, cb), handleError),

      /**
       * Read up to `length` bytes from `position`. Stops early at end of
       * file. Each request asks for at most READ_CHUNK_BYTES, and the session
       * budget caps the total across the call.
       * @returns {Promise<Buffer>}
       */
      async read(position, length) {
        if (!Number.isSafeInteger(position) || position < 0) throw new ToolError(ERROR_CODES.INTERNAL)
        if (!Number.isSafeInteger(length) || length < 0) throw new ToolError(ERROR_CODES.INTERNAL)
        if (bytesRead + length > limits.readBudgetBytes) throw new ToolError(ERROR_CODES.INTERNAL)
        const out = Buffer.alloc(length)
        let filled = 0
        while (filled < length) {
          const want = Math.min(READ_CHUNK_BYTES, length - filled)
          const got = await op(cb => channel.read(handle, out, filled, want, position + filled, (err, n) => {
            if (err && err.code === SFTP_EOF) return cb(null, 0)
            cb(err, n)
          }), handleError)
          if (!Number.isInteger(got) || got <= 0) break
          if (got > want) throw new ToolError(ERROR_CODES.REMOTE)
          filled += got
          bytesRead += got
        }
        return out.subarray(0, filled)
      },

      async close() {
        if (handleClosed) return
        handleClosed = true
        await op(cb => channel.close(handle, cb), handleError)
      }
    })
  }

  const session = Object.freeze({
    /** @returns {Promise<string>} canonical absolute path */
    realpath: path => op(cb => channel.realpath(path, cb), pathError),
    /** @returns {Promise<import('ssh2').Stats>} attributes of the link itself */
    lstat: path => op(cb => channel.lstat(path, cb), pathError),
    /** Open a file read-only. Resolves to a handle facade. */
    openRead: async path => wrapHandle(await op(cb => channel.open(path, 'r', cb), pathError))
  })

  return {
    session,
    close() {
      if (closed) return
      closed = true
      // Closing the channel ends the remote SFTP server process for this
      // session; there is no remote command to signal. Pending requests are
      // abandoned and rejected by the deadline or by ssh2.
      try { channel.end() } catch { /* channel already gone */ }
    }
  }
}

/**
 * Run `work(session)` against a fresh SFTP channel on `serverId` within one
 * deadline. The channel is closed when work finishes, fails or times out; on
 * timeout the caller gets E_TIMEOUT and any later facade call fails at once.
 *
 * @template T
 * @param {string} serverId registry id
 * @param {(session: ReadOnlySftpSession) => Promise<T>} work
 * @param {{ timeoutMs?: number, readBudgetBytes?: number }} [options]
 * @returns {Promise<T>}
 *
 * @typedef {{
 *   realpath(path: string): Promise<string>,
 *   lstat(path: string): Promise<import('ssh2').Stats>,
 *   openRead(path: string): Promise<ReadOnlyHandle>
 * }} ReadOnlySftpSession
 * @typedef {{
 *   fstat(): Promise<import('ssh2').Stats>,
 *   read(position: number, length: number): Promise<Buffer>,
 *   close(): Promise<void>
 * }} ReadOnlyHandle
 */
export async function withSftpSession(serverId, work, options = {}) {
  const timeoutMs = options.timeoutMs ?? CALL_TIMEOUT_MS
  const limits = { readBudgetBytes: options.readBudgetBytes ?? SESSION_READ_BUDGET_BYTES }
  const deadline = createDeadline(timeoutMs)

  try {
    const opening = Promise.resolve().then(() => openSftpChannel(serverId))
    let channel
    try {
      channel = await deadline.race(opening)
    } catch (err) {
      // Timed out while connecting or opening the channel: close the channel
      // if it still arrives.
      opening.then(ch => { try { ch.end() } catch { /* already gone */ } }, () => {})
      throw err
    }

    const { session, close } = createSession(channel, deadline, limits)
    try {
      const running = Promise.resolve().then(() => work(session))
      // The deadline may win the race; the abandoned work promise must not
      // surface later as an unhandled rejection.
      running.catch(() => {})
      return await deadline.race(running)
    } finally {
      close()
    }
  } catch (err) {
    if (err instanceof ToolError) throw err
    throw new ToolError(ERROR_CODES.REMOTE, { cause: err })
  } finally {
    deadline.clear()
  }
}
