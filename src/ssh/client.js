import { NodeSSH } from 'node-ssh'
import { homedir } from 'os'
import { getServerConfig } from '../config/servers.js'
import { ERROR_CODES, ToolError } from '../errors.js'
import { createHostVerifier } from './host-key.js'

// Connection pool keyed by server id. The NodeSSH object never leaves this
// module: the only export that touches it is openSftpChannel, which hands a
// bare SFTP channel to src/ssh/sftp.js. Nothing here opens an exec or shell
// channel.

/**
 * @typedef {{ ready: Promise<NodeSSH>, ssh: NodeSSH | null, timer: ReturnType<typeof setTimeout> | null }} PoolEntry
 * @type {Map<string, PoolEntry>}
 */
const pool = new Map()

export const IDLE_MS = 5 * 60 * 1000
const READY_TIMEOUT_MS = 10000

function expandHome(p) {
  return p.startsWith('~') ? p.replace('~', homedir()) : p
}

/**
 * ssh2's `hostVerifier` for a registered server: accepts the host key only
 * when its SHA-256 digest matches one of the server's `hostKeys` pins. It
 * always returns a function, never undefined, because ssh2 accepts any host
 * key when no verifier is set. A server without valid pins gets a verifier
 * that rejects every key (fail closed). Used with `hostHash: 'sha256'`; ssh2
 * calls it during key exchange, before any authentication is sent.
 *
 * @param {ReturnType<typeof getServerConfig>} server
 * @param {() => void} [onReject] called on each rejection, with no details
 * @returns {(hash: unknown) => boolean}
 */
export function hostVerifierFor(server, onReject) {
  return createHostVerifier(server?.hostKeys, onReject)
}

function drop(serverId, entry) {
  if (pool.get(serverId) === entry) pool.delete(serverId)
  clearTimeout(entry.timer)
  entry.ssh?.dispose()
}

function scheduleIdle(serverId, entry) {
  clearTimeout(entry.timer)
  entry.timer = setTimeout(() => drop(serverId, entry), IDLE_MS)
}

/**
 * Open and authenticate a new connection. Every call verifies the host key
 * afresh, so a reconnect after the pool dropped a connection is checked
 * like the first connection. A host key that matches no pin fails with the
 * fixed E_HOST_KEY error, which carries no fingerprint, host or path; the
 * mismatch is not logged (no log line may carry server details until the
 * audit log exists).
 */
async function connect(server) {
  const ssh = new NodeSSH()
  let hostKeyRejected = false
  const hostVerifier = hostVerifierFor(server, () => { hostKeyRejected = true })
  try {
    await ssh.connect({
      host: server.host,
      port: server.port,
      username: server.user,
      privateKeyPath: expandHome(server.privateKeyPath),
      readyTimeout: READY_TIMEOUT_MS,
      hostHash: 'sha256',
      hostVerifier
    })
  } catch (err) {
    ssh.dispose()
    if (hostKeyRejected) throw new ToolError(ERROR_CODES.HOST_KEY)
    throw err
  }
  if (hostKeyRejected) {
    // ssh2 disconnects on a rejected key; never use a connection that got here.
    ssh.dispose()
    throw new ToolError(ERROR_CODES.HOST_KEY)
  }
  return ssh
}

/**
 * Pooled connection for a registered server. Throws before any network
 * activity when the id is not in the registry. Concurrent callers share one
 * connection attempt.
 * @returns {Promise<NodeSSH>}
 */
async function acquire(serverId) {
  const server = getServerConfig(serverId)

  let entry = pool.get(serverId)
  if (entry?.ssh && !entry.ssh.isConnected()) {
    drop(serverId, entry)
    entry = undefined
  }
  if (!entry) {
    /** @type {PoolEntry} */
    const created = { ready: null, ssh: null, timer: null }
    created.ready = connect(server).then(
      ssh => {
        if (pool.get(serverId) !== created) {
          // Dropped (closeAll or an error) while the handshake was running.
          ssh.dispose()
          throw new Error('connection discarded')
        }
        created.ssh = ssh
        // After the handshake node-ssh no longer listens for 'error'; without
        // a listener a later socket error would be thrown by the emitter.
        ssh.connection?.on('error', () => drop(serverId, created))
        return ssh
      },
      err => {
        if (pool.get(serverId) === created) pool.delete(serverId)
        throw err
      }
    )
    pool.set(serverId, created)
    entry = created
  }

  const ssh = await entry.ready
  if (pool.get(serverId) === entry) scheduleIdle(serverId, entry)
  return ssh
}

/**
 * Open a new SFTP channel on the pooled connection for `serverId`. Only
 * src/ssh/sftp.js calls this; it wraps the channel in a read-only facade and
 * closes it when the call ends or times out. An id that is not in the
 * registry fails with E_NOT_AVAILABLE before any network activity.
 * @returns {Promise<import('ssh2').SFTPWrapper>}
 */
export async function openSftpChannel(serverId) {
  try {
    getServerConfig(serverId)
  } catch (err) {
    throw new ToolError(ERROR_CODES.NOT_AVAILABLE, { cause: err })
  }
  const ssh = await acquire(serverId)
  return ssh.requestSFTP()
}

export function closeAll() {
  for (const [id, entry] of pool) drop(id, entry)
}
