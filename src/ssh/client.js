import { NodeSSH } from 'node-ssh'
import { homedir } from 'os'
import { getServerConfig } from '../config/servers.js'
import { ERROR_CODES, ToolError } from '../errors.js'

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
 * Host-key verification seam. Returns the value for ssh2's `hostVerifier`
 * connect option, or undefined. Host-key pinning is a tracked follow-up and is
 * not implemented yet: until it lands this returns undefined and ssh2 keeps
 * its default of accepting the key the server presents, which is the
 * behaviour before the SFTP rework. The follow-up builds a verifier from
 * per-server pins in the registry that fails closed when a pin is missing.
 *
 * @param {ReturnType<typeof getServerConfig>} _server
 * @returns {undefined | ((key: Buffer) => boolean)}
 */
export function hostVerifierFor(_server) {
  return undefined
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

async function connect(server) {
  const ssh = new NodeSSH()
  const hostVerifier = hostVerifierFor(server)
  await ssh.connect({
    host: server.host,
    port: server.port,
    username: server.user,
    privateKeyPath: expandHome(server.privateKeyPath),
    readyTimeout: READY_TIMEOUT_MS,
    ...(hostVerifier ? { hostVerifier } : {})
  })
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
  scheduleIdle(serverId, entry)
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
