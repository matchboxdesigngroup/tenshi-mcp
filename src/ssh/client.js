import { NodeSSH } from 'node-ssh'
import { homedir } from 'os'
import { getServerConfig } from '../config/servers.js'

/** @type {Map<string, { ssh: NodeSSH, lastUsed: number, timer: ReturnType<typeof setTimeout> }>} */
const pool = new Map()

const IDLE_MS = 5 * 60 * 1000

function expandHome(p) {
  return p.startsWith('~') ? p.replace('~', homedir()) : p
}

function scheduleIdle(serverId) {
  const entry = pool.get(serverId)
  if (!entry) return
  clearTimeout(entry.timer)
  entry.timer = setTimeout(() => {
    const e = pool.get(serverId)
    if (e) {
      e.ssh.dispose()
      pool.delete(serverId)
    }
  }, IDLE_MS)
}

export async function getConnection(serverId) {
  // Allowlist check — throws if not in registry
  const server = getServerConfig(serverId)

  const existing = pool.get(serverId)
  if (existing?.ssh.isConnected()) {
    existing.lastUsed = Date.now()
    scheduleIdle(serverId)
    return existing.ssh
  }

  const ssh = new NodeSSH()
  await ssh.connect({
    host: server.host,
    port: server.port,
    username: server.user,
    privateKeyPath: expandHome(server.privateKeyPath),
    readyTimeout: 10000
  })

  pool.set(serverId, { ssh, lastUsed: Date.now(), timer: null })
  scheduleIdle(serverId)
  return ssh
}

export function closeAll() {
  for (const [id, entry] of pool) {
    clearTimeout(entry.timer)
    entry.ssh.dispose()
    pool.delete(id)
  }
}
