import { spawn, spawnSync } from 'child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'fs'
import { createServer, connect as connectTcp } from 'net'
import { tmpdir, userInfo } from 'os'
import { dirname, join } from 'path'
import { opensshFingerprint } from './fake-sftp-server.js'

// A real OpenSSH server for tests: started by the test as the current user
// (no root), listening on 127.0.0.1 and an ephemeral port, with a throwaway
// host key (pinned by the registry the test writes) and client key generated
// for this run in a temporary directory that is removed afterwards. The
// account is locked down the way the platform ADR asks of target hosts, as
// far as an unprivileged server can: `restrict` in authorized_keys, public
// key only, a forced read-only `internal-sftp`, no forwarding, no TTY.
// ChrootDirectory needs root, so the site tree is a synthetic tree inside the
// temporary directory instead.
//
// Local runs skip the fixture when sshd or ssh-keygen is missing. In CI
// (CI=true, as GitHub Actions sets it) or with TENSHI_MCP_REQUIRE_SSHD=1 it
// is required. TENSHI_MCP_SSHD names another sshd binary.

export const SSHD_REQUIRED = process.env.CI === 'true' || process.env.TENSHI_MCP_REQUIRE_SSHD === '1'

function onPath(name) {
  const r = spawnSync('/bin/sh', ['-c', `command -v ${name}`], { encoding: 'utf8' })
  return r.status === 0 ? r.stdout.trim() : null
}

/** Absolute paths of sshd and ssh-keygen, or null when either is missing. */
export function findOpenSsh() {
  const sshd = [process.env.TENSHI_MCP_SSHD, '/usr/sbin/sshd', '/usr/local/sbin/sshd'].find(p => p && existsSync(p))
  const keygen = onPath('ssh-keygen')
  return sshd && keygen ? { sshd, keygen } : null
}

function freePort() {
  return new Promise((resolve, reject) => {
    const server = createServer()
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address()
      server.close(() => resolve(port))
    })
  })
}

function canConnect(port) {
  return new Promise(resolve => {
    const socket = connectTcp(port, '127.0.0.1')
    socket.once('connect', () => { socket.destroy(); resolve(true) })
    socket.once('error', () => resolve(false))
  })
}

function keygen(bin, path) {
  const r = spawnSync(bin, ['-q', '-t', 'ed25519', '-N', '', '-C', 'tenshi-mcp-fixture', '-f', path], { encoding: 'utf8' })
  if (r.status !== 0) throw new Error(`ssh-keygen failed: ${r.stderr}`)
  return readFileSync(`${path}.pub`, 'utf8').trim()
}

/**
 * Start the server. `prepare(base)` runs before sshd starts and may create
 * files under the temporary base directory (the site tree).
 */
export async function startRealSshd({ prepare } = {}) {
  const tools = findOpenSsh()
  if (!tools) throw new Error('sshd or ssh-keygen not found')
  const base = realpathSync(mkdtempSync(join(tmpdir(), 'tenshi-mcp-sshd-')))
  const etc = join(base, 'etc')
  mkdirSync(etc)
  const hostPublic = keygen(tools.keygen, join(etc, 'host_key'))
  const clientPublic = keygen(tools.keygen, join(etc, 'client_key'))
  writeFileSync(join(etc, 'authorized_keys'), `restrict ${clientPublic}\n`, { mode: 0o600 })
  await prepare?.(base)

  const user = userInfo().username
  const logPath = join(etc, 'sshd.log')
  let port
  let child
  for (let attempt = 0; attempt < 3 && !child; attempt++) {
    port = await freePort()
    const config = join(etc, 'sshd_config')
    writeFileSync(config, [
      'ListenAddress 127.0.0.1',
      `Port ${port}`,
      `HostKey ${join(etc, 'host_key')}`,
      `PidFile ${join(etc, 'sshd.pid')}`,
      `AuthorizedKeysFile ${join(etc, 'authorized_keys')}`,
      // The temporary directory is under a world-writable parent.
      'StrictModes no',
      'PubkeyAuthentication yes',
      'AuthenticationMethods publickey',
      'PasswordAuthentication no',
      'KbdInteractiveAuthentication no',
      `AllowUsers ${user}`,
      'AllowTcpForwarding no',
      'AllowStreamLocalForwarding no',
      'GatewayPorts no',
      'X11Forwarding no',
      'PermitTTY no',
      'PermitTunnel no',
      'PermitUserEnvironment no',
      'Subsystem sftp internal-sftp',
      'ForceCommand internal-sftp -R',
      'LogLevel DEBUG1',
      ''
    ].join('\n'))
    const check = spawnSync(tools.sshd, ['-t', '-f', config], { encoding: 'utf8' })
    if (check.status !== 0) throw new Error(`sshd -t failed: ${check.stderr}`)
    writeFileSync(logPath, '')
    const started = spawn(tools.sshd, ['-D', '-f', config, '-E', logPath], { stdio: 'ignore' })
    let exited = false
    started.once('exit', () => { exited = true })
    for (let i = 0; i < 100 && !exited; i++) {
      if (await canConnect(port)) { child = started; break }
      await new Promise(resolve => setTimeout(resolve, 50))
    }
    if (!child && !exited) started.kill('SIGTERM')
  }
  if (!child) {
    rmSync(base, { recursive: true, force: true })
    throw new Error('sshd did not start')
  }

  return {
    base,
    host: '127.0.0.1',
    port,
    user,
    clientKeyPath: join(etc, 'client_key'),
    hostKeyFingerprint: opensshFingerprint(hostPublic),
    /** The server log so far (LogLevel DEBUG1: every session and global request). */
    log: () => readFileSync(logPath, 'utf8'),
    async stop() {
      if (child.exitCode === null) {
        const exited = new Promise(resolve => child.once('exit', resolve))
        child.kill('SIGTERM')
        await exited
      }
      rmSync(base, { recursive: true, force: true })
    }
  }
}

/** Write a registry for the real server and point TENSHI_MCP_SERVERS_PATH at it. Returns the restore function. */
export async function loadRealRegistry(sshd, sites, { hostKeys } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'tenshi-mcp-registry-'))
  const registryPath = join(dir, 'registry.json')
  writeFileSync(registryPath, JSON.stringify({
    servers: [{
      id: 'real-sshd',
      label: 'Real sshd fixture',
      host: sshd.host,
      port: sshd.port,
      user: sshd.user,
      privateKeyPath: sshd.clientKeyPath,
      hostKeys: hostKeys ?? [sshd.hostKeyFingerprint],
      sites
    }]
  }))
  const previous = process.env.TENSHI_MCP_SERVERS_PATH
  process.env.TENSHI_MCP_SERVERS_PATH = registryPath
  const { loadRegistry } = await import('../../src/config/servers.js')
  try {
    loadRegistry()
  } finally {
    // The registry is read once; the file is not needed afterwards.
    rmSync(dirname(registryPath), { recursive: true, force: true })
  }
  return () => {
    if (previous === undefined) delete process.env.TENSHI_MCP_SERVERS_PATH
    else process.env.TENSHI_MCP_SERVERS_PATH = previous
  }
}
