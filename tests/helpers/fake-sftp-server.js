// In-process SSH server fake for unit tests, built on ssh2's own server mode.
// It serves a small virtual file tree over SFTP (read-only) and records every
// channel, session request and SFTP operation it receives, so tests can
// assert that no exec, shell or write request is ever made.
//
// Virtual tree entries (keys are absolute paths; parents are implicit dirs):
//   { content: string | Buffer }            regular file
//   { dir: true }                            directory
//   { symlink: '/abs/or/relative/target' }   symbolic link
//   { endless: true, size: n }               regular file whose READs always
//                                            return the full requested length
//   { content, hangRead: true }              file whose READs never answer
//   { hangRealpath: true }                   REALPATH on this path never answers
//   { content, realpathReply: '/a/b/../c' }  REALPATH on this path answers with
//                                            the given string verbatim
//   { content, fstatType: 'fifo' }           STAT/LSTAT report a regular file,
//                                            FSTAT on the open handle a FIFO
//                                            (the type changed after the check)
//   { content, uid: 0, gid: 0, perm: 0o600 } owner and permission bits (default
//                                            1000, 1000, 0o644)
//
// A hard link is the same node object under two paths: both names report the
// same content and attributes, and realpath returns the name that was asked
// for, as on a real server. Tests change the tree while a call runs with
// afterOp(op, path, fn) (fn runs once, right after the fake answered `op`
// for exactly `path`) and setEntry(path, node).

import { createHash } from 'crypto'
import { writeFileSync, mkdtempSync, rmSync, chmodSync } from 'fs'
import { createServer, connect as connectTcp } from 'net'
import { tmpdir } from 'os'
import { join, posix } from 'path'
import ssh2 from 'ssh2'

const { Server, utils } = ssh2
const { OPEN_MODE, STATUS_CODE } = utils.sftp

const S_IFREG = 0o100000
const S_IFDIR = 0o040000
const S_IFLNK = 0o120000
const S_IFIFO = 0o010000

export const USERNAME = 'tenshi-test'

/**
 * ssh2's generateKeyPairSync('ed25519') strips leading zero bytes from the
 * public key, so about one key in 256 does not parse. Generate until both
 * halves parse, so the fake never fails at random.
 */
function generateUsableKeyPair() {
  for (let attempt = 0; attempt < 16; attempt++) {
    const pair = utils.generateKeyPairSync('ed25519')
    if (!(utils.parseKey(pair.private) instanceof Error) && !(utils.parseKey(pair.public) instanceof Error)) {
      return pair
    }
  }
  throw new Error('could not generate a usable test key')
}

/**
 * OpenSSH-style SHA-256 fingerprint (`SHA256:<unpadded base64>`) of a public
 * key, computed here independently of src/ so a wrong formula in src/ cannot
 * hide behind the same formula in the fake.
 */
export function opensshFingerprint(publicKey) {
  const parsed = utils.parseKey(publicKey)
  if (parsed instanceof Error) throw parsed
  const digest = createHash('sha256').update(parsed.getPublicSSH()).digest('base64')
  return 'SHA256:' + digest.replace(/=+$/, '')
}

class FakeFs {
  constructor(entries) {
    this.entries = new Map()
    for (const [p, node] of Object.entries(entries)) this.entries.set(posix.normalize(p), node)
  }

  node(p) {
    const n = this.entries.get(p)
    if (n) return n
    if (p === '/') return { dir: true }
    const prefix = p.endsWith('/') ? p : p + '/'
    for (const key of this.entries.keys()) {
      if (key.startsWith(prefix)) return { dir: true }
    }
    return undefined
  }

  /**
   * Resolve like realpath(3): follow every symlink (the last one only when
   * followLast). Returns the resolved path or undefined if a component is
   * missing; throws 'ELOOP' on loops.
   */
  resolve(p, followLast = true, depth = 0) {
    if (depth > 32) throw new Error('ELOOP')
    // Walk the path as given: `..` after a symlink goes to the link target's
    // parent, as on a real server, not to the lexical parent.
    const parts = (p.startsWith('/') ? p : '/' + p).split('/').filter(Boolean)
    let cur = []
    for (let i = 0; i < parts.length; i++) {
      const seg = parts[i]
      if (seg === '.') continue
      if (seg === '..') { cur.pop(); continue }
      cur.push(seg)
      const curPath = '/' + cur.join('/')
      const n = this.node(curPath)
      if (!n) return undefined
      const isLast = i === parts.length - 1
      if (n.symlink && (followLast || !isLast)) {
        const parent = '/' + cur.slice(0, -1).join('/')
        const target = n.symlink.startsWith('/') ? n.symlink : posix.join(parent, n.symlink)
        const resolved = this.resolve(target, true, depth + 1)
        if (resolved === undefined) return undefined
        cur = resolved.split('/').filter(Boolean)
      } else if (!isLast && !n.dir && !n.symlink) {
        return undefined // file used as a directory
      }
    }
    return '/' + cur.join('/')
  }

  attrs(p, node) {
    const now = Math.floor(Date.now() / 1000)
    let mode = S_IFREG | 0o644
    let size = 0
    if (node.dir) mode = S_IFDIR | 0o755
    else if (node.symlink) { mode = S_IFLNK | 0o777; size = node.symlink.length }
    else if (node.endless) size = node.size ?? 0
    else size = Buffer.byteLength(node.content ?? '')
    if (!node.dir && !node.symlink && node.perm !== undefined) mode = S_IFREG | node.perm
    return { mode, uid: node.uid ?? 1000, gid: node.gid ?? 1000, size, atime: now, mtime: now }
  }
}

/**
 * Start the fake on 127.0.0.1 with an ephemeral port.
 * @param {{ files: Record<string, object> }} options
 */
export async function startFakeSftpServer({ files }) {
  const fsTree = new FakeFs(files)
  const hostKey = generateUsableKeyPair()
  const clientKey = generateUsableKeyPair()
  const keyDir = mkdtempSync(join(tmpdir(), 'tenshi-mcp-fake-'))
  const clientKeyPath = join(keyDir, 'client_key')
  writeFileSync(clientKeyPath, clientKey.private)
  chmodSync(clientKeyPath, 0o600)

  const events = {
    connections: 0,
    channels: [],          // channel types other than 'session'
    sessionRequests: [],   // exec, shell, pty, env, subsystem, x11, ...
    globalRequests: [],
    sftpSessionsOpened: 0,
    sftpSessionsClosed: 0,
    ops: [],               // { op, path? }
    opens: [],             // resolved paths opened for reading
    readBytesServed: 0,
    pendingReads: 0,
    openHandles: 0,         // handles opened and not yet closed with CLOSE
    authAttempts: 0         // authentication requests of any method, cumulative
  }

  const clients = new Set()
  // When set, authentication waits until the gate resolves (see holdAuthentication).
  let authGate = null

  function record(op, extra = {}) {
    events.ops.push({ op, ...extra })
  }

  /** @type {{ op: string, path: string, fn: () => void }[]} */
  let hooks = []
  /** Run, once, the hooks registered for `op` on exactly `path`. Called after the reply was sent. */
  function runHooks(op, p) {
    const due = hooks.filter(h => h.op === op && h.path === p)
    if (due.length === 0) return
    hooks = hooks.filter(h => !due.includes(h))
    for (const h of due) h.fn()
  }

  function handleSftp(sftp) {
    events.sftpSessionsOpened++
    let closedCounted = false
    const markClosed = () => {
      if (closedCounted) return
      closedCounted = true
      events.sftpSessionsClosed++
    }
    sftp.on('close', markClosed)
    sftp.on('end', markClosed)

    const handles = new Map()
    let nextHandle = 0

    sftp.on('REALPATH', (reqid, p) => {
      record('REALPATH', { path: p })
      const lexical = posix.normalize(p.startsWith('/') ? p : '/' + p)
      const entry = fsTree.entries.get(lexical)
      if (entry?.hangRealpath) return // never answer
      if (entry?.realpathReply) return sftp.name(reqid, [{ filename: entry.realpathReply, longname: entry.realpathReply, attrs: {} }])
      let resolved
      try { resolved = fsTree.resolve(p, true) } catch { return sftp.status(reqid, STATUS_CODE.FAILURE) }
      if (resolved === undefined) return sftp.status(reqid, STATUS_CODE.NO_SUCH_FILE)
      sftp.name(reqid, [{ filename: resolved, longname: resolved, attrs: {} }])
      runHooks('REALPATH', p)
    })

    const statLike = followLast => (reqid, p) => {
      const op = followLast ? 'STAT' : 'LSTAT'
      record(op, { path: p })
      let resolved
      try { resolved = fsTree.resolve(p, followLast) } catch { return sftp.status(reqid, STATUS_CODE.FAILURE) }
      const node = resolved !== undefined ? fsTree.node(resolved) : undefined
      if (!node) return sftp.status(reqid, STATUS_CODE.NO_SUCH_FILE)
      sftp.attrs(reqid, fsTree.attrs(resolved, node))
      runHooks(op, p)
    }
    sftp.on('STAT', statLike(true))
    sftp.on('LSTAT', statLike(false))

    sftp.on('OPEN', (reqid, p, flags) => {
      record('OPEN', { path: p, flags })
      const writeFlags = OPEN_MODE.WRITE | OPEN_MODE.APPEND | OPEN_MODE.CREAT | OPEN_MODE.TRUNC | OPEN_MODE.EXCL
      if (flags & writeFlags) return sftp.status(reqid, STATUS_CODE.PERMISSION_DENIED)
      let resolved
      try { resolved = fsTree.resolve(p, true) } catch { return sftp.status(reqid, STATUS_CODE.FAILURE) }
      const node = resolved !== undefined ? fsTree.node(resolved) : undefined
      if (!node) return sftp.status(reqid, STATUS_CODE.NO_SUCH_FILE)
      if (node.dir) return sftp.status(reqid, STATUS_CODE.FAILURE)
      events.opens.push(resolved)
      events.openHandles++
      const id = nextHandle++
      handles.set(id, { path: resolved, node })
      const handle = Buffer.alloc(4)
      handle.writeUInt32BE(id, 0)
      sftp.handle(reqid, handle)
      runHooks('OPEN', p)
    })

    const lookup = handle => (handle.length === 4 ? handles.get(handle.readUInt32BE(0)) : undefined)

    sftp.on('FSTAT', (reqid, handle) => {
      record('FSTAT')
      const h = lookup(handle)
      if (!h) return sftp.status(reqid, STATUS_CODE.FAILURE)
      const attrs = fsTree.attrs(h.path, h.node)
      if (h.node.fstatType === 'fifo') attrs.mode = S_IFIFO | 0o644
      sftp.attrs(reqid, attrs)
    })

    sftp.on('READ', (reqid, handle, offset, length) => {
      record('READ', { offset, length })
      const h = lookup(handle)
      if (!h) return sftp.status(reqid, STATUS_CODE.FAILURE)
      if (h.node.hangRead) { events.pendingReads++; return } // never answer
      if (h.node.endless) {
        events.readBytesServed += length
        return sftp.data(reqid, Buffer.alloc(length, 0x41))
      }
      const content = Buffer.isBuffer(h.node.content) ? h.node.content : Buffer.from(h.node.content ?? '')
      if (offset >= content.length) return sftp.status(reqid, STATUS_CODE.EOF)
      const chunk = content.subarray(offset, Math.min(content.length, offset + length))
      events.readBytesServed += chunk.length
      sftp.data(reqid, chunk)
    })

    sftp.on('CLOSE', (reqid, handle) => {
      record('CLOSE')
      const h = lookup(handle)
      if (!h) return sftp.status(reqid, STATUS_CODE.FAILURE)
      handles.delete(handle.readUInt32BE(0))
      events.openHandles--
      sftp.status(reqid, STATUS_CODE.OK)
    })

    // Everything else is recorded and refused: the tools must never need it.
    for (const op of ['WRITE', 'FSETSTAT', 'SETSTAT', 'OPENDIR', 'READDIR', 'REMOVE', 'RMDIR',
      'MKDIR', 'RENAME', 'READLINK', 'SYMLINK', 'EXTENDED']) {
      sftp.on(op, reqid => {
        record(op)
        sftp.status(reqid, STATUS_CODE.OP_UNSUPPORTED)
      })
    }
  }

  const server = new Server({ hostKeys: [hostKey.private] }, client => {
    events.connections++
    clients.add(client)
    client.on('error', () => {})
    client.on('close', () => clients.delete(client))
    client.on('authentication', async ctx => {
      events.authAttempts++
      if (ctx.username !== USERNAME || ctx.method !== 'publickey') return ctx.reject(['publickey'])
      if (authGate) await authGate
      ctx.accept()
    })
    client.on('ready', () => {
      client.on('request', (accept, reject, name) => {
        events.globalRequests.push(name)
        reject?.()
      })
      for (const type of ['tcpip', 'openssh.streamlocal']) {
        client.on(type, (accept, reject) => {
          events.channels.push(type)
          reject?.()
        })
      }
      client.on('session', accept => {
        const session = accept()
        for (const type of ['exec', 'shell', 'pty', 'env', 'subsystem', 'x11', 'auth-agent', 'signal', 'window-change']) {
          session.on(type, (acc, rej, info) => {
            events.sessionRequests.push({ type, info })
            rej?.()
          })
        }
        session.on('sftp', acc => handleSftp(acc()))
      })
    })
  })

  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
  const { port } = server.address()

  return {
    host: '127.0.0.1',
    port,
    username: USERNAME,
    clientKeyPath,
    clientPrivateKey: clientKey.private,
    /** The fake's host-key fingerprint in the OpenSSH form, for registry pins. */
    hostKeyFingerprint: opensshFingerprint(hostKey.public),
    events,
    /** Hold every authentication until the returned function is called. */
    holdAuthentication() {
      let release
      authGate = new Promise(resolve => { release = resolve })
      return () => { authGate = null; release() }
    },
    /**
     * Run `fn` once, right after the fake has answered `op` ('REALPATH',
     * 'LSTAT', 'STAT' or 'OPEN') for exactly `path`: the next request already
     * sees the change, as if the file were swapped between two requests.
     */
    afterOp(op, path, fn) {
      hooks.push({ op, path, fn })
    },
    /** Put `node` at `path`, replacing whatever was there. */
    setEntry(path, node) {
      fsTree.entries.set(posix.normalize(path), node)
    },
    /** Count of SSH connections currently open. */
    openConnections: () => clients.size,
    /** End every open SSH connection from the server side (the pool sees a drop). */
    disconnectClients() {
      for (const c of clients) c.end()
    },
    /** Count of SFTP sessions currently open. */
    openSftpSessions: () => events.sftpSessionsOpened - events.sftpSessionsClosed,
    /** Resolve when the predicate holds, or reject after `ms`. */
    async waitFor(predicate, ms = 2000) {
      const start = Date.now()
      while (!predicate()) {
        if (Date.now() - start > ms) throw new Error('waitFor timed out')
        await new Promise(r => setTimeout(r, 10))
      }
    },
    resetEvents() {
      events.channels.length = 0
      events.sessionRequests.length = 0
      events.globalRequests.length = 0
      events.ops.length = 0
      events.opens.length = 0
      events.readBytesServed = 0
      events.pendingReads = 0
      events.openHandles = 0
      hooks = []
    },
    async close() {
      for (const c of clients) c.end()
      await new Promise(resolve => server.close(() => resolve()))
      rmSync(keyDir, { recursive: true, force: true })
    }
  }
}

/**
 * Allowlist given to fake-registry sites that do not set their own: every
 * directory, a few plain-text extensions. Tests about the policy set `allow`
 * explicitly.
 */
export const TEST_ALLOW = Object.freeze({ extensions: ['.php', '.txt', '.bin', '.log'], directories: ['.'] })

/** The site map with TEST_ALLOW added to every site that has no `allow`. */
export function withTestAllow(sites) {
  return Object.fromEntries(Object.entries(sites).map(([name, site]) => [name, { allow: TEST_ALLOW, ...site }]))
}

/**
 * Registry JSON for a server entry pointing at the fake. See loadFakeRegistry.
 */
export function fakeServerEntry(fake, sites, serverId = 'fake-server', options = {}) {
  return {
    id: serverId,
    label: 'Fake server',
    host: options.host ?? fake.host,
    port: options.port ?? fake.port,
    user: fake.username,
    privateKeyPath: fake.clientKeyPath,
    hostKeys: options.hostKeys ?? [fake.hostKeyFingerprint],
    sites: withTestAllow(sites)
  }
}

/**
 * Write a registry pointing at the fake, load it through the real loader and
 * return the env restore function. The server is pinned to the fake's host
 * key unless `options.hostKeys` is given; `options.host` and `options.port`
 * point it somewhere else (for example a forwarder in front of the fake).
 * Sites without `allow` get TEST_ALLOW.
 * @param {Awaited<ReturnType<typeof startFakeSftpServer>>} fake
 * @param {Record<string, { wordpressRoot: string, logDir: string, allow?: object }>} sites
 * @param {{ hostKeys?: string[], host?: string, port?: number }} [options]
 */
export async function loadFakeRegistry(fake, sites, serverId = 'fake-server', extraServers = [], options = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'tenshi-mcp-registry-'))
  const registryPath = join(dir, 'registry.json')
  writeFileSync(registryPath, JSON.stringify({
    servers: [
      fakeServerEntry(fake, sites, serverId, options),
      ...extraServers.map(s => ({ ...s, sites: withTestAllow(s.sites ?? {}) }))
    ]
  }))
  const previous = process.env.TENSHI_MCP_SERVERS_PATH
  process.env.TENSHI_MCP_SERVERS_PATH = registryPath
  const restore = () => {
    if (previous === undefined) delete process.env.TENSHI_MCP_SERVERS_PATH
    else process.env.TENSHI_MCP_SERVERS_PATH = previous
    rmSync(dir, { recursive: true, force: true })
  }
  const { loadRegistry } = await import('../../src/config/servers.js')
  try {
    loadRegistry()
  } catch (err) {
    // A refused registry leaves nothing behind; the caller sees the error.
    restore()
    throw err
  }
  return restore
}

/**
 * Network activity counters of the fake: SSH connections accepted and SFTP
 * sessions opened, both cumulative.
 */
export function networkCounters(fake) {
  return { connections: fake.events.connections, sftpSessionsOpened: fake.events.sftpSessionsOpened }
}

/**
 * Run `fn` with an empty connection pool and return the counters before and
 * after, so a test can assert that `fn` caused no network activity at all.
 * @param {() => void} closeAll the pool's closeAll
 */
export async function countNetwork(fake, closeAll, fn) {
  closeAll()
  await fake.waitFor(() => fake.openConnections() === 0)
  const before = networkCounters(fake)
  await fn()
  // Give a stray connection attempt time to reach the fake.
  await new Promise(resolve => setTimeout(resolve, 50))
  return { before, after: networkCounters(fake) }
}

/**
 * A TCP listener that counts connection attempts and drops each at once, so
 * the SSH handshake always fails. Stands in for an unreachable server.
 */
export async function startCountingSink() {
  let attempts = 0
  const server = createServer(socket => { attempts++; socket.destroy() })
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
  return {
    host: '127.0.0.1',
    port: server.address().port,
    attempts: () => attempts,
    close: () => new Promise(resolve => server.close(() => resolve()))
  }
}

/**
 * A TCP forwarder on 127.0.0.1 that pipes each new connection to the current
 * target port. `retarget(port)` changes where later connections go, so a test
 * can put a server with a different host key behind the same registry entry.
 */
export async function startTcpForwarder(targetPort) {
  let target = targetPort
  const sockets = new Set()
  const server = createServer(inbound => {
    const outbound = connectTcp(target, '127.0.0.1')
    sockets.add(inbound)
    sockets.add(outbound)
    const done = () => { inbound.destroy(); outbound.destroy(); sockets.delete(inbound); sockets.delete(outbound) }
    inbound.on('error', done).on('close', done)
    outbound.on('error', done).on('close', done)
    inbound.pipe(outbound)
    outbound.pipe(inbound)
  })
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
  return {
    host: '127.0.0.1',
    port: server.address().port,
    retarget(port) { target = port },
    async close() {
      for (const s of sockets) s.destroy()
      await new Promise(resolve => server.close(() => resolve()))
    }
  }
}

/** Assert helper: no exec, shell or any non-SFTP request reached the fake. */
export function nonSftpRequests(fake) {
  return {
    sessionRequests: fake.events.sessionRequests.map(r => r.type),
    channels: [...fake.events.channels],
    mutatingOps: fake.events.ops
      .map(o => o.op)
      .filter(op => !['REALPATH', 'STAT', 'LSTAT', 'OPEN', 'FSTAT', 'READ', 'CLOSE'].includes(op))
  }
}

export const NO_NON_SFTP_REQUESTS = Object.freeze({ sessionRequests: [], channels: [], mutatingOps: [] })
