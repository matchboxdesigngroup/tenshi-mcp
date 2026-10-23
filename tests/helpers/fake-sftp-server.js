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

import { writeFileSync, mkdtempSync, rmSync, chmodSync } from 'fs'
import { tmpdir } from 'os'
import { join, posix } from 'path'
import ssh2 from 'ssh2'

const { Server, utils } = ssh2
const { OPEN_MODE, STATUS_CODE } = utils.sftp

const S_IFREG = 0o100000
const S_IFDIR = 0o040000
const S_IFLNK = 0o120000

export const USERNAME = 'tenshi-test'

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
    const parts = posix.normalize(p.startsWith('/') ? p : '/' + p).split('/').filter(Boolean)
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
    return { mode, uid: 1000, gid: 1000, size, atime: now, mtime: now }
  }
}

/**
 * Start the fake on 127.0.0.1 with an ephemeral port.
 * @param {{ files: Record<string, object> }} options
 */
export async function startFakeSftpServer({ files }) {
  const fsTree = new FakeFs(files)
  const hostKey = utils.generateKeyPairSync('ed25519')
  const clientKey = utils.generateKeyPairSync('ed25519')
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
    pendingReads: 0
  }

  const clients = new Set()

  function record(op, extra = {}) {
    events.ops.push({ op, ...extra })
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
      if (fsTree.entries.get(lexical)?.hangRealpath) return // never answer
      let resolved
      try { resolved = fsTree.resolve(p, true) } catch { return sftp.status(reqid, STATUS_CODE.FAILURE) }
      if (resolved === undefined) return sftp.status(reqid, STATUS_CODE.NO_SUCH_FILE)
      sftp.name(reqid, [{ filename: resolved, longname: resolved, attrs: {} }])
    })

    const statLike = followLast => (reqid, p) => {
      record(followLast ? 'STAT' : 'LSTAT', { path: p })
      let resolved
      try { resolved = fsTree.resolve(p, followLast) } catch { return sftp.status(reqid, STATUS_CODE.FAILURE) }
      const node = resolved !== undefined ? fsTree.node(resolved) : undefined
      if (!node) return sftp.status(reqid, STATUS_CODE.NO_SUCH_FILE)
      sftp.attrs(reqid, fsTree.attrs(resolved, node))
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
      const id = nextHandle++
      handles.set(id, { path: resolved, node })
      const handle = Buffer.alloc(4)
      handle.writeUInt32BE(id, 0)
      sftp.handle(reqid, handle)
    })

    const lookup = handle => (handle.length === 4 ? handles.get(handle.readUInt32BE(0)) : undefined)

    sftp.on('FSTAT', (reqid, handle) => {
      record('FSTAT')
      const h = lookup(handle)
      if (!h) return sftp.status(reqid, STATUS_CODE.FAILURE)
      sftp.attrs(reqid, fsTree.attrs(h.path, h.node))
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
    client.on('authentication', ctx => {
      if (ctx.username === USERNAME && ctx.method === 'publickey') return ctx.accept()
      ctx.reject(['publickey'])
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
    events,
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
    },
    async close() {
      for (const c of clients) c.end()
      await new Promise(resolve => server.close(() => resolve()))
      rmSync(keyDir, { recursive: true, force: true })
    }
  }
}

/**
 * Write a registry pointing at the fake, load it through the real loader and
 * return the env restore function.
 * @param {Awaited<ReturnType<typeof startFakeSftpServer>>} fake
 * @param {Record<string, { wordpressRoot: string, logDir: string }>} sites
 */
export async function loadFakeRegistry(fake, sites, serverId = 'fake-server') {
  const dir = mkdtempSync(join(tmpdir(), 'tenshi-mcp-registry-'))
  const registryPath = join(dir, 'registry.json')
  writeFileSync(registryPath, JSON.stringify({
    servers: [{
      id: serverId,
      label: 'Fake server',
      host: fake.host,
      port: fake.port,
      user: fake.username,
      privateKeyPath: fake.clientKeyPath,
      sites
    }]
  }))
  const previous = process.env.TENSHI_MCP_SERVERS_PATH
  process.env.TENSHI_MCP_SERVERS_PATH = registryPath
  const { loadRegistry } = await import('../../src/config/servers.js')
  loadRegistry()
  return () => {
    if (previous === undefined) delete process.env.TENSHI_MCP_SERVERS_PATH
    else process.env.TENSHI_MCP_SERVERS_PATH = previous
    rmSync(dir, { recursive: true, force: true })
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
