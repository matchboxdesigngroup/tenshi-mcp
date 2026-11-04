import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest'
import childProcess from 'node:child_process'
import { createRequire, syncBuiltinESMExports } from 'node:module'

// Runtime never-exec guard (tenshi#20), the counterpart of the static guard
// in scripts/no-exec-guard.mjs. Before any src/ or SSH library module is
// loaded, every child_process function that starts a process is replaced by a
// recording stub that throws, and so is every ssh2 Client and node-ssh method
// that runs a remote command, opens a shell or requests a subsystem. Then
// read_file and read_log run against the in-process SFTP fake, on success and
// refusal paths. Positive controls check that the SFTP methods on the same
// prototypes were called, so the stubs are known to sit on the live path.

const require = createRequire(import.meta.url)
// The ssh2 copy node-ssh loads, not whichever copy the tests would resolve.
const ssh2Path = createRequire(require.resolve('node-ssh')).resolve('ssh2')

const PROCESS_FUNCTIONS = ['exec', 'execSync', 'execFile', 'execFileSync', 'spawn', 'spawnSync', 'fork']
const CLIENT_FORBIDDEN = ['exec', 'shell', 'subsys']
const NODE_SSH_FORBIDDEN = ['exec', 'execCommand', 'requestShell', 'withShell']

const calls = []
function forbidden(label) {
  return function stub() {
    calls.push(label)
    throw new Error(`forbidden call: ${label}`)
  }
}

// Fixture sanity: ssh2 is not loaded yet in this test file's worker, so no
// module captured the real child_process functions before the stubs are
// installed (ssh2 destructures some of them at load time). node-ssh does not
// import child_process.
const loadedBeforeStubs = [ssh2Path].filter(p => Object.hasOwn(require.cache, p))
for (const name of PROCESS_FUNCTIONS) vi.spyOn(childProcess, name).mockImplementation(forbidden(`child_process.${name}`))
syncBuiltinESMExports()

const { Client } = require(ssh2Path)
// node-ssh ships separate CommonJS and ES module builds; src/ssh/client.js
// imports the ES module build, so the stubs go on that one.
const { NodeSSH } = await import('node-ssh')
for (const name of CLIENT_FORBIDDEN) vi.spyOn(Client.prototype, name).mockImplementation(forbidden(`ssh2.Client.${name}`))
for (const name of NODE_SSH_FORBIDDEN) vi.spyOn(NodeSSH.prototype, name).mockImplementation(forbidden(`NodeSSH.${name}`))
const sftpSpy = vi.spyOn(Client.prototype, 'sftp')
const requestSftpSpy = vi.spyOn(NodeSSH.prototype, 'requestSFTP')

const { startFakeSftpServer, loadFakeRegistry, nonSftpRequests, NO_NON_SFTP_REQUESTS } = await import('./helpers/fake-sftp-server.js')
const { readFileHandler } = await import('../src/tools/read-file.js')
const { readLogHandler } = await import('../src/tools/read-log.js')
const { closeAll } = await import('../src/ssh/client.js')

const ROOT = '/var/www/example.com/public'
const LOGS = '/var/log/sites/example.com'
const CANARY = '/srv/canary/secret.txt'

let fake
let restoreRegistry

beforeAll(async () => {
  fake = await startFakeSftpServer({
    files: {
      [`${ROOT}/index.php`]: { content: '<?php echo 1;' },
      [`${ROOT}/wp-config.php`]: { content: '<?php // fake' },
      [`${ROOT}/wp-content/link-out.txt`]: { symlink: CANARY },
      [`${ROOT}/wp-content/debug.log`]: { content: 'debug one\ndebug two\n' },
      [`${LOGS}/example.com.error.log`]: { content: 'error one\n' },
      [`${LOGS}/example.com.access.log`]: { symlink: CANARY },
      [CANARY]: { content: 'CANARY\n' }
    }
  })
  restoreRegistry = await loadFakeRegistry(fake, { 'example.com': { wordpressRoot: ROOT, logDir: LOGS } })
})

afterAll(async () => {
  closeAll()
  restoreRegistry?.()
  await fake?.close()
  vi.restoreAllMocks()
})

const settle = promise => promise.then(value => ({ value }), error => ({ error }))

describe('read_file and read_log never start a process or a remote command', () => {
  it('installed the stubs before the SSH libraries were loaded', () => {
    expect(loadedBeforeStubs).toEqual([])
    expect(childProcess.spawn).not.toBe(undefined)
    expect(vi.isMockFunction(childProcess.spawn)).toBe(true)
  })

  it('serves and refuses reads with no exec, shell, subsystem or process call', async () => {
    const results = await Promise.all([
      settle(readFileHandler({ site: 'example.com', path: 'index.php' })),
      settle(readFileHandler({ site: 'example.com', path: 'wp-config.php' })),
      settle(readFileHandler({ site: 'example.com', path: 'wp-content/link-out.txt' })),
      settle(readFileHandler({ site: 'example.com', path: '../../../srv/canary/secret.txt' })),
      settle(readFileHandler({ site: 'unknown.example', path: 'index.php' })),
      settle(readLogHandler({ site: 'example.com', log: 'debug', lines: 10 })),
      settle(readLogHandler({ site: 'example.com', log: 'error', lines: 10, filter: 'error' })),
      settle(readLogHandler({ site: 'example.com', log: 'access', lines: 10 }))
    ])

    // First, so a failure names the forbidden call.
    expect(calls).toEqual([])
    expect(results[0].value.content).toBe('<?php echo 1;')
    expect(results[5].value.content).toBe('debug one\ndebug two')
    expect(results[6].value.content).toBe('error one')
    for (const i of [1, 2, 3, 4, 7]) expect(results[i].error?.code, `call ${i}`).toBe('E_NOT_AVAILABLE')

    for (const name of PROCESS_FUNCTIONS) expect(childProcess[name], name).not.toHaveBeenCalled()
    for (const name of CLIENT_FORBIDDEN) expect(Client.prototype[name], name).not.toHaveBeenCalled()
    for (const name of NODE_SSH_FORBIDDEN) expect(NodeSSH.prototype[name], name).not.toHaveBeenCalled()
    expect(nonSftpRequests(fake)).toEqual(NO_NON_SFTP_REQUESTS)
    expect(fake.events.opens).not.toContain(CANARY)

    // Positive controls: the reads went through the stubbed prototypes.
    expect(requestSftpSpy).toHaveBeenCalled()
    expect(sftpSpy).toHaveBeenCalled()
  })
})
