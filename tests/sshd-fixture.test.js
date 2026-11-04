import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { existsSync, linkSync, readdirSync, readFileSync, writeFileSync } from 'fs'
import ssh2 from 'ssh2'
import { SSHD_REQUIRED, findOpenSsh, startRealSshd, loadRealRegistry } from './helpers/real-sshd.js'
import { startFakeSftpServer } from './helpers/fake-sftp-server.js'
import { CORPUS, corpusLayout, writeTree, fakeTree, corpusSite, runCase, checkOutcome } from './helpers/corpus.js'
import { readFileHandler } from '../src/tools/read-file.js'
import { closeAll } from '../src/ssh/client.js'

// The real server code against a real OpenSSH sshd (tests/helpers/real-sshd.js):
// the injection corpus with the same expectations as against the fake, then
// server-side evidence (no command, shell or forwarding request reached
// sshd; no marker file was created), then the behaviour the fake cannot
// show: hard links, OpenSSH's realpath, host-key pinning and the locked-down
// account. Skipped locally without sshd; required in CI.

const SITE = CORPUS.layout.site
const HARDLINK_CANARY_TEXT = 'HARDLINK-CANARY\n'
const available = findOpenSsh() !== null

describe('real sshd fixture', () => {
  it(SSHD_REQUIRED ? 'is available (required here)' : 'is available or skipped locally', () => {
    if (SSHD_REQUIRED) expect(available, 'sshd and ssh-keygen are required in CI (TENSHI_MCP_REQUIRE_SSHD or CI=true)').toBe(true)
  })
})

function rawConnect(sshd) {
  return new Promise((resolve, reject) => {
    const client = new ssh2.Client()
    client.once('ready', () => resolve(client))
    client.once('error', reject)
    client.connect({
      host: sshd.host,
      port: sshd.port,
      username: sshd.user,
      privateKey: readFileSync(sshd.clientKeyPath),
      hostHash: 'sha256',
      hostVerifier: hex => 'SHA256:' + Buffer.from(hex, 'hex').toString('base64').replace(/=+$/, '') === sshd.hostKeyFingerprint
    })
  })
}

function rawSftp(client) {
  return new Promise((resolve, reject) => client.sftp((err, sftp) => (err ? reject(err) : resolve(sftp))))
}

function realpathOutcome(sftp, path) {
  return new Promise(resolve => sftp.realpath(path, (err, resolved) => resolve(err ? { code: err.code } : { resolved })))
}

/** Session, global-request and channel types the server logged (LogLevel DEBUG1). */
function requestTypes(log) {
  const pick = re => [...new Set([...log.matchAll(re)].map(m => m[1]))].sort()
  return {
    session: pick(/session_input_channel_req: session \d+ req (\S+)/g),
    global: pick(/server_input_global_request: rtype (\S+)/g),
    channels: pick(/server_input_channel_open: ctype (\S+)/g)
  }
}

describe.skipIf(!available)('real OpenSSH server', () => {
  let sshd
  let layout
  let restoreRegistry
  let hardLinkCanary

  beforeAll(async () => {
    sshd = await startRealSshd({
      prepare: base => {
        layout = corpusLayout(base)
        writeTree(layout)
        // A hard link inside the root to a file outside it (documented residual).
        hardLinkCanary = `${base}/srv/hardlink-canary.txt`
        writeFileSync(hardLinkCanary, HARDLINK_CANARY_TEXT)
        linkSync(hardLinkCanary, `${layout.ROOT}/wp-content/hard-link.txt`)
      }
    })
    restoreRegistry = await loadRealRegistry(sshd, { [SITE]: corpusSite(layout) })
  }, 30000)

  afterAll(async () => {
    closeAll()
    restoreRegistry?.()
    await sshd?.stop()
  })

  describe('injection corpus', () => {
    it.each(CORPUS.cases.map(c => [c.id, c]))('%s', async (_id, c) => {
      const outcome = await runCase(c, layout)
      expect(checkOutcome(c, outcome, layout)).toEqual([])
    })
  })

  describe('after the corpus', () => {
    it('created no marker file and left the canaries unchanged', () => {
      expect(readdirSync(layout.MARKER_DIR)).toEqual(['.keep'])
      expect(readFileSync(layout.CANARY, 'utf8')).toBe('CANARY-OUTSIDE-ROOT\n')
      expect(readFileSync(layout.SIBLING, 'utf8')).toBe('CANARY-SIBLING\n')
    })

    it('sent sshd only SFTP subsystem requests on session channels', () => {
      const types = requestTypes(sshd.log())
      expect(types.session).toEqual(['subsystem'])
      // ssh2 answers OpenSSH's host-key announcement (hostkeys-00) with a
      // proof request on its own; no forwarding or other global request.
      expect(types.global.filter(t => t !== 'hostkeys-prove-00@openssh.com')).toEqual([])
      expect(types.channels).toEqual(['session'])
      expect(sshd.log()).toMatch(/subsystem: internal-sftp/)
    })
  })

  describe('behaviour the fake does not show', () => {
    it('serves a hard link inside the root to a file outside it (residual: undetectable over SFTP v3)', async () => {
      const result = await readFileHandler({ site: SITE, path: 'wp-content/hard-link.txt' })
      expect(result.content).toBe(HARDLINK_CANARY_TEXT)
      expect(result.path).toBe('wp-content/hard-link.txt')
    })

    it('realpath: OpenSSH resolves a missing last component, the fake refuses it; read_file refuses both', async () => {
      const client = await rawConnect(sshd)
      try {
        const sftp = await rawSftp(client)
        const missingLast = await realpathOutcome(sftp, `${layout.ROOT}/missing.txt`)
        const missingParent = await realpathOutcome(sftp, `${layout.ROOT}/no-such-dir/missing.txt`)
        expect(missingLast).toEqual({ resolved: `${layout.ROOT}/missing.txt` })
        expect(missingParent).toEqual({ code: 2 })
      } finally {
        client.end()
      }

      const fake = await startFakeSftpServer({ files: fakeTree(corpusLayout('/fixture')) })
      try {
        const client2 = await rawConnect({ ...fake, user: fake.username })
        try {
          const sftp = await rawSftp(client2)
          expect(await realpathOutcome(sftp, '/fixture/srv/www/example.com/public/missing.txt')).toEqual({ code: 2 })
        } finally {
          client2.end()
        }
      } finally {
        await fake.close()
      }

      // The tool outcome is the same either way: lstat after realpath fails.
      await expect(readFileHandler({ site: SITE, path: 'missing.txt' })).rejects.toThrow(CORPUS.messages.E_NOT_AVAILABLE)
    })

    it('refuses the server when the host-key pin does not match', async () => {
      closeAll()
      restoreRegistry()
      // A valid pin for some other key.
      const otherPin = 'SHA256:' + Buffer.alloc(32, 7).toString('base64').replace(/=+$/, '')
      restoreRegistry = await loadRealRegistry(sshd, { [SITE]: corpusSite(layout) }, { hostKeys: [otherPin] })
      try {
        await expect(readFileHandler({ site: SITE, path: 'index.php' })).rejects.toMatchObject({ code: 'E_HOST_KEY' })
      } finally {
        closeAll()
        restoreRegistry()
        restoreRegistry = await loadRealRegistry(sshd, { [SITE]: corpusSite(layout) })
      }
      const result = await readFileHandler({ site: SITE, path: 'index.php' })
      expect(result.content).toBe("<?php echo 'ok';\n")
    })

    it('lockdown account: a requested command does not run and SFTP writes are refused', async () => {
      const marker = `${layout.MARKER_DIR}/marker-lockdown`
      const client = await rawConnect(sshd)
      try {
        // The forced internal-sftp replaces the command; give it time to run if it could.
        await new Promise((resolve, reject) => client.exec(`touch ${marker}`, (err, stream) => {
          if (err) return reject(err)
          stream.on('close', resolve).resume()
          setTimeout(() => stream.close(), 500)
        }))
        const sftp = await rawSftp(client)
        const write = await new Promise(resolve => sftp.open(`${layout.ROOT}/written.txt`, 'w', err => resolve(err?.code ?? 'opened')))
        expect(write).toBe(3) // SSH_FX_PERMISSION_DENIED from internal-sftp -R
      } finally {
        client.end()
      }
      expect(existsSync(marker)).toBe(false)
      expect(existsSync(`${layout.ROOT}/written.txt`)).toBe(false)
      expect(sshd.log()).toMatch(/forced-command \(config\) 'internal-sftp -R'/)
    })
  })
})
