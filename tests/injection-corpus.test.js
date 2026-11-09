import { describe, it, expect, beforeAll, afterAll, afterEach } from 'vitest'
import { startFakeSftpServer, loadFakeRegistry, nonSftpRequests, NO_NON_SFTP_REQUESTS } from './helpers/fake-sftp-server.js'
import { CORPUS, corpusLayout, fakeTree, corpusSite, runCase, checkOutcome } from './helpers/corpus.js'
import { closeAll } from '../src/ssh/client.js'

// The injection and traversal corpus against the in-process SFTP fake. The
// same cases run against a real OpenSSH server in tests/sshd-fixture.test.js.
// Here the fake also shows where a refusal was made: cases marked
// "phase": "lexical" must be refused before any SFTP session is opened.

const layout = corpusLayout('/fixture')
let fake
let restoreRegistry

beforeAll(async () => {
  fake = await startFakeSftpServer({ files: fakeTree(layout) })
  restoreRegistry = await loadFakeRegistry(fake, { [CORPUS.layout.site]: corpusSite(layout) })
})

afterEach(() => {
  const seen = nonSftpRequests(fake)
  const opens = [...fake.events.opens]
  fake.resetEvents()
  expect(seen).toEqual(NO_NON_SFTP_REQUESTS)
  expect(opens).not.toContain(layout.CANARY)
  expect(opens).not.toContain(layout.SIBLING)
})

afterAll(async () => {
  closeAll()
  restoreRegistry?.()
  await fake?.close()
})

describe('injection corpus against the SFTP fake', () => {
  it('covers every category of tenshi#15', () => {
    const categories = new Set(CORPUS.cases.map(c => c.category))
    expect([...categories].sort()).toEqual([
      'hostile output', 'option injection', 'quoting', 'redirection', 'registry keys', 'resource abuse',
      'sensitive files', 'separators', 'substitution', 'symlinks', 'traversal encodings'
    ])
    expect(new Set(CORPUS.cases.map(c => c.id)).size).toBe(CORPUS.cases.length)
  })

  it.each(CORPUS.cases.map(c => [c.id, c]))('%s', async (_id, c) => {
    const sessionsBefore = fake.events.sftpSessionsOpened
    const outcome = await runCase(c, layout)
    expect(checkOutcome(c, outcome, layout)).toEqual([])
    if (c.expect.phase === 'lexical') expect(fake.events.sftpSessionsOpened, 'refused before any SFTP session').toBe(sessionsBefore)
    // Positive control for the phase check: a served case opened a session.
    if (!c.expect.error) expect(fake.events.sftpSessionsOpened).toBeGreaterThan(sessionsBefore)
  })
})
