import { readFileSync, mkdirSync, writeFileSync, symlinkSync } from 'fs'
import { dirname, join } from 'path'
import { fileURLToPath } from 'url'
import { readFileHandler } from '../../src/tools/read-file.js'
import { readLogHandler } from '../../src/tools/read-log.js'

// Injection and traversal regression corpus (tests/fixtures/injection-corpus.json),
// shared by the in-process fake (tests/injection-corpus.test.js) and the real
// OpenSSH server (tests/sshd-fixture.test.js), so both run the same cases with
// the same expectations.

const CORPUS_PATH = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'injection-corpus.json')
export const CORPUS = JSON.parse(readFileSync(CORPUS_PATH, 'utf8'))

const HANDLERS = { read_file: readFileHandler, read_log: readLogHandler }

/**
 * Fixture paths for a base directory: `{BASE}` (the fake uses a virtual one,
 * the real server a temporary directory) and the layout names in the corpus.
 */
export function corpusLayout(base) {
  const sub = s => s.replaceAll('{BASE}', base)
  const layout = {
    BASE: base,
    ROOT: sub(CORPUS.layout.ROOT),
    LOGS: sub(CORPUS.layout.LOGS),
    CANARY: sub(CORPUS.layout.CANARY),
    SIBLING: sub(CORPUS.layout.SIBLING),
    MARKER_DIR: sub(CORPUS.layout.MARKER_DIR)
  }
  return layout
}

function substitute(text, layout, caseId) {
  return text
    .replaceAll('{MARKER}', `${layout.MARKER_DIR}/marker-${caseId ?? 'tree'}`)
    .replaceAll('{ROOT}', layout.ROOT)
    .replaceAll('{LOGS}', layout.LOGS)
    .replaceAll('{CANARY}', layout.CANARY)
    .replaceAll('{SIBLING}', layout.SIBLING)
    .replaceAll('{BASE}', layout.BASE)
}

function expandValue(value, layout, caseId) {
  if (typeof value === 'string') return substitute(value, layout, caseId)
  if (value && typeof value === 'object' && typeof value.repeat === 'string') {
    return value.repeat.repeat(value.times) + (value.suffix ?? '')
  }
  return value
}

/** Case arguments with placeholders and repeats expanded. */
export function expandArgs(c, layout) {
  return Object.fromEntries(Object.entries(c.args).map(([k, v]) => [k, expandValue(v, layout, c.id)]))
}

/** The corpus tree as absolute paths with node descriptions. */
export function corpusTree(layout) {
  return Object.entries(CORPUS.tree).map(([path, node]) => {
    const abs = substitute(path, layout)
    if (node.symlink !== undefined) return { path: abs, symlink: substitute(node.symlink, layout) }
    const content = node.repeat !== undefined ? node.repeat.repeat(node.times) : node.content
    return { path: abs, content }
  })
}

/** Files map for startFakeSftpServer. */
export function fakeTree(layout) {
  return Object.fromEntries(corpusTree(layout).map(n => [n.path, n.symlink !== undefined ? { symlink: n.symlink } : { content: n.content }]))
}

/** Create the corpus tree on the local file system under layout.BASE. */
export function writeTree(layout) {
  for (const n of corpusTree(layout)) {
    mkdirSync(dirname(n.path), { recursive: true })
    if (n.symlink !== undefined) symlinkSync(n.symlink, n.path)
    else writeFileSync(n.path, n.content)
  }
}

/** Registry site entry for the corpus site. */
export function corpusSite(layout) {
  return { wordpressRoot: layout.ROOT, logDir: layout.LOGS, allow: CORPUS.layout.allow }
}

/** Run one case: { value } on success, { error } on refusal. */
export async function runCase(c, layout) {
  const handler = HANDLERS[c.tool]
  if (!handler) throw new Error(`unknown tool in corpus: ${c.tool}`)
  return handler(expandArgs(c, layout)).then(value => ({ value }), error => ({ error }))
}

/**
 * Problems with an outcome against the case's expectation (empty when it
 * holds). Phase checks are the caller's: they need the server's counters.
 */
export function checkOutcome(c, outcome, layout) {
  const problems = []
  const e = c.expect
  const serialized = JSON.stringify(outcome.error ? { code: outcome.error.code, message: outcome.error.message } : outcome.value)
  for (const s of CORPUS.forbiddenInOutput) {
    const needle = substitute(s, layout)
    if (serialized.includes(needle)) problems.push(`output contains forbidden text ${JSON.stringify(s)}`)
  }
  if (e.error) {
    if (!outcome.error) return [...problems, `expected ${e.error}, got a result`]
    if (outcome.error.message !== CORPUS.messages[e.error]) problems.push(`expected message ${JSON.stringify(CORPUS.messages[e.error])}, got ${JSON.stringify(outcome.error.message)}`)
    return problems
  }
  if (outcome.error) return [...problems, `expected a result, got ${outcome.error.code ?? outcome.error.message}`]
  const v = outcome.value
  if ('content' in e && v.content !== e.content) problems.push(`content ${JSON.stringify(v.content)} !== ${JSON.stringify(e.content)}`)
  for (const s of e.contentIncludes ?? []) if (!v.content.includes(s)) problems.push(`content lacks ${JSON.stringify(s)}`)
  for (const s of e.contentExcludes ?? []) if (v.content.includes(s)) problems.push(`content contains ${JSON.stringify(s)}`)
  for (const key of ['redactedLines', 'returnedLines', 'requestedLines', 'bytes', 'truncated', 'path']) {
    if (key in e && v[key] !== e[key]) problems.push(`${key} ${JSON.stringify(v[key])} !== ${JSON.stringify(e[key])}`)
  }
  if ('returnedLinesAtMost' in e && !(v.returnedLines <= e.returnedLinesAtMost)) problems.push(`returnedLines ${v.returnedLines} > ${e.returnedLinesAtMost}`)
  return problems
}
