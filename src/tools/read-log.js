import { z } from 'zod'
import { withSftpSession } from '../ssh/sftp.js'
import { checkLexically, confineLexically, openConfinedFile } from '../ssh/confine.js'
import { redactLines } from '../policy/redact.js'
import { toToolError } from '../errors.js'
import { lookupSite } from './site.js'

export const MAX_LINES = 500
/** Bytes read from the end of the log; older content is not searched. */
export const WINDOW_BYTES = 256 * 1024
/** Cap on the returned content in UTF-8 bytes; the newest lines are kept. */
export const MAX_OUTPUT_BYTES = 51200
/** Longer lines are cut to this many characters plus a marker. */
export const MAX_LINE_CHARS = 2000
export const MAX_FILTER_LENGTH = 200
export const LINE_TRUNCATED_MARKER = ' [line truncated]'

export const LOG_NAMES = /** @type {const} */ (['debug', 'access', 'error'])

const InputSchema = z.object({
  site: z.string().min(1),
  log: z.enum(LOG_NAMES),
  lines: z.number().int().min(1).default(50),
  filter: z.string().max(MAX_FILTER_LENGTH).optional()
})

/**
 * Fixed mapping from the log name to a configured root and a file under it.
 * Only registry values form the path: the log name selects a case and `site`
 * is the registry key that lookupSite already matched.
 */
function logLocation(log, site, config) {
  switch (log) {
    case 'debug':
      return { root: config.wordpressRoot, relativePath: 'wp-content/debug.log' }
    case 'error':
      return { root: config.logDir, relativePath: `${site}.error.log`, trustedPrefix: site }
    case 'access':
      return { root: config.logDir, relativePath: `${site}.access.log`, trustedPrefix: site }
  }
}

/**
 * Pick the lines to return from the tail window. Credential lines are
 * redacted first, so the filter, the line selection and the caps only ever
 * see redacted text (a filter cannot probe a secret through the line
 * count). The filter is a case-insensitive substring match on the plain
 * string: no regular expression is ever built from it, so every character is
 * literal.
 *
 * @param {string} text decoded tail window
 * @param {{ dropFirstLine: boolean, lines: number, filter?: string }} options
 *   dropFirstLine: the window starts mid-file, so its first line may be partial
 */
export function selectLines(text, { dropFirstLine, lines, filter }) {
  const all = text.split('\n')
  if (all.length > 0 && all[all.length - 1] === '') all.pop()
  const clean = all.map(line => (line.endsWith('\r') ? line.slice(0, -1) : line))
  // The partial first line still gives context (an assignment whose value is
  // on the next line); it is dropped only after classification.
  const redaction = redactLines(clean)
  const entries = redaction.lines.map((line, i) => ({ line, redacted: redaction.redacted[i] }))
  if (dropFirstLine) entries.shift()

  const needle = filter ? filter.toLowerCase() : ''
  const matched = needle ? entries.filter(e => e.line.toLowerCase().includes(needle)) : entries
  const pickedEntries = matched.slice(-lines)
  const picked = pickedEntries.map(e => e.line)

  let longLines = 0
  const capped = picked.map(line => {
    if (line.length <= MAX_LINE_CHARS) return line
    longLines++
    // Do not split a surrogate pair at the cut.
    const lastKept = line.charCodeAt(MAX_LINE_CHARS - 1)
    const cut = lastKept >= 0xd800 && lastKept <= 0xdbff ? MAX_LINE_CHARS - 1 : MAX_LINE_CHARS
    return line.slice(0, cut) + LINE_TRUNCATED_MARKER
  })

  // Keep the newest lines that fit in the byte cap.
  const kept = []
  let bytes = 0
  for (let i = capped.length - 1; i >= 0; i--) {
    const cost = Buffer.byteLength(capped[i], 'utf8') + (kept.length > 0 ? 1 : 0)
    if (bytes + cost > MAX_OUTPUT_BYTES) break
    kept.push(capped[i])
    bytes += cost
  }
  kept.reverse()
  const redactedLines = pickedEntries.slice(capped.length - kept.length).filter(e => e.redacted).length

  return { lines: kept, longLines, droppedForBytes: capped.length - kept.length, redactedLines }
}

/**
 * @param {unknown} rawInput tool arguments
 * @param {{ timeoutMs?: number }} [options] test hook; the MCP server passes none
 */
export async function readLogHandler(rawInput, options = {}) {
  try {
    const input = InputSchema.parse(rawInput)
    const lines = Math.min(input.lines, MAX_LINES)
    const site = lookupSite(input.site)
    const { root, relativePath, trustedPrefix } = logLocation(input.log, input.site, site)
    // The site name in a log file name comes from the registry (validated as
    // a host name), so the denylist skips it: a site whose name contains a
    // denied word keeps its logs. The rest of the name is checked as usual.
    const denyOptions = { trustedPrefix }
    // A log is served only at its configured location: the canonical path
    // must be exactly the configured one (a log that is a symlink, even to
    // another file inside the root, is refused), and the built-in denylist
    // applies as for every path.
    const expected = confineLexically(root, relativePath)
    const allow = candidate => candidate === expected
    // Every check that needs no server runs before the connection is opened,
    // so a refusal never depends on the server being reachable.
    checkLexically(root, relativePath, allow, denyOptions)

    const { window, start } = await withSftpSession(site.serverId, async session => {
      const { handle, size } = await openConfinedFile(session, root, relativePath, allow, denyOptions)
      try {
        const windowStart = Math.max(0, size - WINDOW_BYTES)
        const buf = await handle.read(windowStart, size - windowStart)
        return { window: buf, start: windowStart }
      } finally {
        await handle.close().catch(() => {})
      }
    }, { timeoutMs: options.timeoutMs })

    const selected = selectLines(window.toString('utf8'), {
      dropFirstLine: start > 0,
      lines,
      filter: input.filter
    })

    return {
      site: input.site,
      log: input.log,
      requestedLines: lines,
      returnedLines: selected.lines.length,
      content: selected.lines.join('\n'),
      truncated: {
        window: start > 0,
        longLines: selected.longLines,
        bytes: selected.droppedForBytes > 0
      },
      redactedLines: selected.redactedLines,
      retrievedAt: new Date().toISOString()
    }
  } catch (err) {
    throw toToolError(err)
  }
}

export const readLogTool = {
  name: 'read_log',
  schema: {
    site: { type: 'string', description: 'Site domain, e.g. example.com' },
    log: { type: 'string', enum: LOG_NAMES, description: 'Log type' },
    lines: { type: 'number', description: `Number of lines to return from the end of the log (max ${MAX_LINES})`, default: 50 },
    filter: { type: 'string', description: 'Optional case-insensitive substring, matched literally' }
  },
  handler: readLogHandler
}
