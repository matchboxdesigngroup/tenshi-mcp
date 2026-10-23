import { z } from 'zod'
import { withSftpSession } from '../ssh/sftp.js'
import { confineLexically, openConfinedFile } from '../ssh/confine.js'
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
      return { root: config.logDir, relativePath: `${site}.error.log` }
    case 'access':
      return { root: config.logDir, relativePath: `${site}.access.log` }
  }
}

/**
 * Pick the lines to return from the tail window. The filter is a
 * case-insensitive substring match on the plain string: no regular
 * expression is ever built from it, so every character is literal.
 *
 * @param {string} text decoded tail window
 * @param {{ dropFirstLine: boolean, lines: number, filter?: string }} options
 *   dropFirstLine: the window starts mid-file, so its first line may be partial
 */
export function selectLines(text, { dropFirstLine, lines, filter }) {
  const all = text.split('\n')
  if (all.length > 0 && all[all.length - 1] === '') all.pop()
  if (dropFirstLine) all.shift()
  const clean = all.map(line => (line.endsWith('\r') ? line.slice(0, -1) : line))

  const needle = filter ? filter.toLowerCase() : ''
  const matched = needle ? clean.filter(line => line.toLowerCase().includes(needle)) : clean
  const picked = matched.slice(-lines)

  let longLines = 0
  const capped = picked.map(line => {
    if (line.length <= MAX_LINE_CHARS) return line
    longLines++
    return line.slice(0, MAX_LINE_CHARS) + LINE_TRUNCATED_MARKER
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

  return { lines: kept, longLines, droppedForBytes: capped.length - kept.length }
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
    const { root, relativePath } = logLocation(input.log, input.site, site)
    // Every check that needs no server runs before the connection is opened,
    // so a refusal never depends on the server being reachable.
    confineLexically(root, relativePath)

    const { window, start } = await withSftpSession(site.serverId, async session => {
      const { handle, size } = await openConfinedFile(session, root, relativePath)
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
