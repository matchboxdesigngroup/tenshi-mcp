import { z } from 'zod'
import { withSftpSession } from '../ssh/sftp.js'
import { checkLexically, openConfinedFile } from '../ssh/confine.js'
import { isAllowed } from '../policy/paths.js'
import { redactLines, REDACTED_LINE } from '../policy/redact.js'
import { toToolError } from '../errors.js'
import { lookupSite } from './site.js'

export const MAX_BYTES = 51200
export const DEFAULT_BYTES = 10000
export const MAX_PATH_LENGTH = 1024
/**
 * Bytes read past the cap so the line that the cap cuts is classified on its
 * whole text (up to this many bytes past the cut), never on the part the
 * caller chose to see. Longer than the span any redaction rule needs.
 */
export const LOOKAHEAD_BYTES = 4096

/**
 * Length of `buf` without a trailing incomplete UTF-8 sequence, so a cut at
 * the byte cap does not split a multibyte character. Bytes that are not
 * valid UTF-8 anyway are left as they are.
 * @param {Buffer} buf
 */
export function utf8BoundaryLength(buf) {
  let i = buf.length - 1
  let continuation = 0
  while (i >= 0 && continuation < 3 && (buf[i] & 0xc0) === 0x80) {
    i--
    continuation++
  }
  if (i < 0) return buf.length
  const lead = buf[i]
  const needed = lead >= 0xf0 && lead <= 0xf7 ? 4 : lead >= 0xe0 && lead <= 0xef ? 3 : lead >= 0xc0 && lead <= 0xdf ? 2 : 1
  return needed > continuation + 1 ? i : buf.length
}

/**
 * The content to return for the first `maxBytes` bytes of `buf`, redacted.
 *
 * Every line is classified before anything is cut: lines that end inside
 * `buf` on their full text, a last line that runs past the end of `buf` on
 * the `LOOKAHEAD_BYTES` (or more) read beyond the cut. So which lines are
 * redacted never depends on `maxBytes`, and a caller cannot recover a secret
 * by moving the cut. A redacted line is returned only as the whole marker
 * (or dropped, and still counted, when the marker does not fit); a clean
 * line may be cut at the cap, never inside a UTF-8 character. The content
 * never exceeds `maxBytes` bytes.
 *
 * @param {Buffer} buf bytes from offset 0, up to maxBytes + LOOKAHEAD_BYTES + 1
 * @param {number} maxBytes
 * @returns {{ text: string, bytes: number, redactedLines: number, cut: boolean }}
 */
export function redactedPrefix(buf, maxBytes) {
  const lines = []
  for (let start = 0; start < buf.length;) {
    const nl = buf.indexOf(0x0a, start)
    const end = nl === -1 ? buf.length : nl
    lines.push({ start, end, next: nl === -1 ? buf.length : nl + 1 })
    start = nl === -1 ? buf.length : nl + 1
  }
  const bodies = lines.map(l => {
    const text = buf.toString('utf8', l.start, l.end)
    return text.endsWith('\r') ? text.slice(0, -1) : text
  })
  const { redacted } = redactLines(bodies)

  const parts = []
  let bytes = 0
  let redactedLines = 0
  let cut = false
  for (let i = 0; i < lines.length && lines[i].start < maxBytes; i++) {
    const { start, next } = lines[i]
    const budget = maxBytes - bytes
    if (redacted[i]) {
      redactedLines++
      const hasNewline = next > lines[i].end
      const straddles = next > maxBytes
      const crlf = hasNewline && lines[i].end > start && buf[lines[i].end - 1] === 0x0d
      const marker = Buffer.from(REDACTED_LINE + (hasNewline && !straddles ? (crlf ? '\r\n' : '\n') : ''), 'utf8')
      if (marker.length > budget) {
        // No room for the marker: the line is dropped, and still counted.
        cut = true
        break
      }
      parts.push(marker)
      bytes += marker.length
      if (straddles) {
        cut = true
        break
      }
      continue
    }
    const rawEnd = Math.min(next, maxBytes, start + budget)
    let piece = buf.subarray(start, rawEnd)
    if (rawEnd < next) {
      piece = piece.subarray(0, utf8BoundaryLength(piece))
      parts.push(piece)
      bytes += piece.length
      cut = true
      break
    }
    parts.push(piece)
    bytes += piece.length
  }
  const text = Buffer.concat(parts).toString('utf8')
  return { text, bytes: Buffer.byteLength(text, 'utf8'), redactedLines, cut }
}

const InputSchema = z.object({
  site: z.string().min(1),
  path: z.string().min(1).max(MAX_PATH_LENGTH),
  maxBytes: z.number().int().min(1).default(DEFAULT_BYTES)
})

/**
 * Read the start of a regular file under the site's WordPress root. The path
 * is confined lexically and then canonically, and must pass the site's
 * allowlist and the built-in denylist both times (see src/ssh/confine.js and
 * src/policy/paths.js). At most `maxBytes` (hard cap MAX_BYTES) are
 * returned; credential lines are redacted on their whole text before the
 * content is cut (see redactedPrefix).
 *
 * @param {unknown} rawInput tool arguments
 * @param {{ timeoutMs?: number }} [options] test hook; the MCP server passes none
 */
export async function readFileHandler(rawInput, options = {}) {
  try {
    const input = InputSchema.parse(rawInput)
    const maxBytes = Math.min(input.maxBytes, MAX_BYTES)
    const site = lookupSite(input.site)
    const allow = relativePath => isAllowed(site.allow, relativePath)
    // Every check that needs no server runs before the connection is opened,
    // so a refusal never depends on the server being reachable.
    checkLexically(site.wordpressRoot, input.path, allow)

    const { buf, relativePath } = await withSftpSession(site.serverId, async session => {
      const opened = await openConfinedFile(session, site.wordpressRoot, input.path, allow)
      try {
        // The look-ahead lets the line at the cut be classified on its whole
        // text; one byte more tells a file of exactly that length from a longer one.
        const data = await opened.handle.read(0, maxBytes + LOOKAHEAD_BYTES + 1)
        return { buf: data, relativePath: opened.relativePath }
      } finally {
        await opened.handle.close().catch(() => {})
      }
    }, { timeoutMs: options.timeoutMs })

    // Lines are classified before the cut (see redactedPrefix); `bytes`
    // counts what is returned.
    const result = redactedPrefix(buf, maxBytes)
    return {
      site: input.site,
      path: relativePath,
      content: result.text,
      bytes: result.bytes,
      truncated: buf.length > maxBytes || result.cut,
      redactedLines: result.redactedLines,
      retrievedAt: new Date().toISOString()
    }
  } catch (err) {
    throw toToolError(err)
  }
}

export const readFileTool = {
  name: 'read_file',
  schema: {
    site: { type: 'string', description: 'Site domain, e.g. example.com' },
    path: { type: 'string', description: 'Path relative to the WordPress root, e.g. wp-content/plugins/example/readme.txt' },
    maxBytes: { type: 'number', description: `Max bytes to read (hard cap: ${MAX_BYTES})`, default: DEFAULT_BYTES }
  },
  handler: readFileHandler
}
