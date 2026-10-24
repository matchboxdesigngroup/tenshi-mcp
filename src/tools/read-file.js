import { z } from 'zod'
import { withSftpSession } from '../ssh/sftp.js'
import { checkLexically, openConfinedFile } from '../ssh/confine.js'
import { isAllowed } from '../policy/paths.js'
import { redactText } from '../policy/redact.js'
import { toToolError } from '../errors.js'
import { lookupSite } from './site.js'

export const MAX_BYTES = 51200
export const DEFAULT_BYTES = 10000
export const MAX_PATH_LENGTH = 1024

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

const InputSchema = z.object({
  site: z.string().min(1),
  path: z.string().min(1).max(MAX_PATH_LENGTH),
  maxBytes: z.number().int().min(1).default(DEFAULT_BYTES)
})

/**
 * Read the start of a regular file under the site's WordPress root. The path
 * is confined lexically and then canonically, and must pass the site's
 * allowlist and the built-in denylist both times (see src/ssh/confine.js and
 * src/policy/paths.js). At most `maxBytes` (hard cap MAX_BYTES) are read, and
 * credential lines are redacted before the content is returned.
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
        // One byte past the cap tells a file of exactly maxBytes from a longer one.
        const data = await opened.handle.read(0, maxBytes + 1)
        return { buf: data, relativePath: opened.relativePath }
      } finally {
        await opened.handle.close().catch(() => {})
      }
    }, { timeoutMs: options.timeoutMs })

    const truncated = buf.length > maxBytes
    const capped = buf.subarray(0, maxBytes)
    // Only a cut made here can split a character; a file that itself ends
    // mid-sequence is returned as it is.
    const content = truncated ? capped.subarray(0, utf8BoundaryLength(capped)) : capped
    // Redaction runs on the cut text, so a credential line cut at the cap is
    // redacted like a complete one; `bytes` counts what is returned.
    const redacted = redactText(content.toString('utf8'))
    return {
      site: input.site,
      path: relativePath,
      content: redacted.text,
      bytes: Buffer.byteLength(redacted.text, 'utf8'),
      truncated,
      redactedLines: redacted.count,
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
