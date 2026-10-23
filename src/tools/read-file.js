import { z } from 'zod'
import { withSftpSession } from '../ssh/sftp.js'
import { openConfinedFile } from '../ssh/confine.js'
import { toToolError } from '../errors.js'
import { lookupSite } from './site.js'

export const MAX_BYTES = 51200
export const DEFAULT_BYTES = 10000
export const MAX_PATH_LENGTH = 1024

const InputSchema = z.object({
  site: z.string().min(1),
  path: z.string().min(1).max(MAX_PATH_LENGTH),
  maxBytes: z.number().int().min(1).default(DEFAULT_BYTES)
})

/**
 * Read the start of a regular file under the site's WordPress root. The path
 * is confined lexically and then canonically (see src/ssh/confine.js); at
 * most `maxBytes` (hard cap MAX_BYTES) are returned.
 *
 * @param {unknown} rawInput tool arguments
 * @param {{ timeoutMs?: number }} [options] test hook; the MCP server passes none
 */
export async function readFileHandler(rawInput, options = {}) {
  try {
    const input = InputSchema.parse(rawInput)
    const maxBytes = Math.min(input.maxBytes, MAX_BYTES)
    const site = lookupSite(input.site)

    const { buf, relativePath } = await withSftpSession(site.serverId, async session => {
      const opened = await openConfinedFile(session, site.wordpressRoot, input.path)
      try {
        // One byte past the cap tells a file of exactly maxBytes from a longer one.
        const data = await opened.handle.read(0, maxBytes + 1)
        return { buf: data, relativePath: opened.relativePath }
      } finally {
        await opened.handle.close().catch(() => {})
      }
    }, { timeoutMs: options.timeoutMs })

    const truncated = buf.length > maxBytes
    const content = buf.subarray(0, maxBytes)
    return {
      site: input.site,
      path: relativePath,
      content: content.toString('utf8'),
      bytes: content.length,
      truncated,
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
