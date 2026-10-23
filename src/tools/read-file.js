import { z } from 'zod'
import { resolve } from 'path'
import { runCommand } from '../ssh/executor.js'
import { resolveServerForSite } from '../config/servers.js'

const MAX_BYTES = 51200

const InputSchema = z.object({
  site: z.string().min(1),
  path: z.string().min(1),
  maxBytes: z.number().int().min(1).default(10000)
})

export async function readFileHandler(rawInput) {
  const input = InputSchema.parse(rawInput)
  const maxBytes = Math.min(input.maxBytes, MAX_BYTES)

  const { serverId, site: siteConfig } = resolveServerForSite(input.site)

  // Resolve and confine path — path.resolve() collapses ../ sequences
  const fullPath = resolve(siteConfig.wordpressRoot, input.path)
  if (!fullPath.startsWith(siteConfig.wordpressRoot + '/') && fullPath !== siteConfig.wordpressRoot) {
    throw new Error(`Path escapes WordPress root: ${input.path}`)
  }

  const { stdout, stderr, exitCode } = await runCommand(serverId, `head -c ${maxBytes} ${fullPath}`)

  const content = stdout || (exitCode !== 0 ? stderr : '')
  return {
    site: input.site,
    requestedPath: input.path,
    resolvedPath: fullPath,
    content,
    truncated: content.length >= maxBytes,
    retrievedAt: new Date().toISOString()
  }
}

export const readFileTool = {
  name: 'read_file',
  schema: {
    site: { type: 'string', description: 'Site domain, e.g. example.com' },
    path: { type: 'string', description: 'Relative path within WordPress root, e.g. wp-config.php' },
    maxBytes: { type: 'number', description: 'Max bytes to read (hard cap: 51200)', default: 10000 }
  },
  handler: readFileHandler
}
