import { z } from 'zod'
import { runCommand } from '../ssh/executor.js'
import { resolveServerForSite } from '../config/servers.js'

const MAX_LINES = 500

const InputSchema = z.object({
  site: z.string().min(1),
  log: z.enum(['debug', 'access', 'error']),
  lines: z.number().int().min(1).default(50),
  filter: z.string().optional()
})

function resolveLogPath(log, site, wordpressRoot, logDir) {
  switch (log) {
    case 'debug':
      return `${wordpressRoot}/wp-content/debug.log`
    case 'error':
      return `${logDir}/${site}.error.log`
    case 'access':
      return `${logDir}/${site}.access.log`
  }
}

export async function readLogHandler(rawInput) {
  const input = InputSchema.parse(rawInput)
  const lines = Math.min(input.lines, MAX_LINES)

  const { serverId, site: siteConfig } = resolveServerForSite(input.site)
  const logPath = resolveLogPath(input.log, input.site, siteConfig.wordpressRoot, siteConfig.logDir)

  const cmd = input.filter
    ? `tail -n ${lines} ${logPath} | grep -i "${input.filter.replace(/"/g, '\\"')}"`
    : `tail -n ${lines} ${logPath}`

  const { stdout, stderr } = await runCommand(serverId, cmd)

  return {
    site: input.site,
    log: input.log,
    resolvedPath: logPath,
    lineCount: lines,
    content: stdout || stderr,
    retrievedAt: new Date().toISOString()
  }
}

export const readLogTool = {
  name: 'read_log',
  schema: {
    site: { type: 'string', description: 'Site domain, e.g. example.com' },
    log: { type: 'string', enum: ['debug', 'access', 'error'], description: 'Log type' },
    lines: { type: 'number', description: 'Number of lines to tail (max 500)', default: 50 },
    filter: { type: 'string', description: 'Optional grep filter string' }
  },
  handler: readLogHandler
}
