import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { z } from 'zod'
import { loadRegistry } from './config/servers.js'
import { readLogHandler } from './tools/read-log.js'
import { readFileHandler } from './tools/read-file.js'
import { closeAll } from './ssh/client.js'

loadRegistry()

const server = new McpServer({
  name: 'tenshi-mcp',
  version: '1.0.0'
})

server.tool(
  'read_log',
  'Tail lines from a WordPress log file (debug/error/access) on a configured server',
  {
    site: z.string().describe('Site domain, e.g. blueprintcoffee.com'),
    log: z.enum(['debug', 'access', 'error']).describe('Log type'),
    lines: z.number().int().min(1).max(500).default(50).describe('Number of lines to tail'),
    filter: z.string().optional().describe('Optional grep filter string')
  },
  async ({ site, log, lines, filter }) => {
    try {
      const result = await readLogHandler({ site, log, lines, filter })
      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }]
      }
    } catch (err) {
      return {
        content: [{ type: 'text', text: `Error: ${err.message}` }],
        isError: true
      }
    }
  }
)

server.tool(
  'read_file',
  'Read a file within the WordPress directory of a configured site',
  {
    site: z.string().describe('Site domain, e.g. blueprintcoffee.com'),
    path: z.string().describe('Relative path within WordPress root, e.g. wp-config.php'),
    maxBytes: z.number().int().min(1).max(51200).default(10000).describe('Max bytes to read')
  },
  async ({ site, path, maxBytes }) => {
    try {
      const result = await readFileHandler({ site, path, maxBytes })
      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }]
      }
    } catch (err) {
      return {
        content: [{ type: 'text', text: `Error: ${err.message}` }],
        isError: true
      }
    }
  }
)

const transport = new StdioServerTransport()
await server.connect(transport)

process.on('SIGINT', () => { closeAll(); process.exit(0) })
process.on('SIGTERM', () => { closeAll(); process.exit(0) })
