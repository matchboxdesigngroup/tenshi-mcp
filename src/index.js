import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { z } from 'zod'
import { loadRegistry } from './config/servers.js'
import { readLogHandler, LOG_NAMES, MAX_LINES, MAX_FILTER_LENGTH } from './tools/read-log.js'
import { readFileHandler } from './tools/read-file.js'
import { closeAll } from './ssh/client.js'

loadRegistry()

const server = new McpServer({
  name: 'tenshi-mcp',
  version: '1.0.0'
})

server.tool(
  'read_log',
  'Return the last lines of a WordPress log (debug/error/access) for a configured site. Only the last 256 KB of the log are read and searched.',
  {
    site: z.string().describe('Site domain, e.g. example.com'),
    log: z.enum(LOG_NAMES).describe('Log type'),
    lines: z.number().int().min(1).max(MAX_LINES).default(50).describe('Number of lines to return from the end of the log'),
    filter: z.string().max(MAX_FILTER_LENGTH).optional().describe('Optional case-insensitive substring; every character is matched literally')
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
    site: z.string().describe('Site domain, e.g. example.com'),
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
