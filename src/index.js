import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { z } from 'zod'
import { boundedString, toolInputSchema } from './schema.js'
import { loadRegistry } from './config/servers.js'
import { readLogHandler, LOG_NAMES, MAX_LINES, MAX_FILTER_LENGTH } from './tools/read-log.js'
import { readFileHandler, MAX_BYTES, DEFAULT_BYTES, MAX_PATH_LENGTH } from './tools/read-file.js'
import { closeAll } from './ssh/client.js'
import { toToolError } from './errors.js'

loadRegistry()

/**
 * Tool failures reach the model as a fixed code and message only: never the
 * caller's input, a server path or remote error text.
 */
function errorResult(err) {
  return {
    content: [{ type: 'text', text: `Error: ${toToolError(err).message}` }],
    isError: true
  }
}

const server = new McpServer({
  name: 'tenshi-mcp',
  version: '1.0.0'
})

/**
 * Register a tool whose arguments are the zod object `shape`, through
 * toolInputSchema (see src/schema.js). server.tool() accepts only a bare
 * shape, which cannot carry the schema metadata toolInputSchema adds.
 */
function tool(name, description, shape, handler) {
  return server.registerTool(name, {
    description,
    inputSchema: toolInputSchema(shape)
  }, handler)
}

tool(
  'read_log',
  'Return the last lines of a WordPress log (debug/error/access) for a configured site. Only the last 256 KB of the log are read and searched.',
  {
    site: z.string().describe('Site domain, e.g. example.com'),
    log: z.enum(LOG_NAMES).describe('Log type'),
    lines: z.number().int().min(1).max(MAX_LINES).default(50).describe('Number of lines to return from the end of the log'),
    filter: boundedString({ max: MAX_FILTER_LENGTH }).optional().describe('Optional case-insensitive substring; every character is matched literally')
  },
  async ({ site, log, lines, filter }) => {
    try {
      const result = await readLogHandler({ site, log, lines, filter })
      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }]
      }
    } catch (err) {
      return errorResult(err)
    }
  }
)

tool(
  'read_file',
  'Read the start of a regular file under the WordPress root of a configured site',
  {
    site: z.string().describe('Site domain, e.g. example.com'),
    path: boundedString({ max: MAX_PATH_LENGTH }).describe('Path relative to the WordPress root, e.g. wp-content/plugins/example/readme.txt'),
    maxBytes: z.number().int().min(1).max(MAX_BYTES).default(DEFAULT_BYTES).describe('Max bytes to read')
  },
  async ({ site, path, maxBytes }) => {
    try {
      const result = await readFileHandler({ site, path, maxBytes })
      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }]
      }
    } catch (err) {
      return errorResult(err)
    }
  }
)

const transport = new StdioServerTransport()
await server.connect(transport)

process.on('SIGINT', () => { closeAll(); process.exit(0) })
process.on('SIGTERM', () => { closeAll(); process.exit(0) })
