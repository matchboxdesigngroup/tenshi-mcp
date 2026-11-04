import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js'
import { z } from 'zod'
import { boundedString, toolInputSchema } from './schema.js'
import { resolveServerForSite } from './config/servers.js'
import { readLogHandler, LOG_NAMES, MAX_LINES, MAX_FILTER_LENGTH } from './tools/read-log.js'
import { readFileHandler, MAX_BYTES, DEFAULT_BYTES, MAX_PATH_LENGTH } from './tools/read-file.js'
import { toToolError } from './errors.js'

/**
 * Argument kinds per tool for the audit log (see createAuditLog in
 * src/audit/log.js): free text and paths are recorded as length and keyed
 * hash only.
 */
export const AUDITED_TOOLS = Object.freeze({
  read_log: Object.freeze({ site: 'text', log: LOG_NAMES, lines: 'number', filter: 'text' }),
  read_file: Object.freeze({ site: 'text', path: 'path', maxBytes: 'number' })
})

/**
 * Registry ids for a site name the caller sent, or null when it is not a
 * registered site. No network activity.
 * @param {string} name
 */
export function resolveSiteIds(name) {
  try {
    const found = resolveServerForSite(name)
    return { site: name, server: found.serverId }
  } catch {
    return null
  }
}

/**
 * Tool failures reach the model as a fixed code and message only: never the
 * caller's input, a server path, remote error text or the audit reason.
 */
function errorResult(toolError) {
  return {
    content: [{ type: 'text', text: `Error: ${toolError.message}` }],
    isError: true
  }
}

/**
 * The MCP server with both tools, every `tools/call` request recorded by
 * `audit` (one record each, see src/audit/log.js). Throws if the audit
 * wrapper could not be installed, so the server never runs unaudited.
 * Connect only through the returned `connect`, which wraps the transport
 * so that requests the SDK refuses before the dispatcher are recorded too.
 *
 * @param {{ audit: ReturnType<typeof import('./audit/log.js').createAuditLog>, timeoutMs?: number }} options
 *   timeoutMs is a test hook passed to the handlers; src/index.js passes none
 */
export function createServer({ audit, timeoutMs }) {
  if (!audit || typeof audit.wrapCallHandler !== 'function' || typeof audit.report !== 'function' || typeof audit.wrapTransport !== 'function') {
    throw new Error('createServer requires an audit log')
  }
  const server = new McpServer({
    name: 'tenshi-mcp',
    version: '1.0.0'
  })

  // McpServer installs its tools/call dispatcher through the low-level
  // server's public setRequestHandler when the first tool is registered.
  // Wrapping it there puts the audit around everything the dispatcher
  // answers: unknown tools, SDK argument validation and every handler.
  const lowLevel = server.server
  const setRequestHandler = lowLevel.setRequestHandler.bind(lowLevel)
  lowLevel.setRequestHandler = (schema, handler) =>
    setRequestHandler(schema, schema === CallToolRequestSchema ? audit.wrapCallHandler(handler) : handler)

  /**
   * Register a tool whose arguments are the zod object `shape`, through
   * toolInputSchema (see src/schema.js). server.tool() accepts only a bare
   * shape, which cannot carry the schema metadata toolInputSchema adds.
   */
  function tool(name, description, shape, run, summarize) {
    return server.registerTool(name, {
      description,
      inputSchema: toolInputSchema(shape)
    }, async (args, extra) => {
      try {
        const result = await run(args)
        audit.report(extra, summarize(result))
        return {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }]
        }
      } catch (err) {
        const toolError = toToolError(err)
        audit.report(extra, { error: toolError })
        return errorResult(toolError)
      }
    })
  }

  tool(
    'read_log',
    'Return the last lines of a WordPress log (debug/error/access) for a configured site. Only the last 256 KB of the log are read and searched. Lines that look like credentials are replaced by a fixed marker before filtering.',
    {
      site: z.string().describe('Site domain, e.g. example.com'),
      log: z.enum(LOG_NAMES).describe('Log type'),
      lines: z.number().int().min(1).max(MAX_LINES).default(50).describe('Number of lines to return from the end of the log'),
      filter: boundedString({ max: MAX_FILTER_LENGTH }).optional().describe('Optional case-insensitive substring; every character is matched literally')
    },
    ({ site, log, lines, filter }) => readLogHandler({ site, log, lines, filter }, { timeoutMs }),
    result => ({
      redactedLines: result.redactedLines,
      truncated: result.truncated.window || result.truncated.bytes || result.truncated.longLines > 0,
      returnedLines: result.returnedLines
    })
  )

  tool(
    'read_file',
    'Read the start of a regular file under the WordPress root of a configured site. Only files whose extension and directory the site allows are served; configuration files with credentials, environment files, dumps, backups, keys and hidden files never are. Lines that look like credentials are replaced by a fixed marker.',
    {
      site: z.string().describe('Site domain, e.g. example.com'),
      path: boundedString({ max: MAX_PATH_LENGTH }).describe('Path relative to the WordPress root, e.g. wp-content/plugins/example/readme.txt'),
      maxBytes: z.number().int().min(1).max(MAX_BYTES).default(DEFAULT_BYTES).describe('Max bytes to read')
    },
    ({ site, path, maxBytes }) => readFileHandler({ site, path, maxBytes }, { timeoutMs }),
    result => ({ redactedLines: result.redactedLines, truncated: result.truncated })
  )

  lowLevel.setRequestHandler = setRequestHandler
  if (!audit.installed) throw new Error('audit log not installed on tools/call')
  return {
    /** @param {import('@modelcontextprotocol/sdk/shared/transport.js').Transport} transport */
    connect: transport => server.connect(audit.wrapTransport(transport)),
    close: () => server.close()
  }
}
