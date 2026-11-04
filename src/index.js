import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { loadRegistry } from './config/servers.js'
import { closeAll } from './ssh/client.js'
import { createAuditLog } from './audit/log.js'
import { openAuditSink, AuditConfigError } from './audit/sink.js'
import { createServer, AUDITED_TOOLS, resolveSiteIds } from './server.js'

/** Longest wait for queued audit records before exit. */
const EXIT_FLUSH_MS = 1000

loadRegistry()

let sink
try {
  ({ sink } = openAuditSink())
} catch (err) {
  // Fixed text naming the variable only, never its value.
  console.error(err instanceof AuditConfigError ? err.message : 'The audit log could not be opened; the server will not start.')
  process.exit(1)
}

const audit = createAuditLog({ sink, tools: AUDITED_TOOLS, resolveSite: resolveSiteIds })
const server = createServer({ audit })

const transport = new StdioServerTransport()
await server.connect(transport)

async function shutdown() {
  closeAll()
  await sink.flush(EXIT_FLUSH_MS)
  process.exit(0)
}

process.on('SIGINT', shutdown)
process.on('SIGTERM', shutdown)
