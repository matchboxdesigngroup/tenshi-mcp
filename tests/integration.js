/**
 * Manual integration test — requires a real servers.json with valid SSH credentials.
 * Usage: node tests/integration.js <serverId> <siteDomain>
 * Example: node tests/integration.js blueprintcoffee blueprintcoffee.com
 */

import { loadRegistry } from '../src/config/servers.js'
import { readLogHandler } from '../src/tools/read-log.js'
import { readFileHandler } from '../src/tools/read-file.js'
import { closeAll } from '../src/ssh/client.js'

const [serverId, site] = process.argv.slice(2)

if (!serverId || !site) {
  console.error('Usage: node tests/integration.js <serverId> <siteDomain>')
  process.exit(1)
}

loadRegistry()

async function run() {
  console.log('\n--- read_log: error (last 20 lines) ---')
  try {
    const r1 = await readLogHandler({ site, log: 'error', lines: 20 })
    console.log('resolvedPath:', r1.resolvedPath)
    console.log('lineCount:', r1.lineCount)
    console.log('content preview:', r1.content.slice(0, 300))
  } catch (e) {
    console.error('read_log error:', e.message)
  }

  console.log('\n--- read_log: debug (last 10 lines, filter: fatal) ---')
  try {
    const r2 = await readLogHandler({ site, log: 'debug', lines: 10, filter: 'fatal' })
    console.log('resolvedPath:', r2.resolvedPath)
    console.log('content:', r2.content || '(no matches)')
  } catch (e) {
    console.error('read_log error:', e.message)
  }

  console.log('\n--- read_file: wp-config.php (first 500 bytes) ---')
  try {
    const r3 = await readFileHandler({ site, path: 'wp-config.php', maxBytes: 500 })
    console.log('resolvedPath:', r3.resolvedPath)
    console.log('truncated:', r3.truncated)
    console.log('content preview:', r3.content.slice(0, 200))
  } catch (e) {
    console.error('read_file error:', e.message)
  }

  console.log('\n--- read_file: path traversal attempt (should fail) ---')
  try {
    await readFileHandler({ site, path: '../../etc/passwd', maxBytes: 100 })
    console.error('ERROR: traversal was not blocked!')
  } catch (e) {
    console.log('Traversal correctly blocked:', e.message)
  }
}

run().finally(() => closeAll())
