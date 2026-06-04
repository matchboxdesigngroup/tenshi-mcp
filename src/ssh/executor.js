import { getConnection } from './client.js'

const ALLOWED_COMMANDS = new Set(['tail', 'head', 'grep', 'cat', 'ls'])
const TIMEOUT_MS = 10000

function parseCommandBinary(cmd) {
  const parts = cmd.trim().split(/\s+/)
  return parts[0] || ''
}

export async function runCommand(serverId, command) {
  const binary = parseCommandBinary(command)
  if (!ALLOWED_COMMANDS.has(binary)) {
    throw new Error(`Command not allowed: ${binary || '(empty)'}`)
  }

  const ssh = await getConnection(serverId)

  const result = await Promise.race([
    ssh.execCommand(command),
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error(`Command timed out after ${TIMEOUT_MS}ms`)), TIMEOUT_MS)
    )
  ])

  return {
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
    exitCode: result.code ?? -1
  }
}
