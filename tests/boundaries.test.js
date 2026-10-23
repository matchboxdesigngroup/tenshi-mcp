import { describe, it, expect } from 'vitest'
import { readdirSync, readFileSync, existsSync } from 'fs'
import { join, relative, dirname } from 'path'
import { fileURLToPath } from 'url'

// Module boundaries of the SFTP layer: tools see only the read-only session
// facade, and only src/ssh/client.js touches the SSH library. The fake-server
// tests prove at runtime that no exec or shell request is sent; this file
// keeps the structure that makes that hold.

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..')
const srcDir = join(repoRoot, 'src')

function sourceFiles(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap(entry => {
    const full = join(dir, entry.name)
    if (entry.isDirectory()) return sourceFiles(full)
    return entry.name.endsWith('.js') ? [relative(repoRoot, full)] : []
  })
}

function importsOf(file) {
  const text = readFileSync(join(repoRoot, file), 'utf8')
  return [...text.matchAll(/^\s*import\s[^'"]*['"]([^'"]+)['"]/gm)].map(m => m[1])
}

const files = sourceFiles(srcDir)

describe('SFTP layer boundaries', () => {
  it('has no string command executor', () => {
    expect(existsSync(join(srcDir, 'ssh', 'executor.js'))).toBe(false)
  })

  it('imports node-ssh only in src/ssh/client.js and ssh2 nowhere', () => {
    const users = files.filter(f => importsOf(f).some(spec => spec === 'node-ssh' || spec.startsWith('node-ssh/')))
    expect(users).toEqual(['src/ssh/client.js'])
    const ssh2Users = files.filter(f => importsOf(f).some(spec => spec === 'ssh2' || spec.startsWith('ssh2/')))
    expect(ssh2Users).toEqual([])
  })

  it('lets only src/ssh/sftp.js use the connection pool for channels', () => {
    const users = files.filter(f => /\bopenSftpChannel\b/.test(readFileSync(join(repoRoot, f), 'utf8')))
    expect(users.sort()).toEqual(['src/ssh/client.js', 'src/ssh/sftp.js'])
  })

  it('keeps tools on the facade: no tool imports the SSH client or an SSH library', () => {
    const tools = files.filter(f => f.startsWith('src/tools/'))
    expect(tools.length).toBeGreaterThan(0)
    for (const tool of tools) {
      for (const spec of importsOf(tool)) {
        expect(spec, `${tool} imports ${spec}`).not.toMatch(/^(node-ssh|ssh2)(\/|$)|ssh\/client\.js$/)
      }
    }
  })

  it('exports nothing from src/ssh/client.js that returns the SSH connection', async () => {
    const client = await import('../src/ssh/client.js')
    expect(Object.keys(client).sort()).toEqual(['IDLE_MS', 'closeAll', 'hostVerifierFor', 'openSftpChannel'])
  })
})
