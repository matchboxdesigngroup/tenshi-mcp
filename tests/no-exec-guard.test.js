import { describe, it, expect, afterEach } from 'vitest'
import { spawnSync } from 'child_process'
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync, rmSync, copyFileSync } from 'fs'
import { createRequire } from 'module'
import { tmpdir } from 'os'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'
import { checkSource, checkTree, EXEMPTIONS, SRC_DIR, PARSER_AVAILABLE } from '../scripts/no-exec-guard.mjs'

const SCRIPT = join(dirname(fileURLToPath(import.meta.url)), '..', 'scripts', 'no-exec-guard.mjs')

// Static never-exec guard (tenshi#20): the real src/ passes with no
// exemptions, and every forbidden pattern below, including aliasing and
// obfuscation attempts, is reported. The runtime counterpart is
// tests/no-exec-runtime.test.js.

const TOOL = 'src/tools/example.js'
const CLIENT = 'src/ssh/client.js'
const SFTP = 'src/ssh/sftp.js'

function rules(code, file = TOOL) {
  return checkSource(code, { file }).map(f => `${f.rule}:${f.name}`)
}

describe('never-exec guard on src/', () => {
  it('passes on the real source tree', () => {
    const { files, findings } = checkTree(SRC_DIR)
    expect(findings).toEqual([])
    expect(files).toContain('src/tools/read-file.js')
    expect(files).toContain('src/tools/read-log.js')
    expect(files).toContain('src/ssh/client.js')
    expect(files).toContain('src/ssh/sftp.js')
  })

  it('has its parser installed as a dependency of this repository', () => {
    expect(PARSER_AVAILABLE).toBe(true)
  })

  it('ships with no exemptions', () => {
    expect(EXEMPTIONS).toEqual([])
    expect(Object.isFrozen(EXEMPTIONS)).toBe(true)
  })
})

// [code, file, expected finding (rule:name)]. Each row must produce that
// finding; other findings may be reported as well.
const FORBIDDEN = [
  // Local process APIs, every import form.
  ["import { exec } from 'child_process'", TOOL, 'import:child_process'],
  ["import { exec as run } from 'node:child_process'", TOOL, 'import:node:child_process'],
  ["import cp from 'node:child_process'", TOOL, 'import:node:child_process'],
  ["import * as cp from 'child_process'; cp.spawn('x')", TOOL, 'name:spawn'],
  ["export { fork } from 'child_process'", TOOL, 'import:child_process'],
  ["export * from 'node:child_process'", TOOL, 'import:node:child_process'],
  ["import cluster from 'node:cluster'", TOOL, 'import:node:cluster'],
  ["import { Worker } from 'node:worker_threads'", TOOL, 'import:node:worker_threads'],
  ["import vm from 'node:vm'", TOOL, 'import:node:vm'],
  ["import { createRequire } from 'node:module'", TOOL, 'import:node:module'],
  ["import process from 'node:process'", TOOL, 'import:node:process'],
  ["import { execa } from 'execa'", TOOL, 'import:execa'],
  ["import { Client } from 'ssh2'", CLIENT, 'import:ssh2'],
  ["import { NodeSSH } from 'node-ssh'", TOOL, 'import:node-ssh'],
  ["import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js'", TOOL, 'import:@modelcontextprotocol/sdk/client/stdio.js'],
  // Dynamic loading.
  ["const m = await import('child_process')", TOOL, 'dynamic-import:import()'],
  ["const m = await import(name)", TOOL, 'dynamic-import:import()'],
  ["const m = await import('./other.js')", TOOL, 'dynamic-import:import()'],
  ["const cp = require('child_process')", TOOL, 'name:require'],
  ["const r = createRequire(import.meta.url)", TOOL, 'name:createRequire'],
  ["const cp = process.getBuiltinModule('child_process')", TOOL, 'process:process'],
  ["process.binding('spawn_sync')", TOOL, 'process:process'],
  ["process.dlopen(m, f)", TOOL, 'process:process'],
  ["process.mainModule.require('x')", TOOL, 'process:process'],
  ["const k = 'getBuiltin' + 'Module'; process[k]('x')", TOOL, 'process:process'],
  ["const p = process; p.env", TOOL, 'process:process'],
  ["const { env } = process", TOOL, 'process:process'],
  ["globalThis.process.env", TOOL, 'name:globalThis'],
  ["global.process.env", TOOL, 'name:global'],
  // Code generation from strings.
  ["eval('1')", TOOL, 'name:eval'],
  ["(0, eval)('1')", TOOL, 'name:eval'],
  ["const e = eval; e('1')", TOOL, 'name:eval'],
  ["new Function('return 1')", TOOL, 'name:Function'],
  ["Function('return 1')()", TOOL, 'name:Function'],
  ["(() => {}).constructor('return 1')", TOOL, 'name:constructor'],
  ["(async () => {})['constructor']('return 1')", TOOL, 'name:constructor'],
  ["Reflect.construct(F, ['x'])", TOOL, 'name:Reflect'],
  // Remote commands (node-ssh, ssh2), every access form.
  ["ssh.exec('ls', [])", CLIENT, 'name:exec'],
  ["ssh.execCommand('ls')", CLIENT, 'name:execCommand'],
  ["ssh['execCommand']('ls')", CLIENT, 'name:execCommand'],
  ['ssh[`execCommand`]("ls")', CLIENT, 'name:execCommand'],
  ["const { execCommand } = ssh", CLIENT, 'name:execCommand'],
  ["const { execCommand: run } = ssh; run('ls')", CLIENT, 'name:execCommand'],
  ["const { ['exec']: run } = ssh.connection", CLIENT, 'name:exec'],
  ["ssh.requestShell()", CLIENT, 'name:requestShell'],
  ["ssh.withShell(cb)", CLIENT, 'name:withShell'],
  ["ssh.connection.shell(cb)", CLIENT, 'name:shell'],
  ["ssh.connection.exec('ls', cb)", CLIENT, 'name:exec'],
  ["ssh.connection.subsys('other', cb)", CLIENT, 'name:subsys'],
  ["ssh.connection.exec.call(ssh.connection, 'ls', cb)", CLIENT, 'name:exec'],
  ['ssh.\\u0065xecCommand("ls")', CLIENT, 'name:execCommand'],
  ["ssh['\\x65xecCommand']('ls')", CLIENT, 'name:execCommand'],
  ["ssh?.execCommand?.('ls')", CLIENT, 'name:execCommand'],
  ['ssh[String.raw`execCommand`]("ls")', CLIENT, 'name:execCommand'],
  ["ssh[String.fromCharCode(101, 120, 101, 99)]('ls')", CLIENT, 'ssh-computed:computed'],
  ["ssh.mkdir('/x', 'exec')", CLIENT, 'name:exec'],
  ["channel._client.exec('ls', cb)", 'src/ssh/sftp.js', 'name:exec'],
  ["const opts = { shell: true }", TOOL, 'name:shell'],
  ["class Runner { exec(cmd) { return cmd } }", TOOL, 'name:exec'],
  ["class Runner { #exec = 1 }", TOOL, 'name:exec'],
  ["export function spawn() {}", TOOL, 'name:spawn'],
  // The RegExp exception is narrow.
  ["const R = /x/; R.exec = ssh.run; R.exec('ls')", TOOL, 'name:exec'],
  ["const R = /x/; const run = R.exec; run('ls')", TOOL, 'name:exec'],
  ["const R = /x/; function f(R) { return R.exec('ls') }", TOOL, 'name:exec'],
  ["const R = /x/; let S = R; S.exec('ls')", TOOL, 'name:exec'],
  ["let R = /x/; R.exec('ls')", TOOL, 'name:exec'],
  ["const RegExp = Other; const R = new RegExp('x'); R.exec('ls')", TOOL, 'name:exec'],
  ["const R = /x/; R['exec']('ls')", TOOL, 'name:exec'],
  ["ssh.exec('ls')", TOOL, 'name:exec'],
  // Files that hold SSH objects: no runtime-built names, no reflection.
  ["const k = 'exe' + 'cCommand'; ssh[k]('ls')", CLIENT, 'ssh-computed:computed'],
  ["const proto = Object.getPrototypeOf(ssh)", CLIENT, 'reflection:getPrototypeOf'],
  ["Object.getOwnPropertyDescriptor(Object.getPrototypeOf(c), k).value", SFTP, 'reflection:getOwnPropertyDescriptor'],
  ["const P = NodeSSH.prototype", CLIENT, 'reflection:prototype'],
  ["ssh['__proto__']", CLIENT, 'reflection:__proto__'],
  // Computed keys in every binding and literal form, in both SSH files.
  ["const { [k]: run } = ssh", CLIENT, 'ssh-computed:computed'],
  ["const { [k]: run } = channel", SFTP, 'ssh-computed:computed'],
  ["function f({ [k]: run }) { return run }", CLIENT, 'ssh-computed:computed'],
  ["const f = ({ a: { [k]: run } }) => run", SFTP, 'ssh-computed:computed'],
  ["let run; ({ [k]: run } = ssh)", CLIENT, 'ssh-computed:computed'],
  ["for (const { [k]: run } of [ssh]) run()", CLIENT, 'ssh-computed:computed'],
  ["try { f() } catch ({ [k]: run }) { run() }", CLIENT, 'ssh-computed:computed'],
  ["const [{ [k]: run } = ssh] = []", SFTP, 'ssh-computed:computed'],
  ["const o = { [k]: 1 }", SFTP, 'ssh-computed:computed'],
  ["class A { [k]() {} }", CLIENT, 'ssh-computed:computed'],
  ["class A { static [k] = 1 }", CLIENT, 'ssh-computed:computed'],
  ["ssh?.[k]?.()", CLIENT, 'ssh-computed:computed'],
  // SSH files import exactly their pinned modules and names and re-export nothing.
  ["import { pick } from '../errors.js'", CLIENT, 'ssh-import:../errors.js:pick'],
  ["import { pick } from '../policy/paths.js'", CLIENT, 'ssh-import:../policy/paths.js'],
  ["import * as client from './client.js'", SFTP, 'ssh-import:./client.js:*'],
  ["import { closeAll } from './client.js'", SFTP, 'ssh-import:./client.js:closeAll'],
  ["export { openSftpChannel } from './client.js'", SFTP, 'ssh-import:./client.js'],
  ["export * from 'node-ssh'", CLIENT, 'ssh-import:node-ssh'],
  ["import { Client } from 'ssh2'", CLIENT, 'ssh-import:ssh2'],
  // Reflection anywhere in src/, not only in the SSH files.
  ["Object.getPrototypeOf(() => {})", TOOL, 'reflection:getPrototypeOf'],
  ["Object.getOwnPropertyDescriptors(f)", TOOL, 'reflection:getOwnPropertyDescriptors'],
  ["Object.getOwnPropertyNames(f)", TOOL, 'reflection:getOwnPropertyNames'],
  ["Object.getOwnPropertySymbols(f)", TOOL, 'reflection:getOwnPropertySymbols'],
  ["Object.setPrototypeOf(a, b)", TOOL, 'reflection:setPrototypeOf'],
  ["const p = f.__proto__", TOOL, 'reflection:__proto__'],
  ["const p = f['__proto__']", TOOL, 'reflection:__proto__'],
  ["const p = f[`__proto__`]", TOOL, 'reflection:__proto__'],
  ["const o = { '__proto__': f }", TOOL, 'reflection:__proto__'],
  ["const p = Object.prototype", TOOL, 'reflection:prototype'],
  ["const { prototype } = f", TOOL, 'reflection:prototype'],
  ["f.__lookupGetter__('x')", TOOL, 'reflection:__lookupGetter__'],
  ["f.__defineGetter__('x', g)", TOOL, 'reflection:__defineGetter__'],
  // Port forwarding, global requests and node-ssh methods with an exec mode.
  ["ssh.forwardOut('127.0.0.1', 0, 'example.com', 80)", CLIENT, 'name:forwardOut'],
  ["ssh.connection.forwardIn('127.0.0.1', 0, cb)", CLIENT, 'name:forwardIn'],
  ["ssh.connection.unforwardIn('127.0.0.1', 0, cb)", CLIENT, 'name:unforwardIn'],
  ["ssh.forwardInStreamLocal('/tmp/s', cb)", CLIENT, 'name:forwardInStreamLocal'],
  ["ssh.forwardOutStreamLocal('/tmp/s')", CLIENT, 'name:forwardOutStreamLocal'],
  ["ssh.connection.openssh_forwardOutStreamLocal('/tmp/s', cb)", CLIENT, 'name:openssh_forwardOutStreamLocal'],
  ["ssh.connection.openssh_noMoreSessions(cb)", CLIENT, 'name:openssh_noMoreSessions'],
  ["ssh.mkdir('/x', mode)", CLIENT, 'name:mkdir'],
  ["ssh.putFile('a', 'b')", CLIENT, 'name:putFile'],
  ["ssh.getDirectory('a', 'b')", CLIENT, 'name:getDirectory'],
  // fs only where it is needed; network clients that need no import.
  ["import fs from 'fs'", TOOL, 'import:fs'],
  ["import { writeFileSync } from 'node:fs'", 'src/ssh/confine.js', 'import:node:fs'],
  ["import { readFileSync } from 'fs'", CLIENT, 'import:fs'],
  ["await fetch('https://example.com')", TOOL, 'name:fetch'],
  ["new WebSocket('wss://example.com')", TOOL, 'name:WebSocket'],
  ["new XMLHttpRequest()", TOOL, 'name:XMLHttpRequest'],
  ["new EventSource('https://example.com')", TOOL, 'name:EventSource'],
  // Unparseable code fails closed.
  ['const = ;', TOOL, 'file:parse'],
  ['with (x) { y() }', TOOL, 'file:parse']
]

describe('never-exec guard: forbidden patterns', () => {
  it.each(FORBIDDEN)('reports %s (%s)', (code, file, expected) => {
    expect(rules(code, file)).toContain(expected)
  })
})

const ALLOWED = [
  ["const R = /^x/; R.exec('a')", TOOL],
  ["/^x/.exec('a')", TOOL],
  ["const R = new RegExp('x', 'i'); R.exec('a')", TOOL],
  ["class A extends Error { constructor(m) { super(m) } }", TOOL],
  ["const v = process.env.X; process.on('SIGTERM', () => process.exit(0))", TOOL],
  ["const x = lines[i] + map[key]", TOOL],
  ["import { z } from 'zod'; import path from 'node:path'", TOOL],
  ["import { NodeSSH } from 'node-ssh'; const s = new NodeSSH(); s.requestSFTP()", CLIENT],
  ["const message = 'no exec here'; const t = `shell ${x}`", TOOL],
  ["/** @returns {import('ssh2').Stats} */ function f() {}", TOOL],
  ["import { readFileSync } from 'fs'", 'src/config/servers.js'],
  ["import fs from 'node:fs'", 'src/audit/sink.js'],
  ["const ok = name !== '__proto__' && !(name in {}) && !Object.hasOwn(raw, '__proto__')", TOOL],
  ["import { openSftpChannel } from './client.js'", SFTP]
]

describe('never-exec guard: allowed patterns', () => {
  it.each(ALLOWED)('accepts %s (%s)', (code, file) => {
    expect(checkSource(code, { file })).toEqual([])
  })
})

describe('never-exec guard: tree checks fail closed', () => {
  let dir
  afterEach(() => { if (dir) rmSync(dir, { recursive: true, force: true }); dir = undefined })

  function tree(files) {
    dir = mkdtempSync(join(tmpdir(), 'tenshi-mcp-guard-'))
    const src = join(dir, 'src')
    mkdirSync(join(src, 'tools'), { recursive: true })
    for (const [name, content] of Object.entries(files)) writeFileSync(join(src, name), content)
    return src
  }

  const found = src => checkTree(src).findings.map(f => `${f.file} ${f.rule}:${f.name}`)

  it('passes a clean tree with a relative import inside src/', () => {
    const src = tree({ 'a.js': "import { b } from './tools/b.js'\n", 'tools/b.js': 'export const b = 1\n' })
    expect(checkTree(src).findings).toEqual([])
  })

  it('reports relative imports outside src/, of missing files and of non-.js files', () => {
    const src = tree({ 'a.js': "import x from '../outside.js'\nimport y from './missing.js'\nimport z from './data.json' with { type: 'json' }\n" })
    const f = checkTree(src).findings.filter(x => x.rule === 'import').map(x => x.detail)
    expect(f).toEqual([
      'relative import outside src/: ../outside.js',
      'relative import of a missing file: ./missing.js',
      'relative import of a non-.js file: ./data.json'
    ])
  })

  it('reports files it cannot check: other extensions and symlinks', () => {
    const src = tree({ 'a.js': 'export const a = 1\n', 'b.cjs': "require('child_process')\n", 'c.mjs': 'export {}\n' })
    symlinkSync(join(src, 'a.js'), join(src, 'tools', 'link.js'))
    expect(found(src)).toEqual(expect.arrayContaining(['src/b.cjs file:type', 'src/c.mjs file:type', 'src/tools/link.js file:type']))
  })

  it('reports an empty tree', () => {
    dir = mkdtempSync(join(tmpdir(), 'tenshi-mcp-guard-'))
    mkdirSync(join(dir, 'src'))
    expect(found(join(dir, 'src'))).toEqual(['src file:empty'])
  })

  it('applies an exemption only to its exact file, rule and name, and reports unused or unjustified ones', () => {
    const src = tree({ 'a.js': "const cp = require('x')\n" })
    const exemption = { file: 'src/a.js', rule: 'name', name: 'require', reason: 'test', issue: 'test' }
    expect(checkTree(src, { exemptions: [exemption] }).findings).toEqual([])
    const other = { ...exemption, file: 'src/b.js' }
    expect(checkTree(src, { exemptions: [other] }).findings.map(f => `${f.rule}:${f.detail}`))
      .toEqual(['name:forbidden name in identifier', 'exemption:unused exemption'])
    expect(checkTree(src, { exemptions: [{ ...exemption, reason: '' }] }).findings.map(f => f.detail))
      .toEqual(['exemption without reason or issue'])
  })
})

describe('never-exec guard: command line exit codes', () => {
  let dir
  afterEach(() => { if (dir) rmSync(dir, { recursive: true, force: true }); dir = undefined })

  const run = (args, script = SCRIPT) => spawnSync(process.execPath, [script, ...args], { encoding: 'utf8' })

  it('exits 0 on the real src/', () => {
    const r = run([])
    expect(r.status).toBe(0)
    expect(r.stdout).toMatch(/^Never-exec guard passed: \d+ file\(s\) under src\/, no findings\.\n$/)
  })

  it('exits 1 on a finding and names it', () => {
    dir = mkdtempSync(join(tmpdir(), 'tenshi-mcp-guard-'))
    mkdirSync(join(dir, 'src'))
    writeFileSync(join(dir, 'src', 'a.js'), "x.execCommand('ls')\n")
    const r = run([join(dir, 'src')])
    expect(r.status).toBe(1)
    expect(r.stderr).toContain('src/a.js:1 [name] execCommand')
    expect(r.stderr).toContain('Never-exec guard failed: 1 finding(s) in 1 file(s).')
  })

  it('checks when invoked through a symlink', () => {
    dir = mkdtempSync(join(tmpdir(), 'tenshi-mcp-guard-'))
    mkdirSync(join(dir, 'src'))
    writeFileSync(join(dir, 'src', 'a.js'), "x.execCommand('ls')\n")
    const link = join(dir, 'guard-link.mjs')
    symlinkSync(SCRIPT, link)
    expect(run([join(dir, 'src')], link).status).toBe(1)
  })

  it('exits 2 on bad arguments and on a missing directory', () => {
    expect(run(['a', 'b']).status).toBe(2)
    expect(run(['--fix']).status).toBe(2)
    const missing = run([join(tmpdir(), 'tenshi-mcp-guard-does-not-exist')])
    expect(missing.status).toBe(2)
    expect(missing.stderr).toMatch(/^Never-exec guard error: /)
  })

  it('exits 2 when the parser is not installed', () => {
    // A copy of the script outside the repository cannot resolve acorn.
    dir = mkdtempSync(join(tmpdir(), 'tenshi-mcp-guard-'))
    const copy = join(dir, 'no-exec-guard.mjs')
    copyFileSync(SCRIPT, copy)
    expect(() => createRequire(copy).resolve('acorn')).toThrow()
    const r = run([SRC_DIR], copy)
    expect(r.status).toBe(2)
    expect(r.stderr).toContain('parser not available')
  })
})
