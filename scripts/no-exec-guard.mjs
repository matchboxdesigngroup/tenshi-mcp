#!/usr/bin/env node
// Never-exec guard (tenshi#20). Run by CI (`node scripts/no-exec-guard.mjs`)
// and by `npm test` (tests/no-exec-guard.test.js).
//
// The server must never start a remote command, a port forward or a local
// process: tools read over SFTP only. This script parses every file under
// src/ with acorn (an exact dev dependency) and fails when the code could
// reach a process, remote-command or forwarding API, load a module
// dynamically, open a network client, or generate code from a string. It is a
// regression guard for changes to this repository, not a sandbox for code that
// is already running in the process.
//
// Rules (rule id in brackets):
//   [file]      Every entry under src/ must be a directory or a regular .js
//               file (no symlinks, no other file types), and must parse as an
//               ES module. Anything else fails, so nothing is left unscanned.
//   [import]    Static imports and `export ... from` may name only a relative
//               .js file inside src/ that exists, or a module in
//               ALLOWED_IMPORTS, from a file that module lists (`fs` only in
//               the registry loader and the audit sink, `node-ssh` only in
//               src/ssh/client.js). Any other module (child_process, vm,
//               worker_threads, module, process, net, a new package, ...)
//               fails.
//   [dynamic-import]  Every `import()` expression fails.
//   [name]      FORBIDDEN_NAMES (and names starting with a FORBIDDEN_PREFIXES
//               entry), used anywhere as an identifier, property name, object
//               key, import or export name, or as an exact string or template
//               value (catches `x.exec`, `x['exec']`, `{ exec: run } = x`,
//               `mkdir(p, 'exec')`, `forwardOut`, `eval`, `Function`,
//               `.constructor`, `require`, `globalThis`, `fetch`, ...).
//               Two exact exceptions: a class `constructor() {}` method, and
//               a direct call `R.exec(...)` where R is provably a RegExp: a
//               regex literal, or a name bound exactly once in the file, by
//               `const NAME = /.../` or `const NAME = new RegExp(...)`, in a
//               file that does not rebind `RegExp`.
//   [reflection]  REFLECTION_NAMES (prototype-chain and property-descriptor
//               access) anywhere under src/: as identifiers, property names,
//               import or export names, and as strings or templates used as
//               a property key (`x['__proto__']`, `{ ['prototype']: v }`).
//               Elsewhere such a string cannot read a property by itself
//               (src/config/servers.js compares and has-checks '__proto__' to
//               refuse it as a site name).
//   [process]   `process` may appear only as `process.<name>` with a plain
//               (non-computed) name from PROCESS_MEMBERS, so neither
//               `process[x]` nor an alias of `process` can reach a module
//               loader or a native binding.
//   [ssh-computed]  In SSH_OBJECT_FILES (the files that hold the SSH
//               connection or the raw SFTP channel), every computed key that
//               is not a literal fails: member access, destructuring in every
//               binding form, object literals and class members.
//   [ssh-import]  SSH_OBJECT_FILES may import exactly the modules and names
//               in SSH_FILE_IMPORTS and re-export nothing, so an SSH object
//               cannot be handed to a new helper in another file.
//
// Residuals (not caught; README "Never-exec guard"): outside SSH_OBJECT_FILES
// a property name assembled at runtime and used as a computed key can reach
// any property of any object in scope, including the constructor of
// functions and so code generation; the guard does not prove the absence of
// such deliberately obfuscated code, review does. Also not seen: SSH objects
// passed to the functions SSH_OBJECT_FILES already import, code in allowed
// dependencies, and anything outside src/.
//
// EXEMPTIONS is empty and must stay empty unless a reviewed change adds an
// entry with a reason and a tracking issue; an unused exemption fails.
//
// Usage: node scripts/no-exec-guard.mjs [srcDir]
// Exit codes: 0 pass; 1 findings; 2 usage error, missing parser or internal
// error.

import { lstatSync, readdirSync, readFileSync, realpathSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Loaded here, not with a static import, so a missing parser is exit 2 with
// a message instead of a module-resolution crash.
let acorn = null;
try {
  acorn = await import('acorn');
} catch {
  acorn = null;
}
export const PARSER_AVAILABLE = acorn !== null;

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const SRC_DIR = path.join(ROOT, 'src');

const ANY = '*';
const FS_FILES = Object.freeze(['src/config/servers.js', 'src/audit/sink.js']);

/** Bare module specifiers src/ may import (exact match), and which files may import each. */
export const ALLOWED_IMPORTS = Object.freeze({
  'crypto': ANY, 'node:crypto': ANY,
  'os': ANY, 'node:os': ANY,
  'path': ANY, 'node:path': ANY,
  'fs': FS_FILES, 'node:fs': FS_FILES,
  'zod': ANY,
  '@modelcontextprotocol/sdk/server/mcp.js': ANY,
  '@modelcontextprotocol/sdk/server/stdio.js': ANY,
  '@modelcontextprotocol/sdk/types.js': ANY,
  'node-ssh': Object.freeze(['src/ssh/client.js']),
});

/** Files that hold the SSH connection or the raw SFTP channel. */
export const SSH_OBJECT_FILES = Object.freeze(['src/ssh/client.js', 'src/ssh/sftp.js']);

/** Exactly what each SSH file may import: specifier -> imported names. */
export const SSH_FILE_IMPORTS = Object.freeze({
  'src/ssh/client.js': Object.freeze({
    'node-ssh': ['NodeSSH'],
    'os': ['homedir'],
    '../config/servers.js': ['getServerConfig'],
    '../errors.js': ['ERROR_CODES', 'ToolError'],
    './host-key.js': ['createHostVerifier'],
  }),
  'src/ssh/sftp.js': Object.freeze({
    './client.js': ['openSftpChannel'],
    '../errors.js': ['ERROR_CODES', 'ToolError', 'toToolError'],
  }),
});

export const FORBIDDEN_NAMES = Object.freeze([
  // Local processes (child_process, cluster).
  'child_process', 'node:child_process',
  'exec', 'execSync', 'execFile', 'execFileSync', 'execCommand',
  'spawn', 'spawnSync', 'fork',
  // Remote commands, shells and subsystems (node-ssh, ssh2). `subsys` is
  // ssh2's generic subsystem request; SFTP goes through node-ssh's
  // requestSFTP, which does not use it.
  'shell', 'requestShell', 'withShell', 'subsys',
  // node-ssh methods that run a remote command when given a method argument,
  // or that transfer files.
  'mkdir', 'getFile', 'putFile', 'putFiles', 'putDirectory', 'getDirectory',
  // Port forwarding and other global requests (node-ssh, ssh2; ssh2's
  // openssh_* methods are matched by prefix).
  'forwardIn', 'forwardOut', 'unforwardIn', 'forwardInStreamLocal', 'forwardOutStreamLocal',
  // Module loading and native bindings.
  'require', 'createRequire', 'module', 'exports', 'mainModule',
  'getBuiltinModule', 'binding', '_linkedBinding', 'dlopen',
  // Code generation from strings, and ways to reach the global object.
  'eval', 'Function', 'constructor', 'globalThis', 'global', 'Reflect',
  // Network clients available as globals without an import.
  'fetch', 'WebSocket', 'XMLHttpRequest', 'EventSource',
]);
export const FORBIDDEN_PREFIXES = Object.freeze(['openssh_']);

/** Prototype-chain and property-descriptor access, refused in all of src/. */
export const REFLECTION_NAMES = Object.freeze([
  'prototype', '__proto__', 'getPrototypeOf', 'setPrototypeOf',
  'getOwnPropertyNames', 'getOwnPropertyDescriptor', 'getOwnPropertyDescriptors',
  'getOwnPropertySymbols', '__lookupGetter__', '__lookupSetter__',
  '__defineGetter__', '__defineSetter__',
]);

/** The only `process.<name>` members src/ may use. */
export const PROCESS_MEMBERS = Object.freeze(['env', 'exit', 'getuid', 'hrtime', 'on']);

/**
 * Exemptions: { file, rule, name, reason, issue }. Empty by default. Each
 * entry suppresses findings with exactly that file, rule and name; an entry
 * that matches nothing is itself a finding.
 */
export const EXEMPTIONS = Object.freeze([]);

const FORBIDDEN = new Set(FORBIDDEN_NAMES);
const REFLECTION = new Set(REFLECTION_NAMES);
const SKIP_KEYS = new Set(['type', 'start', 'end', 'loc', 'range', 'raw', 'regex', 'bigint']);
const isForbidden = name => FORBIDDEN.has(name) || FORBIDDEN_PREFIXES.some(p => name.startsWith(p));
const COMPUTED_KEY = { MemberExpression: 'property', Property: 'key', MethodDefinition: 'key', PropertyDefinition: 'key' };

function lineOf(code, offset) {
  let line = 1;
  for (let i = 0; i < offset && i < code.length; i++) if (code.charCodeAt(i) === 10) line++;
  return line;
}

/** Visit every node with its parent and the key it hangs from. */
function walk(node, visit, parent = null, key = null) {
  if (!node || typeof node.type !== 'string') return;
  visit(node, parent, key);
  for (const k of Object.keys(node)) {
    if (SKIP_KEYS.has(k)) continue;
    const child = node[k];
    if (Array.isArray(child)) {
      for (const c of child) if (c && typeof c.type === 'string') walk(c, visit, node, k);
    } else if (child && typeof child.type === 'string') {
      walk(child, visit, node, k);
    }
  }
}

/** Binding identifiers introduced by a pattern. */
function patternNames(p, out) {
  if (!p) return out;
  switch (p.type) {
    case 'Identifier': out.push(p.name); break;
    case 'ObjectPattern': for (const prop of p.properties) patternNames(prop.type === 'RestElement' ? prop.argument : prop.value, out); break;
    case 'ArrayPattern': for (const el of p.elements) patternNames(el, out); break;
    case 'AssignmentPattern': patternNames(p.left, out); break;
    case 'RestElement': patternNames(p.argument, out); break;
    default: break;
  }
  return out;
}

/**
 * Names bound exactly once in the file, by `const NAME = /regex/`. A name
 * declared anywhere else in the file (parameter, other declaration, import,
 * function or class name, catch parameter) is not proven, whatever its scope.
 */
function provenRegexNames(ast) {
  const count = new Map();
  const regexConst = new Set();
  const add = name => count.set(name, (count.get(name) ?? 0) + 1);
  walk(ast, (node, parent) => {
    switch (node.type) {
      case 'VariableDeclarator':
        for (const n of patternNames(node.id, [])) add(n);
        if (parent?.kind === 'const' && node.id.type === 'Identifier' && isRegexValue(node.init)) {
          regexConst.add(node.id.name);
        }
        break;
      case 'FunctionDeclaration':
      case 'FunctionExpression':
      case 'ArrowFunctionExpression':
        if (node.id) add(node.id.name);
        for (const param of node.params) for (const n of patternNames(param, [])) add(n);
        break;
      case 'ClassDeclaration':
      case 'ClassExpression':
        if (node.id) add(node.id.name);
        break;
      case 'CatchClause':
        for (const n of patternNames(node.param, [])) add(n);
        break;
      case 'ImportSpecifier':
      case 'ImportDefaultSpecifier':
      case 'ImportNamespaceSpecifier':
        add(node.local.name);
        break;
      default: break;
    }
  });
  // `new RegExp(...)` proves a RegExp only while the file does not rebind RegExp.
  if (count.has('RegExp')) return new Set();
  return new Set([...regexConst].filter(name => count.get(name) === 1));
}

/** A regex literal, or `new RegExp(...)`. */
function isRegexValue(node) {
  if (node?.type === 'Literal' && node.regex) return true;
  return node?.type === 'NewExpression' && node.callee.type === 'Identifier' && node.callee.name === 'RegExp';
}

function isRegexReceiver(object, proven) {
  if (object.type === 'Literal' && object.regex) return true;
  return object.type === 'Identifier' && proven.has(object.name);
}

/** True when a string or template node sits where it names a property. */
function isKeyPosition(parent, key) {
  if (!parent) return false;
  if (parent.type === 'MemberExpression') return key === 'property';
  return (parent.type === 'Property' || parent.type === 'MethodDefinition' || parent.type === 'PropertyDefinition') && key === 'key';
}

function checkSpecifier(spec, file, filePath, srcDir) {
  if (typeof spec !== 'string') return 'non-string module specifier';
  if (spec.startsWith('./') || spec.startsWith('../')) {
    if (!filePath) return null;
    const target = path.resolve(path.dirname(filePath), spec);
    const rel = path.relative(srcDir, target);
    if (rel.startsWith('..') || path.isAbsolute(rel)) return `relative import outside src/: ${spec}`;
    if (!target.endsWith('.js')) return `relative import of a non-.js file: ${spec}`;
    try {
      if (!lstatSync(target).isFile()) return `relative import is not a regular file: ${spec}`;
    } catch {
      return `relative import of a missing file: ${spec}`;
    }
    return null;
  }
  if (!Object.hasOwn(ALLOWED_IMPORTS, spec)) return `module not in ALLOWED_IMPORTS: ${spec}`;
  const files = ALLOWED_IMPORTS[spec];
  if (files !== ANY && !files.includes(file)) return `${spec} may be imported only by ${files.join(', ')}`;
  return null;
}

/** Imported names of an import declaration: `default`, `*` or the exported name. */
function importedNames(node) {
  return node.specifiers.map(s => {
    if (s.type === 'ImportDefaultSpecifier') return 'default';
    if (s.type === 'ImportNamespaceSpecifier') return '*';
    return s.imported.type === 'Literal' ? String(s.imported.value) : s.imported.name;
  });
}

function checkSshImport(node, file, report) {
  const allowed = SSH_FILE_IMPORTS[file];
  const spec = String(node.source.value);
  if (node.type !== 'ImportDeclaration') {
    report(node, 'ssh-import', spec, 'a file that holds SSH objects re-exports nothing');
    return;
  }
  if (!Object.hasOwn(allowed, spec)) {
    report(node, 'ssh-import', spec, 'import not in SSH_FILE_IMPORTS');
    return;
  }
  for (const name of importedNames(node)) {
    if (!allowed[spec].includes(name)) report(node, 'ssh-import', `${spec}:${name}`, 'imported name not in SSH_FILE_IMPORTS');
  }
}

/**
 * Check one source text. `file` is the path as `src/...` (forward slashes);
 * it selects the per-file rules. `filePath`, when given, is the absolute path
 * used to resolve relative imports, which must stay inside `srcDir`.
 *
 * @param {string} code
 * @param {{ file: string, filePath?: string, srcDir?: string }} options
 * @returns {{ file: string, line: number, rule: string, name: string, detail: string }[]}
 */
export function checkSource(code, { file, filePath, srcDir = SRC_DIR } = {}) {
  if (!acorn) throw new Error('parser not available: acorn is not installed (run npm ci)');
  const findings = [];
  const report = (node, rule, name, detail) => findings.push({ file, line: lineOf(code, node?.start ?? 0), rule, name, detail });

  let ast;
  try {
    ast = acorn.parse(code, { ecmaVersion: 'latest', sourceType: 'module', allowHashBang: true });
  } catch (err) {
    report(null, 'file', 'parse', `does not parse as an ES module: ${err.message}`);
    return findings;
  }

  const sshObjectFile = SSH_OBJECT_FILES.includes(file);
  const proven = provenRegexNames(ast);
  // Member expressions that are the callee of a call: `R.exec(...)` is exempt,
  // `R.exec = f` or `const f = R.exec` is not.
  const calledDirectly = new Set();
  walk(ast, node => { if (node.type === 'CallExpression' && node.callee.type === 'MemberExpression') calledDirectly.add(node.callee); });

  const checkName = (name, node, parent, key, context, asKey = true) => {
    if (REFLECTION.has(name) && asKey) report(node, 'reflection', name, `reflection name in ${context}`);
    if (!isForbidden(name)) return;
    if (name === 'constructor' && parent?.type === 'MethodDefinition' && parent.kind === 'constructor' && key === 'key') return;
    if (name === 'exec' && parent?.type === 'MemberExpression' && key === 'property' && !parent.computed &&
        isRegexReceiver(parent.object, proven) && calledDirectly.has(parent)) return;
    report(node, 'name', name, `forbidden name in ${context}`);
  };

  walk(ast, (node, parent, key) => {
    const computedKey = COMPUTED_KEY[node.type];
    if (sshObjectFile && computedKey && node.computed && node[computedKey].type !== 'Literal') {
      report(node, 'ssh-computed', 'computed', `computed key (${node.type}) in a file that holds SSH objects`);
    }
    switch (node.type) {
      case 'ImportDeclaration':
      case 'ExportNamedDeclaration':
      case 'ExportAllDeclaration': {
        if (!node.source) break;
        const problem = checkSpecifier(node.source.value, file, filePath, srcDir);
        if (problem) report(node, 'import', String(node.source.value), problem);
        if (sshObjectFile) checkSshImport(node, file, report);
        break;
      }
      case 'ImportExpression':
        report(node, 'dynamic-import', 'import()', 'dynamic import');
        break;
      case 'Identifier':
        checkName(node.name, node, parent, key, 'identifier');
        if (node.name === 'process') {
          const allowed = parent?.type === 'MemberExpression' && key === 'object' && !parent.computed &&
            parent.property.type === 'Identifier' && PROCESS_MEMBERS.includes(parent.property.name);
          if (!allowed) report(node, 'process', 'process', 'process used other than as process.<allowed member>');
        }
        break;
      case 'PrivateIdentifier':
        checkName(node.name, node, parent, key, 'private name');
        break;
      case 'Literal':
        if (typeof node.value === 'string') {
          // The module specifier of an import is checked by the import rules.
          if (key === 'source' && (parent?.type === 'ImportDeclaration' || parent?.type === 'ExportNamedDeclaration' || parent?.type === 'ExportAllDeclaration')) break;
          checkName(node.value, node, parent, key, 'string', isKeyPosition(parent, key));
        }
        break;
      case 'TemplateLiteral':
        for (const q of node.quasis) checkName(q.value.cooked ?? q.value.raw, q, node, 'quasis', 'template', node.expressions.length === 0 && isKeyPosition(parent, key));
        break;
      default: break;
    }
  });
  return findings;
}

/** Every entry under `dir`: regular .js files to check, and anything else as a finding. */
function collect(srcDir, dir, files, findings) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    const rel = ['src', ...path.relative(srcDir, full).split(path.sep)].join('/');
    if (entry.isDirectory()) collect(srcDir, full, files, findings);
    else if (entry.isFile() && entry.name.endsWith('.js')) files.push({ full, rel });
    else findings.push({ file: rel, line: 0, rule: 'file', name: 'type', detail: 'not a regular .js file or directory (the guard cannot check it)' });
  }
}

/**
 * Check every file under `srcDir`.
 * @param {string} [srcDir]
 * @param {{ exemptions?: readonly { file: string, rule: string, name: string, reason: string, issue: string }[] }} [options]
 */
export function checkTree(srcDir = SRC_DIR, { exemptions = EXEMPTIONS } = {}) {
  const files = [];
  const findings = [];
  collect(srcDir, srcDir, files, findings);
  if (files.length === 0) findings.push({ file: 'src', line: 0, rule: 'file', name: 'empty', detail: 'no .js files found' });
  for (const { full, rel } of files) findings.push(...checkSource(readFileSync(full, 'utf8'), { file: rel, filePath: full, srcDir }));

  const used = new Set();
  const kept = findings.filter(f => {
    const i = exemptions.findIndex(e => e.file === f.file && e.rule === f.rule && e.name === f.name);
    if (i === -1) return true;
    used.add(i);
    return false;
  });
  exemptions.forEach((e, i) => {
    if (!e.reason || !e.issue) kept.push({ file: e.file, line: 0, rule: 'exemption', name: e.name, detail: 'exemption without reason or issue' });
    else if (!used.has(i)) kept.push({ file: e.file, line: 0, rule: 'exemption', name: e.name, detail: 'unused exemption' });
  });
  return { files: files.map(f => f.rel), findings: kept };
}

function main(argv) {
  if (argv.length > 1 || (argv[0] ?? '').startsWith('-')) {
    console.error('Usage: node scripts/no-exec-guard.mjs [srcDir]');
    return 2;
  }
  if (!acorn) {
    console.error('Never-exec guard error: parser not available: acorn is not installed (run npm ci).');
    return 2;
  }
  const srcDir = argv[0] ? path.resolve(argv[0]) : SRC_DIR;
  const { files, findings } = checkTree(srcDir);
  for (const f of findings) console.error(`${f.file}:${f.line} [${f.rule}] ${f.name}: ${f.detail}`);
  if (findings.length > 0) {
    console.error(`Never-exec guard failed: ${findings.length} finding(s) in ${files.length} file(s).`);
    return 1;
  }
  console.log(`Never-exec guard passed: ${files.length} file(s) under src/, no findings.`);
  return 0;
}

// Run when this file is the entry point, also when invoked through a symlink
// (compared by real path, so a symlinked invocation never exits 0 unchecked).
function isEntryPoint() {
  if (!process.argv[1]) return false;
  try {
    return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (isEntryPoint()) {
  try {
    process.exitCode = main(process.argv.slice(2));
  } catch (err) {
    console.error(`Never-exec guard error: ${err.message}`);
    process.exitCode = 2;
  }
}
