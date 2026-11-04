#!/usr/bin/env node
// Never-exec guard (tenshi#20). Run by CI (`node scripts/no-exec-guard.mjs`)
// and by `npm test` (tests/no-exec-guard.test.js).
//
// The server must never start a remote command or a local process: tools read
// over SFTP only. This script parses every file under src/ with acorn (already
// in the dependency tree through vitest; no new dependency) and fails when the
// code could reach a process or remote-command API, load a module dynamically,
// or generate code from a string. It is a regression guard for changes to this
// repository, not a sandbox for code that is already running in the process.
//
// Rules (rule id in brackets):
//   [file]      Every entry under src/ must be a directory or a regular .js
//               file (no symlinks, no other file types), and must parse as an
//               ES module. Anything else fails, so nothing is left unscanned.
//   [import]    Static imports and `export ... from` may name only a relative
//               .js file inside src/ that exists, or a module in
//               ALLOWED_IMPORTS. `node-ssh` only from SSH_LIBRARY_FILES. Any
//               other module (child_process, vm, worker_threads, module,
//               process, a new package that wraps them, ...) fails.
//   [dynamic-import]  Every `import()` expression fails.
//   [name]      FORBIDDEN_NAMES, used anywhere as an identifier, property
//               name, object key, import or export name, or as an exact
//               string or template value (catches `x.exec`, `x['exec']`,
//               `{ exec: run } = x`, `mkdir(p, 'exec')`, `eval`, `Function`,
//               `.constructor`, `require`, `globalThis`, ...).
//               Two exact exceptions: a class `constructor() {}` method, and
//               a direct call `R.exec(...)` where R is provably a RegExp: a
//               regex literal, or a name bound exactly once in the file, by
//               `const NAME = /.../` or `const NAME = new RegExp(...)`, in a
//               file that does not rebind `RegExp`.
//   [process]   `process` may appear only as `process.<name>` with a plain
//               (non-computed) name from PROCESS_MEMBERS, so neither
//               `process[x]` nor an alias of `process` can reach a module
//               loader or a native binding.
//   [ssh-computed]  In SSH_OBJECT_FILES (the files that hold the SSH
//               connection or the raw SFTP channel), member access with a
//               computed key that is not a literal fails, and so do the
//               reflection names in SSH_REFLECTION_NAMES, so a method name
//               built at runtime cannot be looked up on those objects.
//
// Residuals (not caught; see the README "Never-exec guard"): a property name
// built at runtime and looked up with a computed key in a file outside
// SSH_OBJECT_FILES, on an object that has a dangerous method (no such object
// is reachable there: tools get only the frozen SFTP facade, and the
// constructors of functions are reachable only through such a lookup); code in
// an allowed dependency; and anything that does not go through src/.
//
// EXEMPTIONS is empty and must stay empty unless a reviewed change adds an
// entry with a reason and a tracking issue; an unused exemption fails.
//
// Usage: node scripts/no-exec-guard.mjs [srcDir]
// Exit codes: 0 pass; 1 findings; 2 usage or internal error.

import { parse } from 'acorn';
import { lstatSync, readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const SRC_DIR = path.join(ROOT, 'src');

/** Bare module specifiers src/ may import. Exact match only. */
export const ALLOWED_IMPORTS = Object.freeze([
  'crypto', 'node:crypto',
  'fs', 'node:fs',
  'os', 'node:os',
  'path', 'node:path',
  'zod',
  '@modelcontextprotocol/sdk/server/mcp.js',
  '@modelcontextprotocol/sdk/server/stdio.js',
  '@modelcontextprotocol/sdk/types.js',
  'node-ssh',
]);

/** Files (relative to the repo root) that may import the SSH library. */
export const SSH_LIBRARY_FILES = Object.freeze(['src/ssh/client.js']);
/** Modules only SSH_LIBRARY_FILES may import. */
export const SSH_LIBRARY_MODULES = Object.freeze(['node-ssh']);

/** Files that hold the SSH connection or the raw SFTP channel. */
export const SSH_OBJECT_FILES = Object.freeze(['src/ssh/client.js', 'src/ssh/sftp.js']);

export const FORBIDDEN_NAMES = Object.freeze([
  // Local processes (child_process, cluster) and remote commands (node-ssh,
  // ssh2). `subsys` is ssh2's generic subsystem request; SFTP goes through
  // node-ssh's requestSFTP, which does not use it.
  'child_process', 'node:child_process',
  'exec', 'execSync', 'execFile', 'execFileSync', 'execCommand',
  'spawn', 'spawnSync', 'fork',
  'shell', 'requestShell', 'withShell', 'subsys',
  // Module loading and native bindings.
  'require', 'createRequire', 'module', 'exports', 'mainModule',
  'getBuiltinModule', 'binding', '_linkedBinding', 'dlopen',
  // Code generation from strings, and ways to reach the global object.
  'eval', 'Function', 'constructor', 'globalThis', 'global', 'Reflect',
]);

/** The only `process.<name>` members src/ may use. */
export const PROCESS_MEMBERS = Object.freeze(['env', 'exit', 'getuid', 'hrtime', 'on']);

export const SSH_REFLECTION_NAMES = Object.freeze([
  'getPrototypeOf', 'getOwnPropertyNames', 'getOwnPropertyDescriptor',
  'getOwnPropertyDescriptors', 'getOwnPropertySymbols', '__proto__',
  '__lookupGetter__', '__lookupSetter__', 'prototype',
]);

/**
 * Exemptions: { file, rule, name, reason, issue }. Empty by default. Each
 * entry suppresses findings with exactly that file, rule and name; an entry
 * that matches nothing is itself a finding.
 */
export const EXEMPTIONS = Object.freeze([]);

const FORBIDDEN = new Set(FORBIDDEN_NAMES);
const SKIP_KEYS = new Set(['type', 'start', 'end', 'loc', 'range', 'raw', 'regex', 'bigint']);

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
  if (!ALLOWED_IMPORTS.includes(spec)) return `module not in ALLOWED_IMPORTS: ${spec}`;
  if (SSH_LIBRARY_MODULES.includes(spec) && !SSH_LIBRARY_FILES.includes(file)) return `${spec} imported outside ${SSH_LIBRARY_FILES.join(', ')}`;
  return null;
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
  const findings = [];
  const report = (node, rule, name, detail) => findings.push({ file, line: lineOf(code, node?.start ?? 0), rule, name, detail });

  let ast;
  try {
    ast = parse(code, { ecmaVersion: 'latest', sourceType: 'module', allowHashBang: true });
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

  const checkName = (name, node, parent, key, context) => {
    if (!FORBIDDEN.has(name)) return;
    if (name === 'constructor' && parent?.type === 'MethodDefinition' && parent.kind === 'constructor' && key === 'key') return;
    if (name === 'exec' && parent?.type === 'MemberExpression' && key === 'property' && !parent.computed &&
        isRegexReceiver(parent.object, proven) && calledDirectly.has(parent)) return;
    report(node, 'name', name, `forbidden name in ${context}`);
  };

  walk(ast, (node, parent, key) => {
    switch (node.type) {
      case 'ImportDeclaration':
      case 'ExportNamedDeclaration':
      case 'ExportAllDeclaration': {
        if (!node.source) break;
        const problem = checkSpecifier(node.source.value, file, filePath, srcDir);
        if (problem) report(node, 'import', String(node.source.value), problem);
        break;
      }
      case 'ImportExpression':
        report(node, 'dynamic-import', 'import()', 'dynamic import');
        break;
      case 'Identifier': {
        // The module specifier string of an import is checked by the import rule.
        checkName(node.name, node, parent, key, 'identifier');
        if (node.name === 'process') {
          const allowed = parent?.type === 'MemberExpression' && key === 'object' && !parent.computed &&
            parent.property.type === 'Identifier' && PROCESS_MEMBERS.includes(parent.property.name);
          if (!allowed) report(node, 'process', 'process', 'process used other than as process.<allowed member>');
        }
        if (sshObjectFile && SSH_REFLECTION_NAMES.includes(node.name)) report(node, 'ssh-computed', node.name, 'reflection in a file that holds SSH objects');
        break;
      }
      case 'PrivateIdentifier':
        checkName(node.name, node, parent, key, 'private name');
        break;
      case 'Literal':
        if (typeof node.value === 'string') {
          if (key === 'source' && (parent?.type === 'ImportDeclaration' || parent?.type === 'ExportNamedDeclaration' || parent?.type === 'ExportAllDeclaration')) break;
          checkName(node.value, node, parent, key, 'string');
          if (sshObjectFile && SSH_REFLECTION_NAMES.includes(node.value)) report(node, 'ssh-computed', node.value, 'reflection in a file that holds SSH objects');
        }
        break;
      case 'TemplateElement':
        checkName(node.value.cooked ?? node.value.raw, node, parent, key, 'template');
        break;
      case 'MemberExpression':
        if (sshObjectFile && node.computed && node.property.type !== 'Literal') {
          report(node, 'ssh-computed', 'computed', 'computed member access in a file that holds SSH objects');
        }
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
  if (argv.length > 1) {
    console.error('Usage: node scripts/no-exec-guard.mjs [srcDir]');
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

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    process.exitCode = main(process.argv.slice(2));
  } catch (err) {
    console.error(`Never-exec guard error: ${err.message}`);
    process.exitCode = 2;
  }
}
