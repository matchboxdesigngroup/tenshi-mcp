#!/usr/bin/env node
// Dependency audit gate used by CI (`npm run audit:check`). Node built-ins only.
//
// Runs `npm audit --json` against the public registry with the dev, optional and
// peer trees included and offline mode off, whatever .npmrc or the environment
// say. Fails when:
//   - a high or critical advisory is reported that is not in .audit-allowlist.json,
//   - an allowlisted advisory is now rated more severe than its entry records,
//   - any allowlist entry is malformed, duplicated, expired, or expires more than
//     MAX_EXPIRY_DAYS ahead (all problems are listed, not only the first), or
//   - npm audit gives no usable report (fails closed).
// Allowlisted advisories that npm no longer reports are printed as stale.
// Output lists severity, package and advisory id only.
//
// Known limit: entries match on advisory id and package, so a new install path
// to an already-allowlisted package and advisory is not reported separately.
//
// Usage: node scripts/audit-check.mjs [--allowlist <path>]
// Exit codes: 0 pass, 1 unlisted or re-rated advisories, 2 audit, allowlist or usage error.

import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const DEFAULT_ALLOWLIST = path.join(ROOT, '.audit-allowlist.json');
export const MAX_EXPIRY_DAYS = 60;

// Command-line flags override .npmrc and npm_config_* environment settings, so
// offline mode, a mirror registry, or omit=dev / production cannot hide advisories.
export const AUDIT_ARGS = Object.freeze([
  'audit',
  '--json',
  '--offline=false',
  '--registry=https://registry.npmjs.org/',
  '--include=optional',
  '--include=peer',
]);

const SEVERITY_RANK = { info: 0, low: 1, moderate: 2, high: 3, critical: 4 };
const ALLOWLIST_SEVERITIES = ['high', 'critical'];

// Unknown or missing severities rank as critical so they can never slip under
// the threshold or under an allowlist entry.
export function severityRank(severity) {
  return SEVERITY_RANK[severity] ?? SEVERITY_RANK.critical;
}

export function advisoryId(via) {
  if (typeof via.url === 'string' && via.url.length > 0) {
    return via.url.split('/').pop();
  }
  return `unknown:${via.source}`;
}

function auditFailureDetail(report) {
  const parts = [report?.error?.code, report?.error?.summary, report?.message, report?.error?.detail]
    .filter((p) => typeof p === 'string' && p.trim() !== '');
  return parts.length > 0 ? parts.join(': ') : 'no detail from npm (registry unreachable or npm error)';
}

// Fail closed unless the output looks like a complete npm audit v2 report.
export function assertReportShape(report) {
  if (!report || typeof report !== 'object' || Array.isArray(report)) {
    throw new Error('npm audit output is not a JSON object');
  }
  if (report.error || report.message) {
    throw new Error(`npm audit failed: ${auditFailureDetail(report)}`);
  }
  if (report.auditReportVersion !== 2) {
    throw new Error(`unsupported npm audit report version ${JSON.stringify(report.auditReportVersion)}`);
  }
  if (!report.vulnerabilities || typeof report.vulnerabilities !== 'object') {
    throw new Error('npm audit report has no "vulnerabilities" object');
  }
  const counts = report.metadata?.vulnerabilities;
  const deps = report.metadata?.dependencies;
  if (!counts || typeof counts.total !== 'number' || !deps || typeof deps.total !== 'number') {
    throw new Error('npm audit report has no vulnerability or dependency metadata');
  }
  if (deps.total < 1) {
    throw new Error('npm audit report covers no dependencies');
  }
  if (counts.total !== Object.keys(report.vulnerabilities).length) {
    throw new Error('npm audit report metadata does not match its vulnerability list');
  }
}

// Collect the unique advisories (not the derived per-package entries).
export function collectAdvisories(report) {
  assertReportShape(report);
  const byKey = new Map();
  for (const [pkg, vuln] of Object.entries(report.vulnerabilities)) {
    for (const via of vuln?.via ?? []) {
      if (typeof via !== 'object' || via === null) continue; // transitive reference
      const id = advisoryId(via);
      const name = via.name ?? pkg;
      const key = `${id}|${name}`;
      const severity = typeof via.severity === 'string' ? via.severity : 'unknown';
      const prev = byKey.get(key);
      if (!prev || severityRank(severity) > severityRank(prev.severity)) {
        byKey.set(key, { id, package: name, severity });
      }
    }
  }
  return [...byKey.values()];
}

function isRealDate(value) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const d = new Date(`${value}T00:00:00Z`);
  return !Number.isNaN(d.getTime()) && d.toISOString().slice(0, 10) === value;
}

function addDays(isoDate, days) {
  const d = new Date(`${isoDate}T00:00:00Z`);
  d.setUTCDate(d.getUTCDate() + days);
  return d.toISOString().slice(0, 10);
}

// `today` is YYYY-MM-DD (UTC). An entry is valid through its `expires` date.
// Throws one error listing every problem found.
export function validateAllowlist(allowlist, today = new Date().toISOString().slice(0, 10)) {
  if (!allowlist || typeof allowlist !== 'object' || !Array.isArray(allowlist.advisories)) {
    throw new Error('allowlist must be an object with an "advisories" array');
  }
  const latest = addDays(today, MAX_EXPIRY_DAYS);
  const problems = [];
  const seen = new Set();
  allowlist.advisories.forEach((entry, i) => {
    const label = `allowlist entry ${i}${typeof entry?.id === 'string' ? ` (${entry.id})` : ''}`;
    const missing = ['id', 'package', 'severity', 'reason', 'issue', 'expires'].filter(
      (f) => typeof entry?.[f] !== 'string' || entry[f].trim() === '',
    );
    if (missing.length > 0) {
      problems.push(`${label} is missing ${missing.map((f) => `"${f}"`).join(', ')}`);
      return;
    }
    if (!/^GHSA(-[a-z0-9]{4}){3}$/.test(entry.id)) problems.push(`${label} has an invalid advisory id`);
    if (!ALLOWLIST_SEVERITIES.includes(entry.severity)) {
      problems.push(`${label} has severity "${entry.severity}"; use "high" or "critical"`);
    }
    if (!isRealDate(entry.expires)) {
      problems.push(`${label} needs "expires" as a real YYYY-MM-DD date`);
    } else if (entry.expires < today) {
      problems.push(`${label} (${entry.package}) expired on ${entry.expires}, see ${entry.issue}`);
    } else if (entry.expires > latest) {
      problems.push(`${label} expires ${entry.expires}, more than ${MAX_EXPIRY_DAYS} days ahead (latest ${latest})`);
    }
    const key = `${entry.id}|${entry.package}`;
    if (seen.has(key)) problems.push(`${label} duplicates an earlier entry for ${entry.package}`);
    seen.add(key);
  });
  if (problems.length > 0) {
    throw new Error(`invalid allowlist (${problems.length} problem${problems.length > 1 ? 's' : ''}):\n  ${problems.join('\n  ')}`);
  }
  return allowlist.advisories;
}

export function evaluate(report, allowlist, level = 'high', today = undefined) {
  if (!(level in SEVERITY_RANK)) throw new Error(`unknown audit level "${level}"`);
  const threshold = SEVERITY_RANK[level];
  const entries = validateAllowlist(allowlist, today);
  const byKey = new Map(entries.map((e) => [`${e.id}|${e.package}`, e]));

  const relevant = collectAdvisories(report).filter((a) => severityRank(a.severity) >= threshold);
  const present = new Set(relevant.map((a) => `${a.id}|${a.package}`));

  const blocking = [];
  const rerated = [];
  const allowlisted = [];
  for (const a of relevant) {
    const entry = byKey.get(`${a.id}|${a.package}`);
    if (!entry) blocking.push(a);
    else if (severityRank(a.severity) > severityRank(entry.severity)) rerated.push({ ...a, allowed: entry.severity });
    else allowlisted.push(a);
  }
  return { blocking, rerated, allowlisted, stale: entries.filter((e) => !present.has(`${e.id}|${e.package}`)) };
}

export function parseArgs(argv) {
  const options = { allowlist: DEFAULT_ALLOWLIST };
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--allowlist') {
      const value = argv[i + 1];
      if (value === undefined || value.startsWith('--') || value.trim() === '') {
        throw new Error('--allowlist needs a file path');
      }
      options.allowlist = path.resolve(value);
      i += 1;
    } else {
      throw new Error(`unknown argument "${argv[i]}"`);
    }
  }
  return options;
}

export function runNpmAudit() {
  return spawnSync('npm', [...AUDIT_ARGS], { cwd: ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
}

function format(a) {
  return `  ${String(a.severity).padEnd(8)} ${a.package} ${a.id}`;
}

export function main(argv, { run = runNpmAudit, today, log = console.log, error = console.error } = {}) {
  let result;
  try {
    const options = parseArgs(argv);
    const allowlist = JSON.parse(readFileSync(options.allowlist, 'utf8'));
    validateAllowlist(allowlist, today); // report allowlist problems even if npm fails
    const out = run();
    if (out.error) throw new Error(`could not run npm audit: ${out.error.message}`);
    let report;
    try {
      report = JSON.parse(out.stdout);
    } catch {
      throw new Error(`could not parse npm audit output (npm exit ${out.status})`);
    }
    result = evaluate(report, allowlist, 'high', today);
  } catch (err) {
    error(`audit check error: ${err.message}`);
    return 2;
  }

  if (result.allowlisted.length > 0) {
    log(`Allowlisted high/critical advisories (${result.allowlisted.length}), see .audit-allowlist.json:`);
    result.allowlisted.forEach((a) => log(format(a)));
  }
  if (result.stale.length > 0) {
    log(`Stale allowlist entries (${result.stale.length}); the advisory no longer appears, remove them:`);
    result.stale.forEach((e) => log(`  ${e.package} ${e.id}`));
  }
  let code = 0;
  if (result.rerated.length > 0) {
    error(`Allowlisted advisories now rated more severe than their entry (${result.rerated.length}):`);
    result.rerated.forEach((a) => error(`${format(a)} (allowlisted as ${a.allowed})`));
    code = 1;
  }
  if (result.blocking.length > 0) {
    error(`Unlisted high/critical advisories (${result.blocking.length}):`);
    result.blocking.forEach((a) => error(format(a)));
    code = 1;
  }
  if (code !== 0) {
    error('Fix them (npm audit fix, or upgrade), or allowlist each with severity, reason, tracking issue and expiry date.');
    return code;
  }
  log('Audit check passed: no unlisted high or critical advisories.');
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  process.exitCode = main(process.argv.slice(2));
}
