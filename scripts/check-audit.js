#!/usr/bin/env node
// Runs `npm audit --json` and fails when any advisory at or above the
// threshold (default: high) is not listed in audit-allowlist.json.
// Allowlisted advisories are reported but do not fail the check; allowlist
// entries whose advisory no longer appears are reported as stale.
//
// Usage: node scripts/check-audit.js [--allowlist <path>]
// Exit codes: 0 pass, 1 unlisted advisories found, 2 audit or allowlist error.

import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const SEVERITY_RANK = { info: 0, low: 1, moderate: 2, high: 3, critical: 4 };

export function advisoryId(via) {
  if (typeof via.url === 'string' && via.url.length > 0) {
    return via.url.split('/').pop();
  }
  return String(via.source);
}

// Collect the unique advisories (not the derived per-package entries) from an
// npm audit v2 JSON report.
export function collectAdvisories(report) {
  if (!report || typeof report !== 'object' || report.error) {
    const detail = report?.error?.summary ?? 'unrecognised output';
    throw new Error(`npm audit did not produce a report: ${detail}`);
  }
  if (!report.vulnerabilities || typeof report.vulnerabilities !== 'object') {
    throw new Error('npm audit report has no "vulnerabilities" field');
  }
  const byKey = new Map();
  for (const [pkg, vuln] of Object.entries(report.vulnerabilities)) {
    for (const via of vuln.via ?? []) {
      if (typeof via !== 'object' || via === null) continue; // transitive reference
      const id = advisoryId(via);
      const name = via.name ?? pkg;
      const key = `${id}|${name}`;
      if (!byKey.has(key)) {
        byKey.set(key, { id, package: name, severity: via.severity, title: via.title ?? '' });
      }
    }
  }
  return [...byKey.values()];
}

export function validateAllowlist(allowlist) {
  if (!allowlist || !Array.isArray(allowlist.advisories)) {
    throw new Error('allowlist must be an object with an "advisories" array');
  }
  allowlist.advisories.forEach((entry, i) => {
    for (const field of ['id', 'package', 'reason', 'issue']) {
      if (typeof entry[field] !== 'string' || entry[field].trim() === '') {
        throw new Error(`allowlist entry ${i} is missing "${field}"`);
      }
    }
  });
  return allowlist.advisories;
}

export function evaluate(report, allowlist, level = 'high') {
  if (!(level in SEVERITY_RANK)) throw new Error(`unknown audit level "${level}"`);
  const threshold = SEVERITY_RANK[level];
  const entries = validateAllowlist(allowlist);
  const allowed = new Set(entries.map((e) => `${e.id}|${e.package}`));

  const relevant = collectAdvisories(report).filter(
    (a) => (SEVERITY_RANK[a.severity] ?? SEVERITY_RANK.critical) >= threshold,
  );
  const present = new Set(relevant.map((a) => `${a.id}|${a.package}`));

  return {
    blocking: relevant.filter((a) => !allowed.has(`${a.id}|${a.package}`)),
    allowlisted: relevant.filter((a) => allowed.has(`${a.id}|${a.package}`)),
    stale: entries.filter((e) => !present.has(`${e.id}|${e.package}`)),
  };
}

function format(a) {
  return `  ${a.severity.padEnd(8)} ${a.package} ${a.id} ${a.title}`;
}

function main(argv) {
  const flag = argv.indexOf('--allowlist');
  const allowlistPath = resolve(flag >= 0 ? argv[flag + 1] : 'audit-allowlist.json');

  let result;
  try {
    const allowlist = JSON.parse(readFileSync(allowlistPath, 'utf8'));
    const run = spawnSync('npm', ['audit', '--json'], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
    if (run.error) throw run.error;
    let report;
    try {
      report = JSON.parse(run.stdout);
    } catch {
      throw new Error(`could not parse npm audit output (exit ${run.status})`);
    }
    result = evaluate(report, allowlist, 'high');
  } catch (err) {
    console.error(`audit check error: ${err.message}`);
    return 2;
  }

  if (result.allowlisted.length > 0) {
    console.log(`Allowlisted high/critical advisories (${result.allowlisted.length}), see audit-allowlist.json:`);
    result.allowlisted.forEach((a) => console.log(format(a)));
  }
  if (result.stale.length > 0) {
    console.log(`Stale allowlist entries (${result.stale.length}); the advisory no longer appears, remove them:`);
    result.stale.forEach((e) => console.log(`  ${e.package} ${e.id}`));
  }
  if (result.blocking.length > 0) {
    console.error(`Unlisted high/critical advisories (${result.blocking.length}):`);
    result.blocking.forEach((a) => console.error(format(a)));
    console.error('Fix them (npm audit fix, or upgrade), or allowlist each with a reason and a tracking issue.');
    return 1;
  }
  console.log('Audit check passed: no unlisted high or critical advisories.');
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  process.exitCode = main(process.argv.slice(2));
}
