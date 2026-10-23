import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  AUDIT_ARGS,
  MAX_EXPIRY_DAYS,
  assertReportShape,
  collectAdvisories,
  evaluate,
  isEntryPoint,
  main,
  parseArgs,
  severityRank,
  validateAllowlist,
} from '../scripts/audit-check.mjs';

const SCRIPT = fileURLToPath(new URL('../scripts/audit-check.mjs', import.meta.url));
const TODAY = '2026-10-22';

// Shape npm 10 prints when the registry cannot be reached (captured from a real
// run against a closed local port; host replaced with a placeholder).
const UNREACHABLE = {
  message: 'request to https://registry.example.com/-/npm/v1/security/audits/quick failed, reason: connect ECONNREFUSED',
  error: { summary: '', detail: '' },
};

const advisory = (name, id, severity) => ({
  source: 1,
  name,
  dependency: name,
  title: `${name} advisory`,
  url: `https://github.com/advisories/${id}`,
  severity,
  range: '<1.0.0',
});

function makeReport(vulnerabilities) {
  return {
    auditReportVersion: 2,
    vulnerabilities,
    metadata: {
      vulnerabilities: { total: Object.keys(vulnerabilities).length },
      dependencies: { prod: 3, dev: 2, optional: 0, peer: 0, peerOptional: 0, total: 5 },
    },
  };
}

const report = makeReport({
  'pkg-a': { name: 'pkg-a', severity: 'critical', via: [advisory('pkg-a', 'GHSA-aaaa-aaaa-aaaa', 'critical')] },
  'pkg-b': {
    name: 'pkg-b',
    severity: 'high',
    via: [advisory('pkg-b', 'GHSA-bbbb-bbbb-bbbb', 'high'), advisory('pkg-b', 'GHSA-mmmm-mmmm-mmmm', 'moderate')],
  },
  // Derived entry: only references pkg-a, carries no advisory of its own.
  'pkg-c': { name: 'pkg-c', severity: 'critical', via: ['pkg-a'] },
});

const entry = (pkg, id, severity = 'high', expires = '2026-11-30') => ({
  id,
  package: pkg,
  severity,
  reason: 'test',
  issue: '#0',
  expires,
});

const quiet = { today: TODAY, log: () => {}, error: () => {} };

describe('AUDIT_ARGS', () => {
  it('forces online mode, the public registry, TLS certificate checks, the lockfile and every dependency tree', () => {
    expect([...AUDIT_ARGS]).toEqual([
      'audit',
      '--json',
      '--offline=false',
      '--registry=https://registry.npmjs.org/',
      '--strict-ssl=true',
      '--package-lock=true',
      '--include=prod',
      '--include=dev',
      '--include=optional',
      '--include=peer',
    ]);
    expect(Object.isFrozen(AUDIT_ARGS)).toBe(true);
  });
});

describe('collectAdvisories', () => {
  it('returns unique advisories and skips transitive references', () => {
    const ids = collectAdvisories(report).map((a) => a.id).sort();
    expect(ids).toEqual(['GHSA-aaaa-aaaa-aaaa', 'GHSA-bbbb-bbbb-bbbb', 'GHSA-mmmm-mmmm-mmmm']);
  });

  it('fails closed on a null "via" item instead of skipping it', () => {
    const r = makeReport({ 'pkg-a': { name: 'pkg-a', via: [advisory('pkg-a', 'GHSA-aaaa-aaaa-aaaa', 'high'), null] } });
    expect(() => collectAdvisories(r)).toThrow(/pkg-a has an unexpected "via" item \(null\)/);
  });

  it('fails closed on other odd "via" shapes', () => {
    for (const item of [7, true, ['pkg-a']]) {
      const r = makeReport({ 'pkg-a': { name: 'pkg-a', via: [item] } });
      expect(() => collectAdvisories(r), JSON.stringify(item)).toThrow(/unexpected "via" item/);
    }
    for (const vuln of [null, 'pkg', { name: 'pkg-a' }, { name: 'pkg-a', via: null }, { name: 'pkg-a', via: {} }]) {
      const r = makeReport({ 'pkg-a': vuln });
      expect(() => collectAdvisories(r), JSON.stringify(vuln)).toThrow(/pkg-a has an unexpected shape/);
    }
  });
});

describe('assertReportShape (fails closed)', () => {
  it('rejects the real unreachable-registry output and prints npm\'s message', () => {
    expect(() => assertReportShape(UNREACHABLE)).toThrow(/^npm audit failed: request to https:\/\/registry\.example\.com\/.*ECONNREFUSED$/);
  });

  it('rejects an otherwise complete report that carries a top-level message', () => {
    expect(() => assertReportShape({ ...report, message: 'something went wrong' })).toThrow(/npm audit failed: something went wrong/);
  });

  it('rejects an otherwise complete report that carries an error object', () => {
    expect(() => assertReportShape({ ...report, error: { code: 'ENOAUDIT', summary: '', detail: '' } })).toThrow(/npm audit failed: ENOAUDIT/);
    expect(() => assertReportShape({ ...report, error: {} })).toThrow(/no detail from npm/);
    expect(() => assertReportShape({ ...report, error: null })).toThrow(/npm audit failed/);
  });

  it('rejects reports that are missing parts or inconsistent', () => {
    expect(() => assertReportShape(null)).toThrow(/not a JSON object/);
    expect(() => assertReportShape([])).toThrow(/not a JSON object/);
    expect(() => assertReportShape({ ...report, auditReportVersion: 1 })).toThrow(/version/);
    expect(() => assertReportShape({ ...report, vulnerabilities: undefined })).toThrow(/vulnerabilities/);
    expect(() => assertReportShape({ ...report, vulnerabilities: [] })).toThrow(/vulnerabilities/);
    expect(() => assertReportShape({ ...report, metadata: undefined })).toThrow(/metadata/);
    const noDeps = { ...report, metadata: { ...report.metadata, dependencies: { total: 0 } } };
    expect(() => assertReportShape(noDeps)).toThrow(/no dependencies/);
    const mismatch = { ...report, metadata: { ...report.metadata, vulnerabilities: { total: 0 } } };
    expect(() => assertReportShape(mismatch)).toThrow(/does not match/);
  });

  it('accepts a complete report', () => {
    expect(() => assertReportShape(report)).not.toThrow();
  });
});

describe('severity fallback', () => {
  it('ranks unknown and missing severities as critical, including Object prototype names', () => {
    expect(severityRank('critical')).toBe(4);
    expect(severityRank(undefined)).toBe(4);
    expect(severityRank('not-a-severity')).toBe(4);
    expect(severityRank('constructor')).toBe(4);
    expect(severityRank('toString')).toBe(4);
    expect(severityRank('moderate')).toBe(2);
  });

  it('blocks an advisory with no severity and formats it without crashing', () => {
    const noSeverity = { ...advisory('pkg-x', 'GHSA-xxxx-xxxx-xxxx', 'high') };
    delete noSeverity.severity;
    const r = makeReport({ 'pkg-x': { name: 'pkg-x', via: [noSeverity] } });
    const result = evaluate(r, { advisories: [] }, 'high', TODAY);
    expect(result.unknown.map((a) => [a.id, a.severity])).toEqual([['GHSA-xxxx-xxxx-xxxx', 'unknown']]);

    const errors = [];
    const code = main(['--allowlist', writeTemp({ advisories: [] })], {
      ...quiet,
      run: () => ({ status: 1, stdout: JSON.stringify(r) }),
      error: (m) => errors.push(m),
    });
    expect(code).toBe(1);
    expect(errors.join('\n')).toMatch(/unknown\s+pkg-x GHSA-xxxx-xxxx-xxxx/);
  });

  it('fails an unknown severity even when the id and package are allowlisted as critical', () => {
    for (const severity of ['severe', 'constructor', undefined]) {
      const odd = advisory('pkg-x', 'GHSA-xxxx-xxxx-xxxx', severity);
      const r = makeReport({ 'pkg-x': { name: 'pkg-x', via: [odd] } });
      for (const allowed of ['high', 'critical']) {
        const allowlist = { advisories: [entry('pkg-x', 'GHSA-xxxx-xxxx-xxxx', allowed)] };
        const result = evaluate(r, allowlist, 'high', TODAY);
        expect(result.unknown.map((a) => a.id), `${severity} vs ${allowed}`).toEqual(['GHSA-xxxx-xxxx-xxxx']);
        expect(result.allowlisted).toEqual([]);
        expect(result.stale).toEqual([]);
        const errors = [];
        const code = main(['--allowlist', writeTemp(allowlist)], {
          ...quiet,
          run: () => ({ status: 1, stdout: JSON.stringify(r) }),
          error: (m) => errors.push(m),
        });
        expect(code, `${severity} vs ${allowed}`).toBe(1);
        expect(errors.join('\n')).toMatch(/unknown or missing severity/);
      }
    }
  });

  it('keeps an unknown severity when the same advisory also appears with a known one, in either order', () => {
    const orders = [
      ['weird', 'critical'],
      ['critical', 'weird'],
      ['weird', 'high'],
      ['high', 'weird'],
      [undefined, 'high'],
      ['high', undefined],
    ];
    for (const severities of orders) {
      const via = severities.map((s) => advisory('pkg-x', 'GHSA-xxxx-xxxx-xxxx', s));
      const r = makeReport({ 'pkg-x': { name: 'pkg-x', via } });
      for (const allowed of ['high', 'critical']) {
        const label = `${severities.join(' then ')} vs entry ${allowed}`;
        const allowlist = { advisories: [entry('pkg-x', 'GHSA-xxxx-xxxx-xxxx', allowed)] };
        const result = evaluate(r, allowlist, 'high', TODAY);
        expect(result.unknown.map((a) => a.id), label).toEqual(['GHSA-xxxx-xxxx-xxxx']);
        expect(result.allowlisted, label).toEqual([]);
        expect(result.rerated, label).toEqual([]);
        const code = main(['--allowlist', writeTemp(allowlist)], { ...quiet, run: () => ({ status: 1, stdout: JSON.stringify(r) }) });
        expect(code, label).toBe(1);
      }
    }
  });
});

describe('evaluate', () => {
  it('blocks high and critical advisories that are not allowlisted', () => {
    const result = evaluate(report, { advisories: [] }, 'high', TODAY);
    expect(result.blocking.map((a) => a.id).sort()).toEqual(['GHSA-aaaa-aaaa-aaaa', 'GHSA-bbbb-bbbb-bbbb']);
  });

  it('ignores advisories below the threshold', () => {
    const result = evaluate(report, { advisories: [] }, 'high', TODAY);
    expect(result.blocking.map((a) => a.id)).not.toContain('GHSA-mmmm-mmmm-mmmm');
  });

  it('passes when every high or critical advisory is allowlisted at its severity', () => {
    const allowlist = {
      advisories: [entry('pkg-a', 'GHSA-aaaa-aaaa-aaaa', 'critical'), entry('pkg-b', 'GHSA-bbbb-bbbb-bbbb', 'high')],
    };
    const result = evaluate(report, allowlist, 'high', TODAY);
    expect(result.blocking).toEqual([]);
    expect(result.unknown).toEqual([]);
    expect(result.rerated).toEqual([]);
    expect(result.allowlisted).toHaveLength(2);
    expect(result.stale).toEqual([]);
  });

  it('fails an allowlisted advisory that was re-rated from high to critical', () => {
    const allowlist = {
      advisories: [entry('pkg-a', 'GHSA-aaaa-aaaa-aaaa', 'high'), entry('pkg-b', 'GHSA-bbbb-bbbb-bbbb', 'high')],
    };
    const result = evaluate(report, allowlist, 'high', TODAY);
    expect(result.rerated.map((a) => [a.id, a.severity, a.allowed])).toEqual([['GHSA-aaaa-aaaa-aaaa', 'critical', 'high']]);
    expect(result.allowlisted.map((a) => a.id)).toEqual(['GHSA-bbbb-bbbb-bbbb']);
    const code = main(['--allowlist', writeTemp(allowlist)], { ...quiet, run: () => ({ status: 1, stdout: JSON.stringify(report) }) });
    expect(code).toBe(1);
  });

  it('fails an allowlisted advisory that was re-rated from critical to high (critical entry, high report)', () => {
    const allowlist = {
      advisories: [entry('pkg-a', 'GHSA-aaaa-aaaa-aaaa', 'critical'), entry('pkg-b', 'GHSA-bbbb-bbbb-bbbb', 'critical')],
    };
    const result = evaluate(report, allowlist, 'high', TODAY);
    expect(result.rerated.map((a) => [a.id, a.severity, a.allowed])).toEqual([['GHSA-bbbb-bbbb-bbbb', 'high', 'critical']]);
    expect(result.allowlisted.map((a) => a.id)).toEqual(['GHSA-aaaa-aaaa-aaaa']);
    const errors = [];
    const code = main(['--allowlist', writeTemp(allowlist)], {
      ...quiet,
      run: () => ({ status: 1, stdout: JSON.stringify(report) }),
      error: (m) => errors.push(m),
    });
    expect(code).toBe(1);
    expect(errors.join('\n')).toMatch(/now rated differently from their entry \(1\)/);
    expect(errors.join('\n')).toMatch(/high\s+pkg-b GHSA-bbbb-bbbb-bbbb \(allowlisted as critical\)/);
  });

  it('does not let an all-critical allowlist cover high advisories', () => {
    const r = makeReport({
      'pkg-b': { name: 'pkg-b', via: [advisory('pkg-b', 'GHSA-bbbb-bbbb-bbbb', 'high')] },
      'pkg-d': { name: 'pkg-d', via: [advisory('pkg-d', 'GHSA-dddd-dddd-dddd', 'high')] },
    });
    const allowlist = {
      advisories: [entry('pkg-b', 'GHSA-bbbb-bbbb-bbbb', 'critical'), entry('pkg-d', 'GHSA-dddd-dddd-dddd', 'critical')],
    };
    const result = evaluate(r, allowlist, 'high', TODAY);
    expect(result.rerated.map((a) => a.id)).toEqual(['GHSA-bbbb-bbbb-bbbb', 'GHSA-dddd-dddd-dddd']);
    expect(result.allowlisted).toEqual([]);
  });

  it('matches on advisory id and package together', () => {
    const allowlist = {
      advisories: [entry('other-pkg', 'GHSA-aaaa-aaaa-aaaa', 'critical'), entry('pkg-b', 'GHSA-bbbb-bbbb-bbbb')],
    };
    const result = evaluate(report, allowlist, 'high', TODAY);
    expect(result.blocking.map((a) => a.id)).toEqual(['GHSA-aaaa-aaaa-aaaa']);
    expect(result.stale.map((e) => e.package)).toEqual(['other-pkg']);
  });

  it('reports allowlist entries whose advisory no longer appears as stale', () => {
    const allowlist = { advisories: [entry('pkg-z', 'GHSA-zzzz-zzzz-zzzz')] };
    expect(evaluate(report, allowlist, 'high', TODAY).stale.map((e) => e.id)).toEqual(['GHSA-zzzz-zzzz-zzzz']);
  });

  it('treats an entry whose advisory dropped below high as stale', () => {
    const allowlist = { advisories: [entry('pkg-b', 'GHSA-mmmm-mmmm-mmmm')] };
    expect(evaluate(report, allowlist, 'high', TODAY).stale.map((e) => e.id)).toEqual(['GHSA-mmmm-mmmm-mmmm']);
  });

  it('fails the evaluation when an allowlisted entry has expired', () => {
    const allowlist = { advisories: [entry('pkg-a', 'GHSA-aaaa-aaaa-aaaa', 'critical', '2026-01-01')] };
    expect(() => evaluate(report, allowlist, 'high', TODAY)).toThrow(/expired/);
  });

  it('rejects an unknown audit level, including Object prototype names', () => {
    expect(() => evaluate(report, { advisories: [] }, 'constructor', TODAY)).toThrow(/unknown audit level/);
  });
});

describe('main exit codes', () => {
  const full = () => ({
    advisories: [entry('pkg-a', 'GHSA-aaaa-aaaa-aaaa', 'critical'), entry('pkg-b', 'GHSA-bbbb-bbbb-bbbb', 'high')],
  });
  const runWith = (allowlist, out) => {
    const logs = [];
    const errors = [];
    const code = main(['--allowlist', writeTemp(allowlist)], {
      today: TODAY,
      run: () => out,
      log: (m) => logs.push(m),
      error: (m) => errors.push(m),
    });
    return { code, logs: logs.join('\n'), errors: errors.join('\n') };
  };

  it('exits 0 when every advisory is allowlisted and nothing is stale', () => {
    const r = runWith(full(), { status: 1, stdout: JSON.stringify(report) });
    expect(r.code).toBe(0);
    expect(r.logs).toMatch(/Audit check passed/);
  });

  it('exits 1 on a stale entry, not only printing it', () => {
    const allowlist = full();
    allowlist.advisories.push(entry('pkg-z', 'GHSA-zzzz-zzzz-zzzz'));
    const r = runWith(allowlist, { status: 1, stdout: JSON.stringify(report) });
    expect(r.code).toBe(1);
    expect(r.errors).toMatch(/Stale allowlist entries \(1\)/);
    expect(r.errors).toMatch(/pkg-z GHSA-zzzz-zzzz-zzzz/);
    expect(r.logs).not.toMatch(/Audit check passed/);
  });

  it('exits 2 and prints npm\'s message for the real unreachable-registry output', () => {
    const r = runWith(full(), { status: 1, stdout: JSON.stringify(UNREACHABLE) });
    expect(r.code).toBe(2);
    expect(r.errors).toMatch(/^audit check error: npm audit failed: request to https:\/\/registry\.example\.com\/.*ECONNREFUSED$/);
  });

  it('exits 2 with the spawn error when npm cannot be started', () => {
    // stdout holds a passing report so only the spawn-error guard can fail the run.
    const r = runWith(full(), { error: new Error('spawnSync npm ENOENT'), status: null, stdout: JSON.stringify(report) });
    expect(r.code).toBe(2);
    expect(r.errors).toBe('audit check error: could not run npm audit: spawnSync npm ENOENT');
  });

  it('exits 2 when npm output is not JSON', () => {
    const r = runWith(full(), { status: 1, stdout: '' });
    expect(r.code).toBe(2);
    expect(r.errors).toMatch(/could not parse npm audit output \(npm exit 1\)/);
  });
});

describe('validateAllowlist', () => {
  const base = { id: 'GHSA-aaaa-aaaa-aaaa', package: 'p', severity: 'high', reason: 'r', issue: '#1', expires: '2026-11-30' };
  const check = (...entries) => () => validateAllowlist({ advisories: entries }, TODAY);

  it('rejects entries with missing or blank fields', () => {
    for (const field of ['id', 'package', 'severity', 'reason', 'issue', 'expires']) {
      const e = { ...base };
      delete e[field];
      expect(check(e)).toThrow(new RegExp(`missing "${field}"`));
      expect(check({ ...base, [field]: ' \t' })).toThrow(new RegExp(`missing "${field}"`));
    }
  });

  it('rejects entries that are not objects', () => {
    expect(check(null)).toThrow(/entry 0 is not an object/);
    expect(check(7)).toThrow(/entry 0 is not an object/);
    expect(check(['x'])).toThrow(/entry 0 is not an object/);
  });

  it('rejects ids that are not GHSA ids', () => {
    expect(check({ ...base, id: 'CVE-2026-0001' })).toThrow(/invalid advisory id/);
  });

  it('requires severity to be exactly "high" or "critical"', () => {
    for (const bad of ['moderate', 'low', 'High', 'CRITICAL', 'critical ', 'unknown']) {
      expect(check({ ...base, severity: bad }), bad).toThrow(/use exactly "high" or "critical"/);
    }
    expect(check({ ...base, severity: 'critical' })()).toHaveLength(1);
  });

  it('requires a real calendar date for expires', () => {
    expect(check({ ...base, expires: 'soon' })).toThrow(/real YYYY-MM-DD/);
    expect(check({ ...base, expires: '2026-11-31' })).toThrow(/real YYYY-MM-DD/);
  });

  it('rejects expired entries and accepts entries on their expiry date', () => {
    expect(check({ ...base, expires: '2026-10-21' })).toThrow(/expired on 2026-10-21/);
    expect(check({ ...base, expires: TODAY })()).toHaveLength(1);
  });

  it(`caps expires at ${MAX_EXPIRY_DAYS} days ahead`, () => {
    expect(check({ ...base, expires: '2026-12-21' })()).toHaveLength(1); // today + 60
    expect(check({ ...base, expires: '2026-12-22' })).toThrow(/more than 60 days ahead/);
  });

  it('rejects duplicate entries for the same advisory and package', () => {
    expect(check(base, { ...base })).toThrow(/duplicates an earlier entry/);
    expect(check(base, { ...base, severity: 'critical' })).toThrow(/duplicates an earlier entry/);
    expect(check(base, { ...base, package: 'q' })()).toHaveLength(2);
  });

  it('lists every problem instead of stopping at the first', () => {
    let message = '';
    try {
      check(
        { ...base, expires: '2026-01-01' },
        { ...base, id: 'bad', package: 'q' },
        { ...base, reason: '' },
        { ...base, package: 'r', severity: 'moderate' },
        { ...base, expires: '2026-01-01' },
      )();
    } catch (err) {
      message = err.message;
    }
    expect(message).toMatch(/6 problems/);
    expect(message).toMatch(/entry 0 .*expired/);
    expect(message).toMatch(/entry 1 .*invalid advisory id/);
    expect(message).toMatch(/entry 2 .*missing "reason"/);
    expect(message).toMatch(/entry 3 .*severity "moderate"/);
    expect(message).toMatch(/entry 4 .*expired/);
    expect(message).toMatch(/entry 4 .*duplicates an earlier entry/);
  });

  it('rejects a file without an advisories array', () => {
    for (const bad of [{}, null, [], 'x', { advisories: null }]) {
      expect(() => validateAllowlist(bad), JSON.stringify(bad)).toThrow(/advisories/);
    }
  });
});

describe('parseArgs and main usage errors', () => {
  it('rejects --allowlist without a value and unknown arguments', () => {
    expect(() => parseArgs(['--allowlist'])).toThrow(/needs a file path/);
    expect(() => parseArgs(['--allowlist', '--other'])).toThrow(/needs a file path/);
    expect(() => parseArgs(['--verbose'])).toThrow(/unknown argument/);
  });

  it('exits 2 (not an uncaught TypeError) on usage errors', () => {
    const errors = [];
    const code = main(['--allowlist'], { run: () => ({ stdout: '{}' }), error: (m) => errors.push(m) });
    expect(code).toBe(2);
    expect(errors[0]).toMatch(/needs a file path/);
  });

  it('exits 2 on an allowlist that is not JSON', () => {
    const file = path.join(dir, 'not-json.json');
    writeFileSync(file, '{ not json');
    const errors = [];
    expect(main(['--allowlist', file], { ...quiet, error: (m) => errors.push(m), run: () => ({}) })).toBe(2);
    expect(errors[0]).toMatch(/^audit check error: /);
  });
});

describe('isEntryPoint', () => {
  it('matches the module through its real path and through a symlink', () => {
    const link = path.join(dir, 'entry-link.mjs');
    symlinkSync(SCRIPT, link);
    const url = pathToFileURL(SCRIPT).href;
    expect(isEntryPoint(SCRIPT, url)).toBe(true);
    expect(isEntryPoint(link, url)).toBe(true);
    expect(isEntryPoint(path.join(dir, 'missing.mjs'), url)).toBe(false);
    expect(isEntryPoint(undefined, url)).toBe(false);
    expect(isEntryPoint(path.join(dir, 'npm'), url)).toBe(false);
  });
});

// End to end: run the real script, copied into a scratch project, with a stub
// `npm` first on PATH. The stub models npm's config precedence (command line,
// then npm_config_* environment, then the project .npmrc, then the userconfig
// file) for the settings that hide advisories, and records its arguments:
//   - offline=true reports no advisories,
//   - omit=dev, production=true or NODE_ENV=production hide the dev tree unless
//     --include=dev is given,
//   - package-lock=false audits a freshly resolved tree that has no advisories,
//   - strict-ssl=false stands for an intercepting proxy that answers for the
//     registry with a clean report (the worst case that setting allows),
//   - any registry other than the public one is unreachable (npm 10 shape).
// The locked tree has a high advisory in a prod dependency and a critical one
// in a dev dependency. STUB_OUTPUT, if set, is printed verbatim instead.
const STUB_NPM = String.raw`#!/usr/bin/env node
const fs = require('node:fs');
const args = process.argv.slice(2);
if (process.env.STUB_ARGS_FILE) fs.writeFileSync(process.env.STUB_ARGS_FILE, JSON.stringify(args));
if (process.env.STUB_OUTPUT !== undefined) {
  process.stdout.write(process.env.STUB_OUTPUT);
  process.exit(1);
}
const read = (f) => { try { return f ? fs.readFileSync(f, 'utf8') : ''; } catch { return ''; } };
const rcs = [read('.npmrc'), read(process.env.npm_config_userconfig)];
const fromRc = (k) => {
  for (const rc of rcs) {
    for (const line of rc.split('\n')) {
      const m = line.match(/^\s*([\w-]+)\s*=\s*(.*?)\s*$/);
      if (m && m[1] === k) return m[2];
    }
  }
  return undefined;
};
const fromArgs = (k) => args.filter((x) => x.startsWith('--' + k + '=')).map((x) => x.slice(k.length + 3));
const pick = (k) => {
  const a = fromArgs(k);
  if (a.length) return a[a.length - 1];
  return process.env['npm_config_' + k.replace(/-/g, '_')] ?? fromRc(k);
};
const meta = (vulns, deps) => ({ vulnerabilities: { total: Object.keys(vulns).length }, dependencies: { total: deps } });
const out = (vulns, deps) => {
  process.stdout.write(JSON.stringify({ auditReportVersion: 2, vulnerabilities: vulns, metadata: meta(vulns, deps) }));
  process.exit(Object.keys(vulns).length ? 1 : 0);
};
const registry = pick('registry') ?? 'https://registry.npmjs.org/';
if (registry !== 'https://registry.npmjs.org/') {
  process.stdout.write(JSON.stringify({ message: 'request to ' + registry + ' failed, reason: getaddrinfo ENOTFOUND', error: { summary: '', detail: '' } }));
  process.exit(1);
}
if (pick('offline') === 'true') out({}, 2);
if (pick('strict-ssl') === 'false') out({}, 2);
if (pick('package-lock') === 'false') out({}, 3);
const adv = (name, id, severity) => ({ source: 1, name, url: 'https://github.com/advisories/' + id, severity });
const vulns = {
  'prod-pkg': { name: 'prod-pkg', via: [adv('prod-pkg', 'GHSA-pppp-pppp-pppp', 'high')] },
  'dev-pkg': { name: 'dev-pkg', via: [adv('dev-pkg', 'GHSA-dddd-dddd-dddd', 'critical')] },
};
const omit = pick('omit') ?? (process.env.NODE_ENV === 'production' ? 'dev' : '');
const omitDev = omit.split(',').includes('dev') || pick('production') === 'true';
if (omitDev && !fromArgs('include').includes('dev')) delete vulns['dev-pkg'];
out(vulns, 2);
`;

let dir;
function writeTemp(content) {
  const file = path.join(dir, `allowlist-${Math.random().toString(36).slice(2)}.json`);
  writeFileSync(file, JSON.stringify(content));
  return file;
}

beforeAll(() => {
  dir = mkdtempSync(path.join(tmpdir(), 'audit-check-'));
  writeFileSync(path.join(dir, 'npm'), STUB_NPM);
  chmodSync(path.join(dir, 'npm'), 0o755);
});
afterAll(() => rmSync(dir, { recursive: true, force: true }));

const isoIn = (days) => new Date(Date.now() + days * 86400000).toISOString().slice(0, 10);
const LOCKED = () => [
  entry('prod-pkg', 'GHSA-pppp-pppp-pppp', 'high', isoIn(30)),
  entry('dev-pkg', 'GHSA-dddd-dddd-dddd', 'critical', isoIn(30)),
];

// A scratch project: scripts/audit-check.mjs (a copy), .audit-allowlist.json and
// an optional project .npmrc. The script runs npm with the project as cwd.
function project({ advisories = [], npmrc, userrc, env: extraEnv = {}, invoke } = {}) {
  const proj = mkdtempSync(path.join(dir, 'proj-'));
  mkdirSync(path.join(proj, 'scripts'));
  copyFileSync(SCRIPT, path.join(proj, 'scripts', 'audit-check.mjs'));
  writeFileSync(path.join(proj, '.audit-allowlist.json'), JSON.stringify({ advisories }));
  if (npmrc !== undefined) writeFileSync(path.join(proj, '.npmrc'), npmrc);
  const env = { ...process.env };
  for (const k of Object.keys(env)) if (k.toLowerCase().startsWith('npm_config_')) delete env[k];
  delete env.NODE_ENV;
  Object.assign(env, { PATH: `${dir}${path.delimiter}${process.env.PATH}`, STUB_ARGS_FILE: path.join(proj, 'args.json') });
  if (userrc !== undefined) {
    writeFileSync(path.join(proj, 'user.npmrc'), userrc);
    env.npm_config_userconfig = path.join(proj, 'user.npmrc');
  }
  Object.assign(env, extraEnv);
  const target = invoke ? invoke(proj) : path.join(proj, 'scripts', 'audit-check.mjs');
  const res = spawnSync(process.execPath, [target], { cwd: proj, env, encoding: 'utf8' });
  let args;
  try {
    args = JSON.parse(readFileSync(path.join(proj, 'args.json'), 'utf8'));
  } catch {
    args = undefined;
  }
  return { status: res.status, stdout: res.stdout, stderr: res.stderr, args };
}

describe('main with a stubbed npm on PATH', () => {
  it('passes exactly AUDIT_ARGS to npm', () => {
    expect(project().args).toEqual([...AUDIT_ARGS]);
  });

  it('exits 0 with the locked-tree advisories allowlisted', () => {
    const res = project({ advisories: LOCKED() });
    expect(res.status, res.stderr).toBe(0);
    expect(res.stdout).toMatch(/Allowlisted high\/critical advisories \(2\)/);
  });

  const HIDING = [
    ['offline=true in the environment', { env: { npm_config_offline: 'true' } }],
    ['offline=true in the project .npmrc', { npmrc: 'offline=true\n' }],
    ['omit=dev in the environment', { env: { npm_config_omit: 'dev' } }],
    ['omit=dev in the project .npmrc', { npmrc: 'omit=dev\n' }],
    ['production=true in the environment', { env: { npm_config_production: 'true' } }],
    ['NODE_ENV=production', { env: { NODE_ENV: 'production' } }],
    ['package-lock=false in the environment', { env: { npm_config_package_lock: 'false' } }],
    ['package-lock=false in the project .npmrc', { npmrc: 'package-lock=false\n' }],
    ['package-lock=false in the userconfig', { userrc: 'package-lock=false\n' }],
    ['strict-ssl=false in the environment', { env: { npm_config_strict_ssl: 'false' } }],
    ['strict-ssl=false in the project .npmrc', { npmrc: 'strict-ssl=false\n' }],
    ['a mirror registry in the project .npmrc', { npmrc: 'registry=https://registry.example.com/\n' }],
    ['all of them in the project .npmrc', { npmrc: 'offline=true\nomit=dev\npackage-lock=false\nproduction=true\nstrict-ssl=false\nregistry=https://registry.example.com/\n' }],
  ];
  for (const [name, opts] of HIDING) {
    it(`with ${name}: still reports the locked-tree advisories`, () => {
      const res = project(opts);
      expect(res.status, res.stderr).toBe(1);
      expect(res.stderr).toMatch(/high\s+prod-pkg GHSA-pppp-pppp-pppp/);
      expect(res.stderr).toMatch(/critical\s+dev-pkg GHSA-dddd-dddd-dddd/);
    });

    it(`with ${name}: passes on the full allowlist (lockfile audited, nothing stale)`, () => {
      const res = project({ ...opts, advisories: LOCKED() });
      expect(res.status, res.stderr).toBe(0);
      expect(res.stderr).not.toMatch(/Stale/);
    });

    it(`with ${name}: an extra stale entry fails the job`, () => {
      const res = project({ ...opts, advisories: [...LOCKED(), entry('gone-pkg', 'GHSA-zzzz-zzzz-zzzz', 'high', isoIn(30))] });
      expect(res.status, res.stderr).toBe(1);
      expect(res.stderr).toMatch(/Stale allowlist entries \(1\)/);
      expect(res.stderr).toMatch(/gone-pkg GHSA-zzzz-zzzz-zzzz/);
    });
  }

  it('fails when an entry records a different severity than npm reports, in either direction', () => {
    const [prod, dev] = LOCKED();
    const up = project({ advisories: [{ ...prod, severity: 'critical' }, dev] });
    expect(up.status, up.stderr).toBe(1);
    expect(up.stderr).toMatch(/high\s+prod-pkg GHSA-pppp-pppp-pppp \(allowlisted as critical\)/);
    const down = project({ advisories: [prod, { ...dev, severity: 'high' }] });
    expect(down.status, down.stderr).toBe(1);
    expect(down.stderr).toMatch(/critical\s+dev-pkg GHSA-dddd-dddd-dddd \(allowlisted as high\)/);
  });

  it('fails when one locked-tree entry is removed from the allowlist', () => {
    const res = project({ advisories: [LOCKED()[0]] });
    expect(res.status, res.stderr).toBe(1);
    expect(res.stderr).toMatch(/Unlisted high\/critical advisories \(1\)/);
    expect(res.stderr).toMatch(/dev-pkg GHSA-dddd-dddd-dddd/);
  });

  it('runs and fails when invoked through a symlink to the script', () => {
    const res = project({
      invoke: (proj) => {
        const link = path.join(proj, 'linked-audit-check.mjs');
        symlinkSync(path.join(proj, 'scripts', 'audit-check.mjs'), link);
        return link;
      },
    });
    expect(res.args).toEqual([...AUDIT_ARGS]);
    expect(res.status).toBe(1);
    expect(res.stderr).toMatch(/GHSA-pppp-pppp-pppp/);
  });

  it('runs when invoked through a symlinked directory', () => {
    const res = project({
      advisories: LOCKED(),
      invoke: (proj) => {
        const link = path.join(proj, 'linked-scripts');
        symlinkSync(path.join(proj, 'scripts'), link);
        return path.join(link, 'audit-check.mjs');
      },
    });
    expect(res.status, res.stderr).toBe(0);
    expect(res.stdout).toMatch(/Audit check passed/);
  });

  it('exits 2 with the spawn error when npm is not on PATH', () => {
    const empty = mkdtempSync(path.join(dir, 'empty-'));
    const res = project({ advisories: LOCKED(), env: { PATH: empty } });
    expect(res.status).toBe(2);
    expect(res.stderr).toMatch(/^audit check error: could not run npm audit: .*ENOENT/);
  });

  it('exits 2 and prints npm\'s message for the real unreachable-registry shape', () => {
    const res = project({ advisories: LOCKED(), env: { STUB_OUTPUT: JSON.stringify(UNREACHABLE) } });
    expect(res.status).toBe(2);
    expect(res.stderr).toMatch(/npm audit failed: request to https:\/\/registry\.example\.com\/.*ECONNREFUSED/);
  });

  it('exits 2 without a stack trace on garbage or odd-shaped npm output', () => {
    const odd = (vulns) => JSON.stringify(makeReport(vulns));
    const bodies = [
      'not json',
      'null',
      '[]',
      '{}',
      '"text"',
      odd({ 'prod-pkg': { name: 'prod-pkg', via: [null] } }),
      odd({ 'prod-pkg': { name: 'prod-pkg' } }),
      odd({ 'prod-pkg': null }),
      odd({ 'prod-pkg': { name: 'prod-pkg', via: {} } }),
    ];
    for (const body of bodies) {
      const res = project({ advisories: LOCKED(), env: { STUB_OUTPUT: body } });
      expect(res.status, body).toBe(2);
      expect(res.stderr, body).toMatch(/^audit check error: /);
      expect(res.stderr, body).not.toMatch(/\n\s+at /);
    }
  });
});
