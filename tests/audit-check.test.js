import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  AUDIT_ARGS,
  MAX_EXPIRY_DAYS,
  assertReportShape,
  collectAdvisories,
  evaluate,
  main,
  parseArgs,
  severityRank,
  validateAllowlist,
} from '../scripts/audit-check.mjs';

const SCRIPT = fileURLToPath(new URL('../scripts/audit-check.mjs', import.meta.url));
const TODAY = '2026-10-22';

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

describe('AUDIT_ARGS', () => {
  it('forces online mode, the public registry, and every dependency tree', () => {
    expect([...AUDIT_ARGS]).toEqual([
      'audit',
      '--json',
      '--offline=false',
      '--registry=https://registry.npmjs.org/',
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
});

describe('assertReportShape (fails closed)', () => {
  it('rejects npm error output and keeps a useful detail', () => {
    const offline = { message: 'request to https://registry.example.com/x failed, reason: connect ECONNREFUSED', error: { summary: '', detail: '' } };
    expect(() => assertReportShape(offline)).toThrow(/npm audit failed: .*ECONNREFUSED/);
    expect(() => assertReportShape({ error: { code: 'ENOAUDIT', summary: '', detail: '' } })).toThrow(/ENOAUDIT/);
    expect(() => assertReportShape({ error: {} })).toThrow(/no detail from npm/);
  });

  it('rejects reports that are missing parts or inconsistent', () => {
    expect(() => assertReportShape(null)).toThrow(/not a JSON object/);
    expect(() => assertReportShape({ ...report, auditReportVersion: 1 })).toThrow(/version/);
    expect(() => assertReportShape({ ...report, vulnerabilities: undefined })).toThrow(/vulnerabilities/);
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
  it('ranks unknown and missing severities as critical', () => {
    expect(severityRank('critical')).toBe(4);
    expect(severityRank(undefined)).toBe(4);
    expect(severityRank('not-a-severity')).toBe(4);
    expect(severityRank('moderate')).toBe(2);
  });

  it('blocks an advisory with no severity and formats it without crashing', () => {
    const noSeverity = { ...advisory('pkg-x', 'GHSA-xxxx-xxxx-xxxx', 'high') };
    delete noSeverity.severity;
    const r = makeReport({ 'pkg-x': { name: 'pkg-x', via: [noSeverity] } });
    const result = evaluate(r, { advisories: [] }, 'high', TODAY);
    expect(result.blocking.map((a) => [a.id, a.severity])).toEqual([['GHSA-xxxx-xxxx-xxxx', 'unknown']]);

    const errors = [];
    const code = main(['--allowlist', writeTemp({ advisories: [] })], {
      run: () => ({ status: 1, stdout: JSON.stringify(r) }),
      today: TODAY,
      log: () => {},
      error: (m) => errors.push(m),
    });
    expect(code).toBe(1);
    expect(errors.join('\n')).toMatch(/unknown\s+pkg-x GHSA-xxxx-xxxx-xxxx/);
  });

  it('cannot hide an unknown-severity advisory behind a high entry', () => {
    const odd = advisory('pkg-x', 'GHSA-xxxx-xxxx-xxxx', 'severe');
    const r = makeReport({ 'pkg-x': { name: 'pkg-x', via: [odd] } });
    const result = evaluate(r, { advisories: [entry('pkg-x', 'GHSA-xxxx-xxxx-xxxx', 'high')] }, 'high', TODAY);
    expect(result.rerated.map((a) => a.id)).toEqual(['GHSA-xxxx-xxxx-xxxx']);
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
  });

  it('keeps allowing an advisory re-rated downwards (critical entry, high report)', () => {
    const allowlist = { advisories: [entry('pkg-b', 'GHSA-bbbb-bbbb-bbbb', 'critical')] };
    const result = evaluate(report, allowlist, 'high', TODAY);
    expect(result.allowlisted.map((a) => a.id)).toEqual(['GHSA-bbbb-bbbb-bbbb']);
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

  it('fails the evaluation when an allowlisted entry has expired', () => {
    const allowlist = { advisories: [entry('pkg-a', 'GHSA-aaaa-aaaa-aaaa', 'critical', '2026-01-01')] };
    expect(() => evaluate(report, allowlist, 'high', TODAY)).toThrow(/expired/);
  });
});

describe('validateAllowlist', () => {
  const base = { id: 'GHSA-aaaa-aaaa-aaaa', package: 'p', severity: 'high', reason: 'r', issue: '#1', expires: '2026-11-30' };
  const check = (...entries) => () => validateAllowlist({ advisories: entries }, TODAY);

  it('rejects entries with missing fields', () => {
    for (const field of ['id', 'package', 'severity', 'reason', 'issue', 'expires']) {
      const e = { ...base };
      delete e[field];
      expect(check(e)).toThrow(new RegExp(`missing "${field}"`));
    }
  });

  it('rejects ids that are not GHSA ids and severities other than high or critical', () => {
    expect(check({ ...base, id: 'CVE-2026-0001' })).toThrow(/invalid advisory id/);
    expect(check({ ...base, severity: 'moderate' })).toThrow(/severity "moderate"/);
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
    expect(check(base, { ...base, package: 'q' })()).toHaveLength(2);
  });

  it('lists every problem instead of stopping at the first', () => {
    let message = '';
    try {
      check({ ...base, expires: '2026-01-01' }, { ...base, id: 'bad', package: 'q' }, { ...base, reason: '' })();
    } catch (err) {
      message = err.message;
    }
    expect(message).toMatch(/3 problems/);
    expect(message).toMatch(/expired/);
    expect(message).toMatch(/invalid advisory id/);
    expect(message).toMatch(/missing "reason"/);
  });

  it('rejects a file without an advisories array', () => {
    expect(() => validateAllowlist({})).toThrow(/advisories/);
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

  it('exits 2 when npm output is not JSON or npm cannot run', () => {
    const quiet = { today: TODAY, log: () => {}, error: () => {} };
    const allowlist = writeTemp({ advisories: [] });
    expect(main(['--allowlist', allowlist], { ...quiet, run: () => ({ status: 1, stdout: '' }) })).toBe(2);
    expect(main(['--allowlist', allowlist], { ...quiet, run: () => ({ error: new Error('ENOENT') }) })).toBe(2);
  });
});

// End to end: run the real script with a stub `npm` first on PATH. The stub
// behaves like npm for the settings that matter: offline mode returns no
// advisories, and omit=dev / production hides dev-tree advisories, unless the
// command line overrides them. It also records the arguments it received.
const STUB_NPM = `#!/usr/bin/env node
const fs = require('node:fs');
const args = process.argv.slice(2);
fs.writeFileSync(process.env.STUB_ARGS_FILE, JSON.stringify(args));
const conf = {};
if (process.env.npm_config_userconfig) {
  for (const line of fs.readFileSync(process.env.npm_config_userconfig, 'utf8').split('\\n')) {
    const m = line.match(/^\\s*([\\w-]+)\\s*=\\s*(.*?)\\s*$/);
    if (m) conf[m[1]] = m[2];
  }
}
for (const k of ['offline', 'omit', 'production']) {
  if (process.env['npm_config_' + k] !== undefined) conf[k] = process.env['npm_config_' + k];
}
const cli = (name) => { const a = args.find((x) => x.startsWith('--' + name + '=')); return a && a.split('=')[1]; };
const offline = (cli('offline') ?? conf.offline) === 'true';
const omitDev = (conf.omit === 'dev' || conf.production === 'true') && !args.includes('--include=dev');
const adv = (name, id, severity) => ({ source: 1, name, url: 'https://github.com/advisories/' + id, severity });
let vulns = {
  'prod-pkg': { name: 'prod-pkg', via: [adv('prod-pkg', 'GHSA-pppp-pppp-pppp', 'high')] },
  'dev-pkg': { name: 'dev-pkg', via: [adv('dev-pkg', 'GHSA-dddd-dddd-dddd', 'critical')] },
};
if (offline) vulns = {};
else if (omitDev) delete vulns['dev-pkg'];
process.stdout.write(JSON.stringify({
  auditReportVersion: 2,
  vulnerabilities: vulns,
  metadata: { vulnerabilities: { total: Object.keys(vulns).length }, dependencies: { prod: 1, dev: 1, total: 2 } },
}));
process.exit(Object.keys(vulns).length ? 1 : 0);
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

describe('main with a stubbed npm on PATH', () => {
  function runScript(extraEnv) {
    const argsFile = path.join(dir, 'args.json');
    const env = { ...process.env, PATH: `${dir}${path.delimiter}${process.env.PATH}`, STUB_ARGS_FILE: argsFile, ...extraEnv };
    for (const k of ['npm_config_offline', 'npm_config_omit', 'npm_config_production', 'npm_config_userconfig']) {
      if (!(k in extraEnv)) delete env[k];
    }
    const res = spawnSync(process.execPath, [SCRIPT, '--allowlist', writeTemp({ advisories: [] })], { env, encoding: 'utf8' });
    return { ...res, args: JSON.parse(readFileSync(argsFile, 'utf8')) };
  }

  it('passes exactly AUDIT_ARGS to npm', () => {
    expect(runScript({}).args).toEqual([...AUDIT_ARGS]);
  });

  const cases = [
    ['offline=true in the environment', { npm_config_offline: 'true' }],
    ['omit=dev in the environment', { npm_config_omit: 'dev' }],
    ['production=true in the environment', { npm_config_production: 'true' }],
  ];
  for (const [name, env] of cases) {
    it(`still reports dev and prod advisories with ${name}`, () => {
      const res = runScript(env);
      expect(res.status).toBe(1);
      expect(res.stderr).toMatch(/GHSA-pppp-pppp-pppp/);
      expect(res.stderr).toMatch(/GHSA-dddd-dddd-dddd/);
    });
  }

  it('still reports dev and prod advisories with offline and omit=dev in an .npmrc', () => {
    const npmrc = path.join(dir, 'npmrc');
    writeFileSync(npmrc, 'offline=true\nomit=dev\n');
    const res = runScript({ npm_config_userconfig: npmrc });
    expect(res.status).toBe(1);
    expect(res.stderr).toMatch(/GHSA-pppp-pppp-pppp/);
    expect(res.stderr).toMatch(/GHSA-dddd-dddd-dddd/);
  });
});
