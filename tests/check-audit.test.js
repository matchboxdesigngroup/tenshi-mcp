import { describe, it, expect } from 'vitest';
import { collectAdvisories, evaluate, validateAllowlist } from '../scripts/check-audit.js';

const advisory = (name, id, severity) => ({
  source: 1,
  name,
  dependency: name,
  title: `${name} advisory`,
  url: `https://github.com/advisories/${id}`,
  severity,
  range: '<1.0.0',
});

const report = {
  auditReportVersion: 2,
  vulnerabilities: {
    'pkg-a': { name: 'pkg-a', severity: 'critical', via: [advisory('pkg-a', 'GHSA-aaaa-aaaa-aaaa', 'critical')] },
    'pkg-b': {
      name: 'pkg-b',
      severity: 'high',
      via: [advisory('pkg-b', 'GHSA-bbbb-bbbb-bbbb', 'high'), advisory('pkg-b', 'GHSA-mmmm-mmmm-mmmm', 'moderate')],
    },
    // Derived entry: only references pkg-a, carries no advisory of its own.
    'pkg-c': { name: 'pkg-c', severity: 'critical', via: ['pkg-a'] },
  },
};

const entry = (pkg, id) => ({ id, package: pkg, reason: 'test', issue: '#0' });

describe('collectAdvisories', () => {
  it('returns unique advisories and skips transitive references', () => {
    const ids = collectAdvisories(report).map((a) => a.id).sort();
    expect(ids).toEqual(['GHSA-SABOTAGE', 'GHSA-bbbb-bbbb-bbbb', 'GHSA-mmmm-mmmm-mmmm']);
  });

  it('throws when npm audit returned an error instead of a report', () => {
    expect(() => collectAdvisories({ error: { summary: 'network' } })).toThrow(/network/);
    expect(() => collectAdvisories({})).toThrow(/vulnerabilities/);
  });
});

describe('evaluate', () => {
  it('blocks high and critical advisories that are not allowlisted', () => {
    const result = evaluate(report, { advisories: [] });
    expect(result.blocking.map((a) => a.id).sort()).toEqual(['GHSA-aaaa-aaaa-aaaa', 'GHSA-bbbb-bbbb-bbbb']);
  });

  it('ignores advisories below the threshold', () => {
    const result = evaluate(report, { advisories: [] });
    expect(result.blocking.map((a) => a.id)).not.toContain('GHSA-mmmm-mmmm-mmmm');
  });

  it('passes when every high or critical advisory is allowlisted', () => {
    const allowlist = {
      advisories: [entry('pkg-a', 'GHSA-aaaa-aaaa-aaaa'), entry('pkg-b', 'GHSA-bbbb-bbbb-bbbb')],
    };
    const result = evaluate(report, allowlist);
    expect(result.blocking).toEqual([]);
    expect(result.allowlisted).toHaveLength(2);
    expect(result.stale).toEqual([]);
  });

  it('matches on advisory id and package together', () => {
    const allowlist = { advisories: [entry('other-pkg', 'GHSA-aaaa-aaaa-aaaa'), entry('pkg-b', 'GHSA-bbbb-bbbb-bbbb')] };
    const result = evaluate(report, allowlist);
    expect(result.blocking.map((a) => a.id)).toEqual(['GHSA-aaaa-aaaa-aaaa']);
    expect(result.stale.map((e) => e.package)).toEqual(['other-pkg']);
  });

  it('reports allowlist entries whose advisory no longer appears as stale', () => {
    const allowlist = { advisories: [entry('pkg-z', 'GHSA-zzzz-zzzz-zzzz')] };
    expect(evaluate(report, allowlist).stale.map((e) => e.id)).toEqual(['GHSA-zzzz-zzzz-zzzz']);
  });
});

describe('validateAllowlist', () => {
  it('rejects entries without a reason or tracking issue', () => {
    expect(() => validateAllowlist({ advisories: [{ id: 'GHSA-x', package: 'p', reason: 'r' }] })).toThrow(/issue/);
    expect(() => validateAllowlist({ advisories: [{ id: 'GHSA-x', package: 'p', issue: '#1' }] })).toThrow(/reason/);
  });

  it('rejects a file without an advisories array', () => {
    expect(() => validateAllowlist({})).toThrow(/advisories/);
  });
});
