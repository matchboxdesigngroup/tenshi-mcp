import { describe, it, expect } from 'vitest';
import { collectAdvisories, evaluate, validateAllowlist } from '../scripts/audit-check.mjs';

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

const TODAY = '2026-10-22';
const entry = (pkg, id, expires = '2026-11-30') => ({ id, package: pkg, reason: 'test', issue: '#0', expires });

describe('collectAdvisories', () => {
  it('returns unique advisories and skips transitive references', () => {
    const ids = collectAdvisories(report).map((a) => a.id).sort();
    expect(ids).toEqual(['GHSA-aaaa-aaaa-aaaa', 'GHSA-bbbb-bbbb-bbbb', 'GHSA-mmmm-mmmm-mmmm']);
  });

  it('throws when npm audit returned an error instead of a report', () => {
    expect(() => collectAdvisories({ error: { summary: 'network' } })).toThrow(/network/);
    expect(() => collectAdvisories({})).toThrow(/vulnerabilities/);
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

  it('passes when every high or critical advisory is allowlisted', () => {
    const allowlist = {
      advisories: [entry('pkg-a', 'GHSA-aaaa-aaaa-aaaa'), entry('pkg-b', 'GHSA-bbbb-bbbb-bbbb')],
    };
    const result = evaluate(report, allowlist, 'high', TODAY);
    expect(result.blocking).toEqual([]);
    expect(result.allowlisted).toHaveLength(2);
    expect(result.stale).toEqual([]);
  });

  it('matches on advisory id and package together', () => {
    const allowlist = { advisories: [entry('other-pkg', 'GHSA-aaaa-aaaa-aaaa'), entry('pkg-b', 'GHSA-bbbb-bbbb-bbbb')] };
    const result = evaluate(report, allowlist, 'high', TODAY);
    expect(result.blocking.map((a) => a.id)).toEqual(['GHSA-aaaa-aaaa-aaaa']);
    expect(result.stale.map((e) => e.package)).toEqual(['other-pkg']);
  });

  it('reports allowlist entries whose advisory no longer appears as stale', () => {
    const allowlist = { advisories: [entry('pkg-z', 'GHSA-zzzz-zzzz-zzzz')] };
    expect(evaluate(report, allowlist, 'high', TODAY).stale.map((e) => e.id)).toEqual(['GHSA-zzzz-zzzz-zzzz']);
  });
});

describe('validateAllowlist', () => {
  it('rejects entries without a reason or tracking issue', () => {
    const base = { id: 'GHSA-aaaa-aaaa-aaaa', package: 'p', expires: '2026-11-30' };
    expect(() => validateAllowlist({ advisories: [{ ...base, reason: 'r' }] }, TODAY)).toThrow(/issue/);
    expect(() => validateAllowlist({ advisories: [{ ...base, issue: '#1' }] }, TODAY)).toThrow(/reason/);
  });

  it('rejects entries without an expiry date or with a malformed one', () => {
    const base = { id: 'GHSA-aaaa-aaaa-aaaa', package: 'p', reason: 'r', issue: '#1' };
    expect(() => validateAllowlist({ advisories: [base] }, TODAY)).toThrow(/expires/);
    expect(() => validateAllowlist({ advisories: [{ ...base, expires: 'soon' }] }, TODAY)).toThrow(/YYYY-MM-DD/);
  });

  it('rejects expired entries and accepts entries on their expiry date', () => {
    expect(() => validateAllowlist({ advisories: [entry('p', 'GHSA-aaaa-aaaa-aaaa', '2026-10-21')] }, TODAY)).toThrow(/expired/);
    expect(validateAllowlist({ advisories: [entry('p', 'GHSA-aaaa-aaaa-aaaa', TODAY)] }, TODAY)).toHaveLength(1);
  });

  it('rejects ids that are not GHSA advisory ids', () => {
    expect(() => validateAllowlist({ advisories: [entry('p', 'CVE-2026-0001')] }, TODAY)).toThrow(/invalid advisory id/);
  });

  it('fails the evaluation when an allowlisted entry has expired', () => {
    const allowlist = { advisories: [entry('pkg-a', 'GHSA-aaaa-aaaa-aaaa', '2026-01-01')] };
    expect(() => evaluate(report, allowlist, 'high', TODAY)).toThrow(/expired/);
  });

  it('rejects a file without an advisories array', () => {
    expect(() => validateAllowlist({})).toThrow(/advisories/);
  });
});
