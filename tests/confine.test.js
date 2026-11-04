import { describe, it, expect } from 'vitest'
import { isStrictlyWithin, isCanonicalPath, confineLexically, checkLexically } from '../src/ssh/confine.js'
import { ERROR_CODES } from '../src/errors.js'

const ROOT = '/var/www/example.com/public'

describe('isStrictlyWithin (path-segment comparison)', () => {
  it.each([
    [ROOT, `${ROOT}/wp-config.php`, true],
    [ROOT, `${ROOT}/wp-content/debug.log`, true],
    [`${ROOT}/`, `${ROOT}/index.php`, true],
    ['/', '/etc', true],
    [ROOT, ROOT, false],
    [ROOT, `${ROOT}/`, false],
    [ROOT, '/var/www/example.com', false],
    // Sibling that shares the string prefix but not the last segment.
    [ROOT, '/var/www/example.com/public-backup/wp-config.php', false],
    [ROOT, '/var/www/example.com/publicity', false],
    [ROOT, '/etc/passwd', false],
    [ROOT, `${ROOT}/../secret`, false],
    [ROOT, 'wp-config.php', false],
    ['relative/root', 'relative/root/x', false],
    // `.` and `..` are refused, never collapsed.
    [ROOT, `${ROOT}/wp-content/link/../wp-config.php`, false],
    [ROOT, `${ROOT}/./wp-config.php`, false],
    [`${ROOT}/wp-content/..`, `${ROOT}/wp-config.php`, false]
  ])('root %s, target %s -> %s', (root, target, expected) => {
    expect(isStrictlyWithin(root, target)).toBe(expected)
  })

  it('rejects non-string input', () => {
    expect(isStrictlyWithin(undefined, '/x')).toBe(false)
    expect(isStrictlyWithin(ROOT, undefined)).toBe(false)
  })
})

describe('isCanonicalPath', () => {
  it.each([
    ['/', true],
    [ROOT, true],
    [`${ROOT}/wp-config.php`, true],
    [`${ROOT}/`, false],
    [`${ROOT}//wp-config.php`, false],
    [`${ROOT}/./wp-config.php`, false],
    [`${ROOT}/x/../wp-config.php`, false],
    [`${ROOT}/..`, false],
    ['relative/path', false],
    ['', false],
    [`${ROOT}/a\0b`, false],
    [undefined, false]
  ])('%j -> %s', (p, expected) => {
    expect(isCanonicalPath(p)).toBe(expected)
  })
})

describe('confineLexically', () => {
  it.each([
    ['wp-config.php', 'wp-config.php'],
    ['./wp-config.php', 'wp-config.php'],
    ['wp-content/../wp-config.php', 'wp-config.php'],
    ['wp-content//plugins/x.php', 'wp-content/plugins/x.php']
  ])('accepts %s as %s', (input, expected) => {
    expect(confineLexically(ROOT, input)).toBe(expected)
  })

  it.each([
    ['../../etc/passwd'],
    ['../public-backup/wp-config.php'],
    ['/etc/passwd'],
    ['.'],
    ['wp-content/..'],
    [''],
    ['wp-config.php\0.txt'],
    ['a'.repeat(1025)]
  ])('refuses %j with E_NOT_AVAILABLE', input => {
    expect(() => confineLexically(ROOT, input)).toThrow(expect.objectContaining({ code: ERROR_CODES.NOT_AVAILABLE }))
  })

  it('refuses a relative or missing root', () => {
    expect(() => confineLexically('relative', 'x')).toThrow(expect.objectContaining({ code: ERROR_CODES.NOT_AVAILABLE }))
    expect(() => confineLexically(undefined, 'x')).toThrow(expect.objectContaining({ code: ERROR_CODES.NOT_AVAILABLE }))
  })
})

describe('confineLexically input rules', () => {
  it.each([
    ['%2e%2e/x.php'], ['a%20b.php'], ['a\\b.php'], ['a\u0001b.php'], ['a\u007fb.php'], ['a\u0085b.php'],
    ['a\u202eb.php'], ['a\ufeffb.php'], ['a\u2029b.php'], ['\udc00.php'], ['\u2025/x.php'], ['\uff0e\uff0e/x.php'],
    ['a\uff0fb.php'], ['a\uff3cb.php'], ['\u2024x.php']
  ])('refuses %j', input => {
    expect(() => confineLexically(ROOT, input)).toThrow(expect.objectContaining({ code: ERROR_CODES.NOT_AVAILABLE }))
  })

  it('accepts ordinary non-ASCII names', () => {
    expect(confineLexically(ROOT, 'wp-content/caf\u00e9.txt')).toBe('wp-content/caf\u00e9.txt')
    expect(confineLexically(ROOT, 'wp-content/cafe\u0301.txt')).toBe('wp-content/cafe\u0301.txt')
  })
})

describe('checkLexically', () => {
  const always = () => true

  it('applies the denylist even when the allow rule accepts everything', () => {
    expect(() => checkLexically(ROOT, 'wp-config.php', always)).toThrow(expect.objectContaining({ code: ERROR_CODES.NOT_AVAILABLE }))
    expect(checkLexically(ROOT, './index.php', always)).toBe('index.php')
  })

  it('applies the allow rule to the normalised path', () => {
    const seen = []
    expect(() => checkLexically(ROOT, 'wp-content/../index.php', p => { seen.push(p); return false }))
      .toThrow(expect.objectContaining({ code: ERROR_CODES.NOT_AVAILABLE }))
    expect(seen).toEqual(['index.php'])
  })

  it('fails closed without an allow rule, and accepts only a literal true', () => {
    expect(() => checkLexically(ROOT, 'index.php')).toThrow(expect.objectContaining({ code: ERROR_CODES.INTERNAL }))
    expect(() => checkLexically(ROOT, 'index.php', () => 1)).toThrow(expect.objectContaining({ code: ERROR_CODES.NOT_AVAILABLE }))
  })
})
