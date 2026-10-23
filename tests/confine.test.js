import { describe, it, expect } from 'vitest'
import { isStrictlyWithin, isCanonicalPath, confineLexically } from '../src/ssh/confine.js'
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
