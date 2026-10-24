// Sensitive-file policy for every tool that reads a path. Two layers, both
// evaluated on a path relative to the site's root, without `.` or `..`
// segments (the lexically normalised request and, again, the canonical path
// the server resolved):
//
//   1. Allowlist (mandatory, per site, from the registry): the file's
//      extension and the directory it lies under must both be listed.
//   2. Denylist (built in, always applied, cannot be relaxed by the
//      registry): credential-bearing configuration, environment files,
//      database dumps, backups and archives, key material and hidden files,
//      matched case-insensitively and in their common extension variants.
//
// A refusal by either layer is the same E_NOT_AVAILABLE as a missing file;
// the tools never say which rule applied.
//
// A future directory listing must apply both: list a directory only if it is
// allowed, and hide every entry for which isDenied(`${dir}/${name}`) holds.

/** Final extensions (and second-to-last ones, see isDeniedSegment) that are never served. */
export const DENIED_EXTENSIONS = Object.freeze(new Set([
  // database files and dumps
  'sql', 'sqlite', 'sqlite3', 'db', 'db3', 'dump', 'mdb', 'accdb', 'frm', 'ibd', 'myd', 'myi',
  // backups, editor and temporary copies
  'bak', 'backup', 'bk', 'bkp', 'old', 'orig', 'save', 'sav', 'swp', 'swo', 'swn', 'tmp', 'temp',
  // archives (site backups are usually archives)
  'zip', 'tar', 'gz', 'tgz', 'bz2', 'tbz', 'tbz2', 'xz', 'txz', 'zst', 'lz', 'lzma', '7z', 'rar', 'wpress', 'jpa',
  // keys, certificates and key stores
  'pem', 'key', 'p8', 'p12', 'pfx', 'jks', 'keystore', 'kdbx', 'ppk', 'asc', 'gpg', 'pgp', 'der', 'crt', 'cer', 'csr', 'ovpn',
  // environment files
  'env'
]))

/** File or directory names (the part before the first dot) that are never served. */
const DENIED_STEMS = new Set([
  'credentials', 'credential', 'secrets', 'secret', 'passwords', 'password', 'passwd', 'shadow', 'htpasswd',
  'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519', 'id_ecdsa_sk', 'id_ed25519_sk', 'authorized_keys', 'known_hosts',
  'backup', 'backups', 'dump', 'dumps', 'updraft'
])

/** Exact file names that are never served. */
const DENIED_NAMES = new Set(['auth.json'])

// C0 and C1 controls, DEL, and format characters (bidirectional overrides,
// zero-width characters): never part of a path this server serves.
const UNSAFE_CHARS = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u

/**
 * A segment as the denylist sees it: compatibility-normalised (so full-width
 * and other look-alike forms of ASCII letters and dots fold to ASCII),
 * lower-cased, with trailing dots and spaces removed (`name.php.` and
 * `name.php ` count as `name.php`).
 * @param {string} segment
 */
function foldSegment(segment) {
  return segment.normalize('NFKC').toLowerCase().replace(/[. ]+$/, '')
}

/**
 * True when one path segment is sensitive. `isLast` marks the final segment
 * (the file name); the substring rule for backup directories applies only to
 * directories, so a file such as `{site}.error.log` is not refused because
 * the site's domain contains a word.
 * @param {string} segment
 * @param {boolean} isLast
 */
function isDeniedSegment(segment, isLast) {
  if (segment === '' || UNSAFE_CHARS.test(segment) || !segment.isWellFormed()) return true
  const name = foldSegment(segment)
  if (name === '') return true
  // Hidden files and directories: environment files, VCS data, SSH and
  // cloud credentials, editor swap files, server auth files.
  if (name.startsWith('.')) return true
  // WordPress configuration and its copies (wp-config.php.bak, wp_config.php, ...).
  if (/wp[-_ ]?config/.test(name)) return true
  // Editor backups: name~ and #name#.
  if (name.endsWith('~') || (name.startsWith('#') && name.endsWith('#'))) return true
  if (DENIED_NAMES.has(name)) return true
  const parts = name.split('.')
  // Stems apply to names of up to three parts (secrets.yml, secrets.prod.yml,
  // backup.txt). Log names built from a site's domain have at least four
  // ({label}.{tld}.error.log), so a domain such as backup.example.com does not
  // lose its logs; their extensions are still checked below.
  if (parts.length <= 3 && DENIED_STEMS.has(parts[0])) return true
  // The last two extensions: dump.sql, dump.sql.gz, export.sql.txt, x.env.
  const extensions = parts.slice(1)
  for (const ext of extensions.slice(-2)) {
    if (DENIED_EXTENSIONS.has(ext)) return true
  }
  if (!isLast && name.includes('backup')) return true
  return false
}

/**
 * Segments of a relative path, or null when it is not in the form the policy
 * accepts: no leading slash, no empty, `.` or `..` segment.
 * @param {unknown} relativePath
 * @returns {string[] | null}
 */
function relativeSegments(relativePath) {
  if (typeof relativePath !== 'string' || relativePath === '' || relativePath.startsWith('/')) return null
  const parts = relativePath.split('/')
  return parts.every(s => s !== '' && s !== '.' && s !== '..') ? parts : null
}

/**
 * True when the built-in denylist refuses `relativePath` (relative to the
 * site's root). Anything that is not a well-formed relative path is refused.
 * @param {unknown} relativePath
 */
export function isDenied(relativePath) {
  const parts = relativeSegments(relativePath)
  if (parts === null) return true
  return parts.some((segment, i) => isDeniedSegment(segment, i === parts.length - 1))
}

/**
 * Final extension of a file name, lower-cased with its dot (`.php`), or ''
 * when there is none. A name that starts with a dot has no extension.
 * @param {string} name
 */
export function extensionOf(name) {
  const dot = name.lastIndexOf('.')
  if (dot <= 0 || dot === name.length - 1) return ''
  return name.slice(dot).toLowerCase()
}

/**
 * True when the site's allowlist permits the file `relativePath`: its
 * extension is listed and it lies (at any depth) under a listed directory.
 * Directories compare by whole segment and case-sensitively, as the server's
 * file system does; `.` stands for the root itself. Extensions compare
 * case-insensitively.
 *
 * @param {{ extensions: readonly string[], directories: readonly string[] } | undefined} allow
 * @param {unknown} relativePath
 */
export function isAllowed(allow, relativePath) {
  if (!allow || !Array.isArray(allow.extensions) || !Array.isArray(allow.directories)) return false
  const parts = relativeSegments(relativePath)
  if (parts === null) return false
  const ext = extensionOf(parts[parts.length - 1])
  if (ext === '' || !allow.extensions.includes(ext)) return false
  const dirParts = parts.slice(0, -1)
  return allow.directories.some(dir => {
    if (dir === '.') return true
    const want = dir.split('/')
    return want.length <= dirParts.length && want.every((s, i) => s === dirParts[i])
  })
}

/**
 * True when a configured allowlist directory is valid: `.` or a relative
 * path of plain segments that the denylist does not already refuse.
 * @param {string} dir
 */
export function isValidAllowedDirectory(dir) {
  if (dir === '.') return true
  const parts = relativeSegments(dir)
  if (parts === null || dir.length > 512 || dir.includes('\\')) return false
  return parts.every(s => !isDeniedSegment(s, false))
}

/**
 * True when a configured allowlist extension is valid: a dot and 1 to 16
 * letters or digits, and not on the denylist.
 * @param {string} ext already lower-cased
 */
export function isValidAllowedExtension(ext) {
  return /^\.[a-z0-9]{1,16}$/.test(ext) && !DENIED_EXTENSIONS.has(ext.slice(1))
}
