import { posix } from 'path'
import { ERROR_CODES, ToolError } from '../errors.js'
import { isDenied } from '../policy/paths.js'

// Path confinement and the sensitive-file policy for every tool that reads a
// file. Layers, in order:
//   1. Lexical, before any connection: the caller's relative path must be
//      plain text (no NUL, control or format characters, backslashes, percent
//      signs, look-alikes of `.`, `/` or `\`, or unpaired surrogates), and
//      must stay under the configured root after normalisation. The
//      normalised path must pass the policy: the built-in denylist and the
//      tool's allow rule. Tools call checkLexically before opening a
//      connection; openConfinedFile repeats it.
//   2. Canonical, on the server: the root and the target are resolved with
//      SFTP realpath (symlinks followed). Replies that are not in canonical
//      form are refused, not normalised. The target must lie strictly under
//      the canonical root, compared by path segment, never by string prefix,
//      and its path relative to the canonical root must pass the policy
//      again (a symlink with an allowed name can point at a denied file).
//   3. Type and identity: lstat on the canonical path must show a regular
//      file (not a link); after open, fstat on the handle must show a regular
//      file with the same type, permissions and owner as the lstat, and a
//      second realpath of the canonical path must return it unchanged.
//
// Residual (check then open): SFTP v3 has no O_NOFOLLOW and no way to bind
// an open handle to an inode, so a path swapped between the checks and OPEN
// can make the server open another file. Layer 3 detects a swap that is
// still in place after the open, or that changed the file's type, mode or
// owner; a swap that is reverted before the second realpath and keeps those
// attributes is not detected. Nothing is read from a handle that fails
// layer 3. Hard links cannot be detected at all over SFTP v3 (the attributes
// carry no link count or inode): a hard link inside the root is served as a
// regular file under its own name, subject to the policy and to redaction.
// Server-side confinement (a read-only account, chroot or per-site user) is
// the backstop for both.

const MAX_RELATIVE_PATH_LENGTH = 1024

// C0 and C1 controls, DEL, format characters (bidirectional overrides,
// zero-width characters) and the Unicode line and paragraph separators.
const UNSAFE_CHARS = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u

function notAvailable() {
  return new ToolError(ERROR_CODES.NOT_AVAILABLE)
}

/**
 * Path segments of an absolute POSIX path, or null when a segment is `.` or
 * `..`. Nothing is normalised: a lexical `..` could disagree with what the
 * server resolves physically, so such paths are refused, not collapsed.
 * Empty segments (a trailing or doubled slash) carry no meaning and are
 * skipped.
 * @param {string} p
 */
function segments(p) {
  const parts = p.split('/').filter(s => s !== '')
  return parts.some(s => s === '.' || s === '..') ? null : parts
}

/**
 * True for an absolute path in canonical form, as a conforming SFTP
 * `realpath` returns it: no `.`, `..` or empty segments, no trailing slash,
 * no NUL. `/` itself is canonical.
 * @param {unknown} p
 */
export function isCanonicalPath(p) {
  if (typeof p !== 'string' || !p.startsWith('/') || p.includes('\0')) return false
  if (p === '/') return true
  return p.slice(1).split('/').every(s => s !== '' && s !== '.' && s !== '..')
}

/**
 * True when `target` is strictly below `root`, comparing whole path segments
 * (so `/srv/site` does not contain `/srv/site-backup/x`). Both must be
 * absolute POSIX paths without `.` or `..` segments; anything else is false.
 * @param {string} root
 * @param {string} target
 */
export function isStrictlyWithin(root, target) {
  if (typeof root !== 'string' || typeof target !== 'string') return false
  if (!posix.isAbsolute(root) || !posix.isAbsolute(target)) return false
  const r = segments(root)
  const t = segments(target)
  if (r === null || t === null) return false
  if (t.length <= r.length) return false
  for (let i = 0; i < r.length; i++) {
    if (r[i] !== t[i]) return false
  }
  return true
}

/**
 * True when `text` contains a character that is not `.`, `/` or `\` itself
 * but becomes one of them under Unicode compatibility normalisation (for
 * example full-width `．`, `／`, `＼` or the two-dot leader `‥`). No layer of
 * this server normalises paths that way, but a server or file system might.
 * @param {string} text
 */
function hasPathSyntaxLookalike(text) {
  for (const ch of text) {
    if (ch === '.' || ch === '/' || ch === '\\') continue
    if (/[./\\]/.test(ch.normalize('NFKC'))) return true
  }
  return false
}

/**
 * Check the caller's relative path without touching the network. Returns the
 * normalised relative path (no leading `./`, no `..` segments) or throws
 * E_NOT_AVAILABLE.
 * @param {string} root configured absolute root
 * @param {string} relativePath caller input
 */
export function confineLexically(root, relativePath) {
  if (typeof root !== 'string' || !posix.isAbsolute(root)) throw notAvailable()
  if (typeof relativePath !== 'string' || relativePath.length === 0) throw notAvailable()
  if (relativePath.length > MAX_RELATIVE_PATH_LENGTH) throw notAvailable()
  if (relativePath.includes('\0') || UNSAFE_CHARS.test(relativePath) || !relativePath.isWellFormed()) throw notAvailable()
  // A backslash is a separator on some SFTP servers, and a percent sign
  // starts an encoding that some layer might decode: neither is accepted.
  if (relativePath.includes('\\') || relativePath.includes('%')) throw notAvailable()
  if (hasPathSyntaxLookalike(relativePath)) throw notAvailable()
  if (posix.isAbsolute(relativePath)) throw notAvailable()
  const resolved = posix.resolve(root, relativePath)
  if (!isStrictlyWithin(root, resolved)) throw notAvailable()
  return posix.relative(posix.resolve(root), resolved)
}

/**
 * The policy for a path relative to the root: the built-in denylist always,
 * then the tool's allow rule. Throws E_NOT_AVAILABLE when either refuses.
 * @param {string} relativePath
 * @param {(relativePath: string) => boolean} allow
 */
function enforcePolicy(relativePath, allow) {
  if (typeof allow !== 'function') throw new ToolError(ERROR_CODES.INTERNAL)
  if (isDenied(relativePath)) throw notAvailable()
  if (allow(relativePath) !== true) throw notAvailable()
}

/**
 * Every check that needs no server: lexical confinement, then the policy on
 * the normalised path. Returns the normalised relative path.
 * @param {string} root configured absolute root
 * @param {string} relativePath caller input or fixed log path
 * @param {(relativePath: string) => boolean} allow the tool's allow rule
 */
export function checkLexically(root, relativePath, allow) {
  const normalised = confineLexically(root, relativePath)
  enforcePolicy(normalised, allow)
  return normalised
}

/** Same file type, permissions and owner, as far as the server reported them. */
function sameIdentity(a, b) {
  return a.mode === b.mode && a.uid === b.uid && a.gid === b.gid
}

/**
 * Open `relativePath` under `root` for reading, confined and policy-checked
 * as described at the top of this module. Returns the open handle, its size
 * and the canonical path relative to the canonical root. The caller closes
 * the handle.
 *
 * @param {import('./sftp.js').ReadOnlySftpSession} session
 * @param {string} root configured absolute root (WordPress root or log dir)
 * @param {string} relativePath path under root
 * @param {(relativePath: string) => boolean} allow the tool's allow rule,
 *   applied to the normalised and to the canonical relative path
 * @returns {Promise<{ handle: import('./sftp.js').ReadOnlyHandle, size: number, relativePath: string }>}
 */
export async function openConfinedFile(session, root, relativePath, allow) {
  const normalised = checkLexically(root, relativePath, allow)

  // The server's answers are checked as given: a reply that is not in
  // canonical form is refused rather than normalised here.
  const canonicalRoot = await session.realpath(root)
  if (!isCanonicalPath(canonicalRoot) || canonicalRoot === '/') throw notAvailable()
  const canonicalTarget = await session.realpath(posix.join(canonicalRoot, normalised))
  if (!isCanonicalPath(canonicalTarget)) throw notAvailable()
  if (!isStrictlyWithin(canonicalRoot, canonicalTarget)) throw notAvailable()
  const canonicalRelative = posix.relative(canonicalRoot, canonicalTarget)
  enforcePolicy(canonicalRelative, allow)

  // realpath resolved every link, so the target itself must not be a link
  // and must be a regular file.
  const linkStats = await session.lstat(canonicalTarget)
  if (!linkStats.isFile()) throw notAvailable()

  const handle = await session.openRead(canonicalTarget)
  try {
    const stats = await handle.fstat()
    if (!stats.isFile() || !Number.isSafeInteger(stats.size) || stats.size < 0) throw notAvailable()
    // The opened file must be the one that was checked: same type,
    // permissions and owner, and the path must still resolve to itself.
    if (!sameIdentity(linkStats, stats)) throw notAvailable()
    if (await session.realpath(canonicalTarget) !== canonicalTarget) throw notAvailable()
    return { handle, size: stats.size, relativePath: canonicalRelative }
  } catch (err) {
    await handle.close().catch(() => {})
    throw err
  }
}
