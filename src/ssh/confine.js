import { posix } from 'path'
import { ERROR_CODES, ToolError } from '../errors.js'

// Path confinement for every tool that reads a file. Two layers:
//   1. Lexical, before any network activity: the relative path must stay
//      under the configured root after normalisation.
//   2. Canonical, on the server: the root and the target are resolved with
//      SFTP realpath (symlinks followed) and the target must lie strictly
//      under the canonical root, compared by path segment, never by string
//      prefix. The target must be a regular file (lstat before open, fstat on
//      the open handle).

const MAX_RELATIVE_PATH_LENGTH = 1024

function notAvailable() {
  return new ToolError(ERROR_CODES.NOT_AVAILABLE)
}

/** @param {string} p absolute POSIX path */
function segments(p) {
  return posix.normalize(p).split('/').filter(s => s !== '' && s !== '.')
}

/**
 * True when `target` is strictly below `root`, comparing whole path segments
 * (so `/srv/site` does not contain `/srv/site-backup/x`). Both must be
 * absolute POSIX paths; anything else is false.
 * @param {string} root
 * @param {string} target
 */
export function isStrictlyWithin(root, target) {
  if (typeof root !== 'string' || typeof target !== 'string') return false
  if (!posix.isAbsolute(root) || !posix.isAbsolute(target)) return false
  const r = segments(root)
  const t = segments(target)
  if (t.length <= r.length) return false
  for (let i = 0; i < r.length; i++) {
    if (r[i] !== t[i]) return false
  }
  return true
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
  if (relativePath.includes('\0')) throw notAvailable()
  if (posix.isAbsolute(relativePath)) throw notAvailable()
  const resolved = posix.resolve(root, relativePath)
  if (!isStrictlyWithin(root, resolved)) throw notAvailable()
  return posix.relative(posix.resolve(root), resolved)
}

/**
 * Open `relativePath` under `root` for reading, confined as described at the
 * top of this module. Returns the open handle, its size and the canonical
 * path relative to the canonical root. The caller closes the handle.
 *
 * Follow-up seam: the sensitive-file allowlist and denylist, and a realpath
 * re-check after open, are evaluated on `canonicalTarget` here, so every
 * path-reading tool gets them at once.
 *
 * @param {import('./sftp.js').ReadOnlySftpSession} session
 * @param {string} root configured absolute root (WordPress root or log dir)
 * @param {string} relativePath path under root
 * @returns {Promise<{ handle: import('./sftp.js').ReadOnlyHandle, size: number, relativePath: string }>}
 */
export async function openConfinedFile(session, root, relativePath) {
  const normalised = confineLexically(root, relativePath)

  const canonicalRoot = await session.realpath(root)
  const canonicalTarget = await session.realpath(posix.join(canonicalRoot, normalised))
  if (!isStrictlyWithin(canonicalRoot, canonicalTarget)) throw notAvailable()

  // realpath resolved every link, so the target itself must not be a link
  // and must be a regular file.
  const linkStats = await session.lstat(canonicalTarget)
  if (!linkStats.isFile()) throw notAvailable()

  const handle = await session.openRead(canonicalTarget)
  try {
    const stats = await handle.fstat()
    if (!stats.isFile() || !Number.isSafeInteger(stats.size) || stats.size < 0) throw notAvailable()
    return {
      handle,
      size: stats.size,
      relativePath: posix.relative(canonicalRoot, canonicalTarget)
    }
  } catch (err) {
    await handle.close().catch(() => {})
    throw err
  }
}
