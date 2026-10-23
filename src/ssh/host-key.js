import { timingSafeEqual } from 'crypto'

// Host-key pins. A pin is the SHA-256 fingerprint of a server's public host
// key in the form OpenSSH prints it (`ssh-keygen -lf`): `SHA256:` followed by
// the unpadded base64 of the 32-byte digest. Pins come from the registry
// only, recorded out of band and changed through a reviewed change; there is
// no trust on first use, no environment override and no switch that turns
// verification off.

/** At most this many pins per server: the current key plus a rotation window. */
export const MAX_HOST_KEYS = 5

const PREFIX = 'SHA256:'
const DIGEST_BYTES = 32
// 32 bytes are 43 base64 characters without padding, 44 with one `=`.
const BASE64_BODY = /^[A-Za-z0-9+/]{43}=?$/
const HEX_DIGEST = /^[0-9a-f]{64}$/

/**
 * Normalise a registry pin. Accepts `SHA256:<base64>` with the standard
 * base64 alphabet, unpadded (as OpenSSH prints it) or with its single `=`
 * padding, and returns the unpadded form. The encoding must be canonical, so
 * one key has exactly one accepted spelling (with or without the padding).
 * Anything else (hex, MD5 or SHA1 fingerprints, base64url, a lowercase
 * prefix, whitespace, a raw public key) returns undefined.
 *
 * @param {unknown} value
 * @returns {string | undefined}
 */
export function normaliseFingerprint(value) {
  if (typeof value !== 'string' || !value.startsWith(PREFIX)) return undefined
  const body = value.slice(PREFIX.length)
  if (!BASE64_BODY.test(body)) return undefined
  const unpadded = body.endsWith('=') ? body.slice(0, -1) : body
  const digest = Buffer.from(unpadded, 'base64')
  if (digest.length !== DIGEST_BYTES) return undefined
  // Non-zero trailing bits decode to the same bytes; refuse them.
  if (digest.toString('base64').replace(/=+$/, '') !== unpadded) return undefined
  return PREFIX + unpadded
}

/**
 * Compare two buffers in time that depends only on their lengths. Returns
 * false for different lengths instead of throwing (crypto.timingSafeEqual
 * throws on a length mismatch).
 *
 * @param {Buffer} a
 * @param {Buffer} b
 * @returns {boolean}
 */
export function constantTimeEqual(a, b) {
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) return false
  if (a.length !== b.length) {
    // Keep the work comparable to a real comparison; the result is false.
    timingSafeEqual(a, a)
    return false
  }
  return timingSafeEqual(a, b)
}

/**
 * True when `digest` equals at least one pin. Every pin is compared, in
 * constant time, whatever the earlier results were: there is no early exit
 * and the result does not say which pin matched.
 *
 * @param {Buffer} digest
 * @param {Buffer[]} pins
 * @returns {boolean}
 */
export function matchesAnyPin(digest, pins) {
  let matched = 0
  for (const pin of pins) matched |= constantTimeEqual(pin, digest) ? 1 : 0
  return matched === 1
}

/**
 * Build the ssh2 `hostVerifier` for a list of pins. ssh2 is configured with
 * `hostHash: 'sha256'` and calls the verifier during key exchange, before
 * authentication, with the lowercase hex SHA-256 digest of the host key blob.
 * The verifier returns false (ssh2 then disconnects) when the list is empty
 * or holds an invalid pin, when the argument is not such a digest (for
 * example a raw key Buffer, which ssh2 passes if the hash name is not
 * supported), or when the digest matches no pin. It never throws and never
 * logs. `onReject` is called once per rejection, with no arguments, so the
 * caller can report a fixed error.
 *
 * @param {unknown} hostKeys normalised pins from the registry
 * @param {() => void} [onReject]
 * @returns {(hash: unknown) => boolean}
 */
export function createHostVerifier(hostKeys, onReject = () => {}) {
  const pins = []
  let valid = Array.isArray(hostKeys) && hostKeys.length > 0 && hostKeys.length <= MAX_HOST_KEYS
  if (valid) {
    for (const key of hostKeys) {
      const normalised = normaliseFingerprint(key)
      if (normalised === undefined) { valid = false; break }
      pins.push(Buffer.from(normalised.slice(PREFIX.length), 'base64'))
    }
  }
  return function hostVerifier(hash) {
    const accepted = valid
      && typeof hash === 'string'
      && HEX_DIGEST.test(hash)
      && matchesAnyPin(Buffer.from(hash, 'hex'), pins)
    if (!accepted) onReject()
    return accepted
  }
}
