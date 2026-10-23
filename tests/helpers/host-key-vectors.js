// Fixed host-key test vectors. Each public key was generated for these tests
// only (its private half was deleted) and its fingerprint is the output of
// OpenSSH `ssh-keygen -lf` for that key, so the tests prove that the pins
// accepted by the registry are the ones OpenSSH prints.

import { createHash } from 'crypto'

export const VECTORS = Object.freeze({
  ed25519: Object.freeze({
    publicKey: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAWnKCMkp1JXeQao/sL46CI4Mrd5ltI+FV69e60OoRUF tenshi-mcp-test-vector',
    fingerprint: 'SHA256:BF6uaNA0TFBufM/Fq/DXmgNia6zxt4rhuWZSZQxFM08'
  }),
  ecdsa: Object.freeze({
    publicKey: 'ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDwDrD9hX4yoCrYIpEaq5ddYBGZ9GfOpI9zYjzopCUVpyrdxj6KU/MnvIfF6dv7wZpgbtoi9Us5mos8e+ueumf8= tenshi-mcp-test-vector',
    fingerprint: 'SHA256:82ZinQ+K1l4tDBDBiWUqTrcMkMzdI+hqjSy83bW7Ovc'
  })
})

/** The key blob of an OpenSSH public key line (what ssh2 hashes). */
export function keyBlob(publicKeyLine) {
  return Buffer.from(publicKeyLine.split(' ')[1], 'base64')
}

/** What ssh2 passes to hostVerifier with hostHash 'sha256': lowercase hex. */
export function sha256Hex(publicKeyLine) {
  return createHash('sha256').update(keyBlob(publicKeyLine)).digest('hex')
}

/** A canonical, unpadded OpenSSH-form fingerprint of 32 bytes of `byte`. */
export function fingerprintOfByte(byte) {
  return 'SHA256:' + Buffer.alloc(32, byte).toString('base64').replace(/=+$/, '')
}
