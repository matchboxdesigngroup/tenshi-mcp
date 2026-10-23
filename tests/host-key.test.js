import { describe, it, expect, vi, beforeEach } from 'vitest'
import { VECTORS, sha256Hex, fingerprintOfByte } from './helpers/host-key-vectors.js'

// Count calls to crypto.timingSafeEqual while keeping its real behaviour, so
// the tests can prove that every pin is compared (no early exit).
const counter = vi.hoisted(() => ({ calls: 0 }))
vi.mock('crypto', async importOriginal => {
  const actual = await importOriginal()
  const timingSafeEqual = (a, b) => { counter.calls++; return actual.timingSafeEqual(a, b) }
  return { ...actual, default: { ...actual, timingSafeEqual }, timingSafeEqual }
})

const {
  MAX_HOST_KEYS,
  normaliseFingerprint,
  constantTimeEqual,
  matchesAnyPin,
  createHostVerifier
} = await import('../src/ssh/host-key.js')

const ED = VECTORS.ed25519
const EC = VECTORS.ecdsa
const ED_HEX = sha256Hex(ED.publicKey)
const ED_BODY = ED.fingerprint.slice('SHA256:'.length)

beforeEach(() => { counter.calls = 0 })

describe('normaliseFingerprint', () => {
  it('accepts the OpenSSH form exactly as ssh-keygen -lf prints it', () => {
    expect(normaliseFingerprint(ED.fingerprint)).toBe(ED.fingerprint)
    expect(normaliseFingerprint(EC.fingerprint)).toBe(EC.fingerprint)
  })

  it('accepts the single = padding and normalises it away', () => {
    expect(normaliseFingerprint(ED.fingerprint + '=')).toBe(ED.fingerprint)
  })

  const rejected = {
    'double padding': ED.fingerprint + '==',
    'lowercase prefix': 'sha256:' + ED_BODY,
    'no prefix': ED_BODY,
    'space after the prefix': 'SHA256: ' + ED_BODY,
    'leading whitespace': ' ' + ED.fingerprint,
    'trailing newline': ED.fingerprint + '\n',
    'lowercase hex digest': ED_HEX,
    'uppercase hex digest': ED_HEX.toUpperCase(),
    'hex digest with the SHA256 prefix': 'SHA256:' + ED_HEX,
    'uppercase hex digest with the SHA256 prefix': 'SHA256:' + ED_HEX.toUpperCase(),
    'MD5 form': 'MD5:' + Array.from({ length: 16 }, (_, i) => (i * 17).toString(16).padStart(2, '0')).join(':'),
    'legacy bare MD5 colon hex': Array.from({ length: 16 }, (_, i) => (i * 13).toString(16).padStart(2, '0')).join(':'),
    'SHA1 form': 'SHA1:' + Buffer.alloc(20, 7).toString('base64').replace(/=+$/, ''),
    'SHA512 form': 'SHA512:' + Buffer.alloc(64, 7).toString('base64').replace(/=+$/, ''),
    'base64url alphabet': 'SHA256:' + Buffer.alloc(32, 0xfb).toString('base64url'),
    'non-canonical trailing bits': 'SHA256:' + ED_BODY.slice(0, -1) + 'F',
    'one character short': ED.fingerprint.slice(0, -1),
    'one character long': ED.fingerprint + 'A',
    'raw public key line': ED.publicKey,
    'empty string': '',
    'prefix only': 'SHA256:'
  }
  for (const [name, value] of Object.entries(rejected)) {
    it(`rejects ${name}`, () => {
      expect(normaliseFingerprint(value)).toBeUndefined()
    })
  }

  it('rejects values that are not strings', () => {
    for (const value of [undefined, null, 42, {}, [ED.fingerprint], Buffer.from(ED.fingerprint)]) {
      expect(normaliseFingerprint(value)).toBeUndefined()
    }
  })
})

describe('constantTimeEqual', () => {
  it('is true for equal buffers and false for unequal ones of the same length', () => {
    expect(constantTimeEqual(Buffer.alloc(32, 1), Buffer.alloc(32, 1))).toBe(true)
    expect(constantTimeEqual(Buffer.alloc(32, 1), Buffer.alloc(32, 2))).toBe(false)
  })

  it('returns false for different lengths, in both orders, without throwing', () => {
    expect(() => constantTimeEqual(Buffer.alloc(32), Buffer.alloc(31))).not.toThrow()
    expect(constantTimeEqual(Buffer.alloc(32), Buffer.alloc(31))).toBe(false)
    expect(constantTimeEqual(Buffer.alloc(31), Buffer.alloc(32))).toBe(false)
    expect(constantTimeEqual(Buffer.alloc(0), Buffer.alloc(32))).toBe(false)
    expect(constantTimeEqual(Buffer.alloc(32), Buffer.alloc(0))).toBe(false)
  })

  it('still runs a constant-time comparison on a length mismatch', () => {
    constantTimeEqual(Buffer.alloc(32), Buffer.alloc(16))
    expect(counter.calls).toBe(1)
  })

  it('returns false for non-buffers without throwing', () => {
    expect(constantTimeEqual('a', 'a')).toBe(false)
    expect(constantTimeEqual(Buffer.alloc(1), undefined)).toBe(false)
  })
})

describe('matchesAnyPin', () => {
  const pins = [1, 2, 3, 4, 5].map(b => Buffer.alloc(32, b))

  it('matches the first and the last of several pins', () => {
    expect(matchesAnyPin(Buffer.alloc(32, 1), pins)).toBe(true)
    expect(matchesAnyPin(Buffer.alloc(32, 5), pins)).toBe(true)
  })

  it('does not match a digest that is not pinned, or an empty pin list', () => {
    expect(matchesAnyPin(Buffer.alloc(32, 9), pins)).toBe(false)
    expect(matchesAnyPin(Buffer.alloc(32, 1), [])).toBe(false)
  })

  it('compares every pin even when the first one matches (no early exit)', () => {
    expect(matchesAnyPin(Buffer.alloc(32, 1), pins)).toBe(true)
    expect(counter.calls).toBe(pins.length)
  })

  it('compares every pin when none matches', () => {
    expect(matchesAnyPin(Buffer.alloc(32, 9), pins)).toBe(false)
    expect(counter.calls).toBe(pins.length)
  })

  it('returns only a boolean, never which pin matched', () => {
    expect(matchesAnyPin(Buffer.alloc(32, 3), pins)).toBe(true)
  })
})

describe('createHostVerifier', () => {
  it('accepts the hex SHA-256 of a host key whose ssh-keygen fingerprint is pinned', () => {
    expect(createHostVerifier([ED.fingerprint])(ED_HEX)).toBe(true)
    expect(createHostVerifier([EC.fingerprint])(sha256Hex(EC.publicKey))).toBe(true)
  })

  it('accepts a key pinned as the first or the last of several pins', () => {
    expect(createHostVerifier([ED.fingerprint, fingerprintOfByte(1), fingerprintOfByte(2)])(ED_HEX)).toBe(true)
    expect(createHostVerifier([fingerprintOfByte(1), fingerprintOfByte(2), fingerprintOfByte(3), fingerprintOfByte(4), ED.fingerprint])(ED_HEX)).toBe(true)
  })

  it('rotation: accepts when only the second of two pins matches', () => {
    expect(createHostVerifier([EC.fingerprint, ED.fingerprint])(ED_HEX)).toBe(true)
  })

  it('compares every configured pin on each verification', () => {
    createHostVerifier([ED.fingerprint, fingerprintOfByte(1), fingerprintOfByte(2)])(ED_HEX)
    expect(counter.calls).toBe(3)
  })

  it('rejects a key that matches no pin', () => {
    expect(createHostVerifier([EC.fingerprint, fingerprintOfByte(1)])(ED_HEX)).toBe(false)
  })

  it('fails closed without usable pins', () => {
    for (const hostKeys of [undefined, null, [], 'SHA256:x', [ED.fingerprint, 'not-a-pin'],
      Array.from({ length: MAX_HOST_KEYS + 1 }, (_, i) => (i === 0 ? ED.fingerprint : fingerprintOfByte(i)))]) {
      expect(createHostVerifier(hostKeys)(ED_HEX)).toBe(false)
    }
  })

  it('rejects anything that is not a lowercase hex SHA-256 digest, without throwing', () => {
    const verify = createHostVerifier([ED.fingerprint])
    for (const value of [ED_HEX.toUpperCase(), ED.fingerprint, ED_HEX.slice(2), ED_HEX + '00',
      Buffer.from(ED_HEX, 'hex'), undefined, null, 0, {}]) {
      expect(() => verify(value)).not.toThrow()
      expect(verify(value)).toBe(false)
    }
  })

  it('rejects the raw key Buffer that ssh2 passes when no hash is applied', () => {
    expect(createHostVerifier([ED.fingerprint])(Buffer.from(ED.publicKey.split(' ')[1], 'base64'))).toBe(false)
  })

  it('reports each rejection once, with no arguments, and never an acceptance', () => {
    const onReject = vi.fn()
    const verify = createHostVerifier([ED.fingerprint], onReject)
    verify(ED_HEX)
    expect(onReject).not.toHaveBeenCalled()
    verify(sha256Hex(EC.publicKey))
    expect(onReject).toHaveBeenCalledTimes(1)
    expect(onReject).toHaveBeenCalledWith()
  })

  it('logs nothing', () => {
    const spies = ['log', 'info', 'warn', 'error', 'debug'].map(m => vi.spyOn(console, m).mockImplementation(() => {}))
    try {
      createHostVerifier([ED.fingerprint])(sha256Hex(EC.publicKey))
      createHostVerifier([])(ED_HEX)
      for (const spy of spies) expect(spy).not.toHaveBeenCalled()
    } finally {
      for (const spy of spies) spy.mockRestore()
    }
  })
})
