import { describe, it, expect } from 'vitest'
import { z } from 'zod'
import { boundedString, toolInputSchema } from '../src/schema.js'

describe('toolInputSchema', () => {
  const schema = toolInputSchema({ site: z.string(), lines: z.number().default(50) })

  it('strips unknown keys, including names of Object.prototype members', () => {
    const parsed = schema.parse({ site: 'example.com', extra: 1, constructor: 'x', toString: 'y', ['__proto__']: { polluted: true } })
    expect(Reflect.ownKeys(parsed).sort()).toEqual(['lines', 'site'])
    expect(parsed).toStrictEqual({ site: 'example.com', lines: 50 })
    expect(Object.getPrototypeOf(parsed)).toBe(Object.prototype)
    expect({}.polluted).toBeUndefined()
  })

  it('lists additionalProperties false and the declared properties only', () => {
    expect(z.toJSONSchema(schema, { target: 'draft-7', io: 'input' })).toStrictEqual({
      $schema: 'http://json-schema.org/draft-07/schema#',
      type: 'object',
      properties: { site: { type: 'string' }, lines: { type: 'number', default: 50 } },
      required: ['site'],
      additionalProperties: false
    })
  })
})

describe('boundedString', () => {
  it('reports the same issue as zod 4 .min()/.max() where both agree (ASCII)', () => {
    const cases = [
      [boundedString({ max: 3 }), z.string().max(3), 'abcd'],
      [boundedString({ min: 2 }), z.string().min(2), 'a'],
      [boundedString({ min: 1 }), z.string().min(1), '']
    ]
    for (const [ours, native, value] of cases) {
      const a = z.object({ v: ours }).safeParse({ v: value })
      const b = z.object({ v: native }).safeParse({ v: value })
      expect(a.success).toBe(false)
      expect(a.error.issues).toStrictEqual(b.error.issues)
    }
  })

  it('counts UTF-16 units where zod 4 .max() counts code points', () => {
    const astral = '\u{1F600}'.repeat(3) // 3 code points, 6 units
    expect(z.string().max(4).safeParse(astral).success).toBe(true)
    expect(boundedString({ max: 4 }).safeParse(astral).success).toBe(false)
    expect(boundedString({ max: 6 }).safeParse(astral).success).toBe(true)
  })

  it('counts UTF-16 units where zod 4 .min() counts code points', () => {
    const astral = '\u{1F600}' // 1 code point, 2 units
    expect(z.string().min(2).safeParse(astral).success).toBe(false)
    expect(boundedString({ min: 2 }).safeParse(astral).success).toBe(true)
  })

  it('reports one issue for a value outside both bounds checks it can fail', () => {
    const r = boundedString({ min: 1, max: 2 }).safeParse('abc')
    expect(r.error.issues.map(i => i.code)).toEqual(['too_big'])
  })

  it('refuses non-strings with the type issue only', () => {
    const r = boundedString({ min: 1, max: 2 }).safeParse(123)
    expect(r.error.issues.map(i => i.code)).toEqual(['invalid_type'])
  })

  it('lists its bounds as minLength and maxLength, also when described or optional', () => {
    const json = s => z.toJSONSchema(s, { target: 'draft-7', io: 'input' })
    expect(json(boundedString({ min: 1, max: 9 }))).toMatchObject({ type: 'string', minLength: 1, maxLength: 9 })
    expect(json(z.object({ f: boundedString({ max: 9 }).optional().describe('d') })).properties.f).toStrictEqual({ type: 'string', maxLength: 9, description: 'd' })
    expect(json(boundedString())).not.toHaveProperty('maxLength')
  })
})
