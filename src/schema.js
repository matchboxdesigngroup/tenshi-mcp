import { z } from 'zod'

/**
 * A string whose length bounds count UTF-16 code units (`value.length`), as
 * zod 3 did. zod 4's `.min()` and `.max()` count Unicode code points, so a
 * string of astral characters (two units each) could be up to twice as long
 * as `max`. Each bound yields the same issue that zod 4's own check does
 * (code, origin, bound, inclusive; path set by the parent), so callers and
 * messages are unchanged. The bounds are also recorded as JSON Schema
 * `minLength`/`maxLength` metadata, so a listed tool schema shows them as
 * before.
 *
 * @param {{ min?: number, max?: number }} [bounds]
 */
export function boundedString({ min, max } = {}) {
  const schema = z.string().check(ctx => {
    const units = ctx.value.length
    if (min !== undefined && units < min) {
      ctx.issues.push({ origin: 'string', code: 'too_small', minimum: min, inclusive: true, input: ctx.value, continue: true })
    }
    if (max !== undefined && units > max) {
      ctx.issues.push({ origin: 'string', code: 'too_big', maximum: max, inclusive: true, input: ctx.value, continue: true })
    }
  })
  const meta = {}
  if (min !== undefined) meta.minLength = min
  if (max !== undefined) meta.maxLength = max
  return Object.keys(meta).length > 0 ? schema.meta(meta) : schema
}

/**
 * The input schema of a tool: an object of `shape` that strips unknown keys
 * (they are dropped, not refused). The listed JSON Schema keeps
 * "additionalProperties": false: the SDK's zod 3 converter emitted it for
 * objects that strip unknown keys, but zod 4's converter omits it for them in
 * input mode. tests/fixtures/tools-list.json pins the listed result.
 *
 * @param {Record<string, import('zod').ZodType>} shape
 */
export function toolInputSchema(shape) {
  return z.object(shape).meta({ additionalProperties: false })
}
