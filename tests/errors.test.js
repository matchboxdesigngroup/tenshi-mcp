import { describe, it, expect } from 'vitest'
import { z } from 'zod'
import { ERROR_CODES, ToolError, toToolError } from '../src/errors.js'

describe('tool errors', () => {
  it('uses a fixed message per code', () => {
    expect(new ToolError(ERROR_CODES.NOT_AVAILABLE).message).toBe('E_NOT_AVAILABLE: The requested resource is not available.')
    expect(new ToolError(ERROR_CODES.TIMEOUT).message).toBe('E_TIMEOUT: The operation timed out.')
    expect(new ToolError(ERROR_CODES.HOST_KEY).message).toBe('E_HOST_KEY: The server host key did not match the registry; the connection was refused.')
  })

  it('treats an unknown code as E_INTERNAL', () => {
    const err = new ToolError('E_SOMETHING /etc/passwd')
    expect(err.code).toBe(ERROR_CODES.INTERNAL)
    expect(err.message).not.toContain('/etc/passwd')
  })

  it('never formats the cause into the message', () => {
    const err = toToolError(new Error('No such file: /var/www/secret'))
    expect(err.code).toBe(ERROR_CODES.INTERNAL)
    expect(err.message).toBe('E_INTERNAL: The tool failed unexpectedly.')
    expect(JSON.stringify(err)).not.toContain('/var/www/secret')
  })

  it('maps schema failures to E_INVALID_INPUT without echoing the input', () => {
    const parsed = z.object({ log: z.enum(['debug']) }).safeParse({ log: 'evil;input' })
    const err = toToolError(parsed.error)
    expect(err.code).toBe(ERROR_CODES.INVALID_INPUT)
    expect(err.message).not.toContain('evil')
  })

  it('passes ToolErrors through unchanged', () => {
    const original = new ToolError(ERROR_CODES.TIMEOUT)
    expect(toToolError(original)).toBe(original)
  })
})
