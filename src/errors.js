import { ZodError } from 'zod'

/**
 * Fixed error codes returned to the model. A tool error never contains caller
 * input, server paths or remote error text: the message is chosen from this
 * table only. Unknown site, path outside the root, missing file and
 * permission denied all share E_NOT_AVAILABLE, so a caller cannot tell them
 * apart from the output.
 */
export const ERROR_CODES = Object.freeze({
  INVALID_INPUT: 'E_INVALID_INPUT',
  NOT_AVAILABLE: 'E_NOT_AVAILABLE',
  TIMEOUT: 'E_TIMEOUT',
  REMOTE: 'E_REMOTE',
  INTERNAL: 'E_INTERNAL'
})

const MESSAGES = Object.freeze({
  E_INVALID_INPUT: 'The tool arguments are invalid.',
  E_NOT_AVAILABLE: 'The requested resource is not available.',
  E_TIMEOUT: 'The operation timed out.',
  E_REMOTE: 'The remote server could not complete the request.',
  E_INTERNAL: 'The tool failed unexpectedly.'
})

export class ToolError extends Error {
  /**
   * @param {string} code one of ERROR_CODES
   * @param {{ cause?: unknown }} [options] the cause stays in process memory
   *   for debugging and is never formatted into the message
   */
  constructor(code, options = {}) {
    const known = Object.hasOwn(MESSAGES, code) ? code : ERROR_CODES.INTERNAL
    super(`${known}: ${MESSAGES[known]}`)
    this.name = 'ToolError'
    this.code = known
    if (options.cause !== undefined) {
      Object.defineProperty(this, 'cause', { value: options.cause, enumerable: false })
    }
  }
}

/**
 * Map any thrown value to a ToolError. ToolErrors pass through unchanged,
 * schema failures become E_INVALID_INPUT and everything else E_INTERNAL.
 * @param {unknown} err
 * @returns {ToolError}
 */
export function toToolError(err) {
  if (err instanceof ToolError) return err
  if (err instanceof ZodError) return new ToolError(ERROR_CODES.INVALID_INPUT, { cause: err })
  return new ToolError(ERROR_CODES.INTERNAL, { cause: err })
}
