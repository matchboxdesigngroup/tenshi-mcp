import { resolveServerForSite } from '../config/servers.js'
import { ERROR_CODES, ToolError } from '../errors.js'

/**
 * Look up a site in the registry for a tool call. Any miss, including names
 * that only exist on Object.prototype (`__proto__`, `constructor`), is
 * E_NOT_AVAILABLE and happens before any network activity.
 * @param {string} site
 * @returns {{ serverId: string, wordpressRoot: string, logDir: string, allow: { extensions: string[], directories: string[] } }}
 */
export function lookupSite(site) {
  let found
  try {
    found = resolveServerForSite(site)
  } catch (err) {
    throw new ToolError(ERROR_CODES.NOT_AVAILABLE, { cause: err })
  }
  const config = found?.site
  if (!config || typeof config.wordpressRoot !== 'string' || typeof config.logDir !== 'string' ||
      !config.allow || !Array.isArray(config.allow.extensions) || !Array.isArray(config.allow.directories)) {
    throw new ToolError(ERROR_CODES.NOT_AVAILABLE)
  }
  return {
    serverId: found.serverId,
    wordpressRoot: config.wordpressRoot,
    logDir: config.logDir,
    allow: { extensions: [...config.allow.extensions], directories: [...config.allow.directories] }
  }
}
