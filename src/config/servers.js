import { readFileSync } from 'fs'
import { resolve } from 'path'
import { z } from 'zod'
import { boundedString } from '../schema.js'
import { MAX_HOST_KEYS, normaliseFingerprint } from '../ssh/host-key.js'

const SiteSchema = z.object({
  wordpressRoot: boundedString({ min: 1 }),
  logDir: boundedString({ min: 1 })
})

// Issue messages are fixed text: they never contain the rejected value.
// zod 4 ignores the zod 3 required_error and invalid_type_error params, so
// the error function names the two cases of the array type check (missing,
// not an array). zod 4 also runs length checks on anything with a length,
// such as a string that failed the array check; `when` limits them to arrays.
const isArray = payload => Array.isArray(payload.value)
const HostKeysSchema = z.array(z.string(), {
  error: issue => issue.input === undefined
    ? 'host-key pins are required (at least one SHA-256 fingerprint)'
    : 'must be an array of SHA-256 fingerprints'
})
  .min(1, { error: 'at least one SHA-256 fingerprint is required', when: isArray })
  .max(MAX_HOST_KEYS, { error: `at most ${MAX_HOST_KEYS} fingerprints are allowed`, when: isArray })
  .transform((keys, ctx) => {
    const normalised = keys.map(normaliseFingerprint)
    const seen = new Set()
    normalised.forEach((key, i) => {
      if (key === undefined) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: [i], message: 'not a SHA-256 fingerprint in the OpenSSH form SHA256:<base64>' })
      } else if (seen.has(key)) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: [i], message: 'duplicate fingerprint' })
      } else {
        seen.add(key)
      }
    })
    return normalised
  })

const ServerSchema = z.object({
  id: boundedString({ min: 1 }),
  label: boundedString({ min: 1 }),
  host: boundedString({ min: 1 }),
  port: z.number().int().min(1).max(65535),
  user: boundedString({ min: 1 }),
  privateKeyPath: boundedString({ min: 1 }),
  hostKeys: HostKeysSchema,
  sites: z.record(z.string(), SiteSchema)
})

const RegistrySchema = z.object({
  servers: z.array(ServerSchema).min(1)
}).strict()

/**
 * The registry file failed validation. The message names the server (by id
 * when it has a usable one, otherwise by position) and the field, never the
 * rejected value.
 */
export class RegistryError extends Error {
  constructor(message) {
    super(message)
    this.name = 'RegistryError'
  }
}

/** Label for the server at `index` in the raw file: its id, else its position. */
function serverLabel(raw, index) {
  const id = raw?.servers?.[index]?.id
  return typeof id === 'string' && id !== '' && id.length <= 100 && !/[\u0000-\u001f\u007f]/.test(id)
    ? `server "${id}"`
    : `servers[${index}]`
}

/** @param {unknown} raw @param {z.ZodError} error */
function describeIssues(raw, error) {
  return error.issues.map(issue => {
    const [top, index, ...rest] = issue.path
    if (top === 'servers' && typeof index === 'number') {
      const field = rest.length ? rest.join('.') : '(entry)'
      return `${serverLabel(raw, index)}: ${field}: ${issue.message}`
    }
    return `${issue.path.join('.') || '(root)'}: ${issue.message}`
  })
}

/** @type {Map<string, z.infer<typeof ServerSchema>>} */
let registry = new Map()

export const SERVERS_PATH_ENV = 'TENSHI_MCP_SERVERS_PATH'
/** Deprecated name, still read as a fallback. Removed in M5. */
export const DEPRECATED_SERVERS_PATH_ENV = 'SSH_MCP_SERVERS_PATH'
export const DEFAULT_SERVERS_PATH = './servers.json'

/** @returns {string | undefined} the value unchanged, or undefined if empty or whitespace only */
function nonBlank(value) {
  return typeof value === 'string' && value.trim() !== '' ? value : undefined
}

/**
 * Resolve the registry path from the environment.
 *
 * TENSHI_MCP_SERVERS_PATH wins when set. The deprecated SSH_MCP_SERVERS_PATH
 * is used only when the new name is unset or blank. A value that is empty or
 * whitespace only counts as unset, so a blank new name cannot shadow a valid
 * old one; any other value is used verbatim (not trimmed), because a path is
 * taken literally and silently changing it would hide a config mistake
 * instead of surfacing it as a missing file. Either deprecated case
 * emits one warning that names the variables, never their values. Warnings
 * go to stderr (console.warn): stdout carries the MCP stdio protocol.
 *
 * @param {Record<string, string | undefined>} [env]
 * @param {(message: string) => void} [warn]
 * @returns {string} absolute path
 */
export function resolveServersPath(env = process.env, warn = console.warn) {
  const current = nonBlank(env[SERVERS_PATH_ENV])
  const deprecated = nonBlank(env[DEPRECATED_SERVERS_PATH_ENV])
  if (current) {
    if (deprecated) {
      warn(`${DEPRECATED_SERVERS_PATH_ENV} is ignored because ${SERVERS_PATH_ENV} is set; remove ${DEPRECATED_SERVERS_PATH_ENV}, it is removed in M5.`)
    }
    return resolve(current)
  }
  if (deprecated) {
    warn(`${DEPRECATED_SERVERS_PATH_ENV} is deprecated and is removed in M5; rename it to ${SERVERS_PATH_ENV}.`)
    return resolve(deprecated)
  }
  return resolve(DEFAULT_SERVERS_PATH)
}

/**
 * Read and validate the registry. When any server is invalid, including a
 * server without valid host-key pins, it throws RegistryError and the
 * registry is left empty, also if an earlier load had succeeded: nothing is
 * reachable until a valid registry loads (fail closed).
 */
export function loadRegistry() {
  registry = new Map()
  const filePath = resolveServersPath()
  const raw = JSON.parse(readFileSync(filePath, 'utf8'))
  const result = RegistrySchema.safeParse(raw)
  if (!result.success) {
    throw new RegistryError(`Registry is invalid:\n  ${describeIssues(raw, result.error).join('\n  ')}`)
  }
  registry = new Map(result.data.servers.map(s => [s.id, s]))
}

/** @returns {z.infer<typeof ServerSchema>} */
export function getServerConfig(serverId) {
  if (registry.size === 0) throw new Error('Registry not initialized — call loadRegistry() first')
  const server = registry.get(serverId)
  if (!server) throw new Error(`Unknown server: ${serverId}`)
  return server
}

/** @returns {z.infer<typeof SiteSchema> & { serverId: string }} */
export function getSiteConfig(serverId, site) {
  const server = getServerConfig(serverId)
  const siteConfig = server.sites[site]
  if (!siteConfig) throw new Error(`Unknown site: ${site} on server ${serverId}`)
  return { ...siteConfig, serverId }
}

/**
 * Look up which server owns a given site domain.
 * Returns { serverId, server, site } or throws if not found.
 */
export function resolveServerForSite(siteDomain) {
  for (const [serverId, server] of registry) {
    if (server.sites[siteDomain]) {
      return {
        serverId,
        server,
        site: server.sites[siteDomain]
      }
    }
  }
  throw new Error(`No server configured for site: ${siteDomain}`)
}
