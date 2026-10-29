import { readFileSync } from 'fs'
import { resolve } from 'path'
import { z } from 'zod'
import { MAX_HOST_KEYS, normaliseFingerprint } from '../ssh/host-key.js'
import { isValidAllowedDirectory, isValidAllowedExtension } from '../policy/paths.js'

export const MAX_ROOT_LENGTH = 1024
export const MAX_ALLOW_ENTRIES = 50

/**
 * True for a configured root (`wordpressRoot`, `logDir`): an absolute path
 * in canonical form (no `.`, `..` or empty segments), optionally with one
 * trailing slash, without control characters or backslashes, and not `/`
 * itself. A root that fails this would refuse every path at run time, so it
 * is a load error instead.
 * @param {string} p
 */
export function isValidRoot(p) {
  if (typeof p !== 'string' || p.length > MAX_ROOT_LENGTH || !p.startsWith('/')) return false
  if (/[\p{Cc}\p{Cf}\\]/u.test(p) || !p.isWellFormed()) return false
  const trimmed = p.length > 1 && p.endsWith('/') ? p.slice(0, -1) : p
  if (trimmed === '/') return false
  return trimmed.slice(1).split('/').every(s => s !== '' && s !== '.' && s !== '..')
}

/**
 * True for a usable site name: a host name of letters, digits, dots, hyphens
 * and underscores, starting and ending with a letter or digit, with no empty
 * label, and not a property name of Object.prototype (`constructor`,
 * `toString`, ...) or `__proto__`. Log file names are built from it.
 * @param {unknown} name
 */
export function isValidSiteName(name) {
  if (typeof name !== 'string' || name.length > 253) return false
  if (!/^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/.test(name) || name.includes('..')) return false
  return name !== '__proto__' && !(name in Object.prototype)
}

const RootSchema = z.string().refine(isValidRoot, {
  message: 'must be an absolute path without ".", ".." or empty segments, control characters or backslashes, and not "/"'
})

// Issue messages are fixed text: they never contain the rejected value.
const AllowSchema = z.object({
  extensions: z.array(z.string(), { required_error: 'is required', invalid_type_error: 'must be an array of extensions' })
    .min(1, 'at least one extension is required')
    .max(MAX_ALLOW_ENTRIES, `at most ${MAX_ALLOW_ENTRIES} extensions are allowed`)
    .transform((list, ctx) => {
      const lower = list.map(e => e.toLowerCase())
      lower.forEach((ext, i) => {
        if (!isValidAllowedExtension(ext)) {
          ctx.addIssue({ code: z.ZodIssueCode.custom, path: [i], message: 'must be a dot and 1 to 16 letters or digits, and not an always-denied extension' })
        }
      })
      return [...new Set(lower)]
    }),
  directories: z.array(z.string(), { required_error: 'is required', invalid_type_error: 'must be an array of directories' })
    .min(1, 'at least one directory is required')
    .max(MAX_ALLOW_ENTRIES, `at most ${MAX_ALLOW_ENTRIES} directories are allowed`)
    .superRefine((list, ctx) => {
      list.forEach((dir, i) => {
        if (!isValidAllowedDirectory(dir)) {
          ctx.addIssue({ code: z.ZodIssueCode.custom, path: [i], message: 'must be "." or a relative path of plain segments that the built-in denylist does not refuse' })
        }
      })
    })
}, { required_error: 'is required: the extensions and directories read_file may serve', invalid_type_error: 'must be an object with extensions and directories' }).strict()

const SiteSchema = z.object({
  wordpressRoot: RootSchema,
  logDir: RootSchema,
  allow: AllowSchema
})

const SiteNameSchema = z.string().refine(isValidSiteName, {
  message: 'site names must be host names (letters, digits, dots, hyphens, underscores) and not reserved names'
})

// Issue messages are fixed text: they never contain the rejected value.
const HostKeysSchema = z.array(z.string(), {
  required_error: 'host-key pins are required (at least one SHA-256 fingerprint)',
  invalid_type_error: 'must be an array of SHA-256 fingerprints'
})
  .min(1, 'at least one SHA-256 fingerprint is required')
  .max(MAX_HOST_KEYS, `at most ${MAX_HOST_KEYS} fingerprints are allowed`)
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
  id: z.string().min(1),
  label: z.string().min(1),
  host: z.string().min(1),
  port: z.number().int().min(1).max(65535),
  user: z.string().min(1),
  privateKeyPath: z.string().min(1),
  hostKeys: HostKeysSchema,
  sites: z.record(SiteNameSchema, SiteSchema)
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
      // A rejected site name is a value: show it only when it is a valid
      // name (the issue is then about one of its fields).
      const shown = rest[0] === 'sites' && rest.length > 1 && !isValidSiteName(rest[1])
        ? ['sites', '(invalid site name)', ...rest.slice(2)]
        : rest
      const field = shown.length ? shown.join('.') : '(entry)'
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

/**
 * The site's own entry, never an inherited property: `__proto__`,
 * `constructor` and other Object.prototype names are not sites (the loader
 * refuses them as site names as well).
 */
function ownSite(sites, name) {
  return typeof name === 'string' && Object.hasOwn(sites, name) ? sites[name] : undefined
}

/** @returns {z.infer<typeof SiteSchema> & { serverId: string }} */
export function getSiteConfig(serverId, site) {
  const server = getServerConfig(serverId)
  const siteConfig = ownSite(server.sites, site)
  if (!siteConfig) throw new Error(`Unknown site: ${site} on server ${serverId}`)
  return { ...siteConfig, serverId }
}

/**
 * Look up which server owns a given site domain, by own property only.
 * Returns { serverId, server, site } or throws if not found.
 */
export function resolveServerForSite(siteDomain) {
  for (const [serverId, server] of registry) {
    const site = ownSite(server.sites, siteDomain)
    if (site) return { serverId, server, site }
  }
  throw new Error(`No server configured for site: ${siteDomain}`)
}
