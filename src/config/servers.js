import { readFileSync } from 'fs'
import { resolve } from 'path'
import { z } from 'zod'

const SiteSchema = z.object({
  wordpressRoot: z.string().min(1),
  logDir: z.string().min(1)
})

const ServerSchema = z.object({
  id: z.string().min(1),
  label: z.string().min(1),
  host: z.string().min(1),
  port: z.number().int().min(1).max(65535),
  user: z.string().min(1),
  privateKeyPath: z.string().min(1),
  sites: z.record(SiteSchema)
})

const RegistrySchema = z.object({
  servers: z.array(ServerSchema).min(1)
}).strict()

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

export function loadRegistry() {
  const filePath = resolveServersPath()
  const raw = JSON.parse(readFileSync(filePath, 'utf8'))
  const parsed = RegistrySchema.parse(raw)
  registry = new Map(parsed.servers.map(s => [s.id, s]))
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
