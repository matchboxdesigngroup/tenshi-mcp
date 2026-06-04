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
})

/** @type {Map<string, z.infer<typeof ServerSchema>>} */
let registry = new Map()

export function loadRegistry() {
  const filePath = resolve(process.env.SSH_MCP_SERVERS_PATH || './servers.json')
  const raw = JSON.parse(readFileSync(filePath, 'utf8'))
  const parsed = RegistrySchema.parse(raw)
  registry = new Map(parsed.servers.map(s => [s.id, s]))
}

/** @returns {z.infer<typeof ServerSchema>} */
export function getServerConfig(serverId) {
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
