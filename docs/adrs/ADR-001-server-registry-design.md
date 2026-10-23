# ADR-001: Server Registry as Validated JSON with Zod + Module-Singleton Map

**Date:** 2026-06-04  
**Status:** Accepted

## Context

The MCP server needs to map site domains (e.g. `example.com`) to SSH connection parameters and filesystem paths. Different servers have different directory layouts (SpinupWP vs custom), so paths must be per-site, not assumed.

## Decision

- Registry is a plain `servers.json` file (not committed), read once at startup via `loadRegistry()`
- Zod validates the full schema at load time — fail fast before any SSH connection is attempted
- The parsed data lives in a module-level `Map` (singleton per process)
- `RegistrySchema` uses `.strict()` to catch config drift (unexpected top-level keys)
- `resolveServerForSite(domain)` provides the primary lookup path for tools — they pass a site domain, not a server ID, since Claude doesn't know which server hosts which site

## Consequences

- **Good:** Config errors surface immediately on startup, not mid-request
- **Good:** Domain-based lookup means tools have a clean interface (just `site: "example.com"`)
- **Good:** Per-site `wordpressRoot` + `logDir` accommodates any server layout
- **Trade-off:** Module singleton means hot-reload of `servers.json` requires a process restart — acceptable for a local MCP server with stable config
- **Initialization guard** added to `getServerConfig` to give a clear error if registry is used before `loadRegistry()` is called
