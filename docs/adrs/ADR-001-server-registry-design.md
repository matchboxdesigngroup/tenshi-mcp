# ADR-001: Server Registry as Validated JSON with Zod + Module-Singleton Map

**Date:** 2026-06-04  
**Status:** Accepted

> **Update (host-key pins).** Each server entry now also requires `hostKeys`: one to five SHA-256 host-key fingerprints in the OpenSSH form (`SHA256:<base64>`), recorded out of band and changed through a reviewed change. The schema validates and normalises them at load time. A server without valid pins makes the whole registry refuse to load, with an error that names the server id and never the value. A failed load leaves the registry empty. This follows the platform ADR on tool-layer remote access (private platform repository), and the README section "Host-key pins" describes the field. The text below is kept as the original record.

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
