# Tenshi-MCP

Local MCP server (stdio transport) that SSHs into configured WordPress servers and exposes `read_log` and `read_file` tools for Claude triage sessions.

## Status

The tool layer is under security review. Do not expose this server to untrusted input or use it against production servers until hardening lands. Security-relevant details are discussed in the private platform repo, not in public issues. See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution conventions and [CHANGELOG.md](CHANGELOG.md) for changes.

## Quick start

```bash
npm install
cp servers.json.example servers.json  # fill in real server details
npm start                             # reads ./servers.json from the working directory
```

To use another registry file, set `TENSHI_MCP_SERVERS_PATH` in the environment of the process that starts the server (the `env` block of the MCP client entry, or `export` / inline in a shell). The server does not load `.env` files; `.env.example` is only a template.

## Running tests

```bash
npm test               # run all unit tests once
npm run test:watch     # watch mode
```

Unit tests use `vitest` with mocked SSH — no real server needed.

## CI checks

`.github/workflows/ci.yml` runs on every PR and on pushes to `main`, using the Node version in `.nvmrc` (23): `npm ci`, `npm test`, and `node scripts/audit-check.mjs` (locally also `npm run audit:check`). The audit check fails on any high or critical `npm audit` advisory not listed, with severity, reason, tracking issue and an expiry date at most 60 days ahead, in `.audit-allowlist.json` (expired, malformed, duplicate and stale entries, advisories re-rated above their entry and advisories with an unknown severity fail too; npm offline, omit-dev and `package-lock=false` settings are overridden so the lockfile tree is audited). Secret scanning is not in CI yet (waits for the scanning ADR). Run the same three commands locally before opening a PR. `tests/integration.js` is manual and is not run in CI. Details: [CONTRIBUTING.md](CONTRIBUTING.md#ci-checks).

## Manual integration test

Requires a real `servers.json` with valid SSH credentials:

```bash
node tests/integration.js <serverId> <siteDomain>
# e.g.: node tests/integration.js example-server example.com
```

## Project structure

```
src/
  index.js              MCP entry point — registers tools, stdio transport
  config/servers.js     Load + validate servers.json (Zod), lookup functions
  ssh/client.js         Connection pool keyed by server ID, 5-min idle timeout
  ssh/executor.js       runCommand with command allowlist + 10s timeout
  tools/read-log.js     read_log tool — tail log files, optional grep filter
  tools/read-file.js    read_file tool — read files within WordPress root

scripts/
  audit-check.mjs       npm audit gate with allowlist (.audit-allowlist.json)

tests/
  config.test.js        Unit: registry validation
  client.test.js        Unit: allowlist guard
  executor.test.js      Unit: allowlist + timeout
  read-log.test.js      Unit: path resolution + output shape
  read-file.test.js     Unit: path confinement + traversal guard
  server.test.js        Protocol: server name and tool list over stdio, env fallback
  audit-check.test.js   Unit: audit allowlist check
  integration.js        Manual: end-to-end SSH against real server
```

## Server registry (`servers.json`)

Not committed. Path: `TENSHI_MCP_SERVERS_PATH` in the server process environment, default `./servers.json`. Format: see `servers.json.example`, and `docs/specs/` for the full schema.

Each server entry specifies per-site `wordpressRoot` and `logDir` to handle different host layouts (SpinupWP vs custom).

## Security model

Three enforcement layers:
1. **Host allowlist** — only hosts in `servers.json` are connectable
2. **Command allowlist** — only `tail`, `head`, `grep`, `cat`, `ls` permitted in executor
3. **Path confinement** — `read_file` paths must resolve within `wordpressRoot`

Hard caps enforced server-side: 500 lines max, 50 KB max.

## MCP registration

Register the server in your MCP client configuration. For Claude Code, use a project `.mcp.json`: `cp .mcp.json.example .mcp.json` (`.mcp.json` is git-ignored). The example contains:

```json
{
  "mcpServers": {
    "tenshi-mcp": {
      "command": "node",
      "args": ["/path/to/tenshi-mcp/src/index.js"],
      "env": {
        "TENSHI_MCP_SERVERS_PATH": "/path/to/tenshi-mcp/servers.json"
      }
    }
  }
}
```

Replace `/path/to/tenshi-mcp` with the absolute path of your checkout. `SSH_MCP_SERVERS_PATH` is the deprecated former name of `TENSHI_MCP_SERVERS_PATH`: still read when the new name is unset or empty (whitespace only counts as empty), with a startup warning on stderr; removed in M5.

## Docs

- `docs/specs/` — implementation plan
- `docs/adrs/` — architecture decision records
