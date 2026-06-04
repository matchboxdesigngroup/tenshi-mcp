# ssh-triage-mcp

Local MCP server (stdio transport) that SSHs into configured WordPress servers and exposes `read_log` and `read_file` tools for Claude triage sessions.

## Quick start

```bash
npm install
cp .env.example .env          # edit SSH_MCP_SERVERS_PATH if needed
cp servers.json.example servers.json  # fill in real server details
npm start
```

## Running tests

```bash
npm test               # run all unit tests once
npm run test:watch     # watch mode
```

Unit tests use `vitest` with mocked SSH — no real server needed.

## Manual integration test

Requires a real `servers.json` with valid SSH credentials:

```bash
node tests/integration.js <serverId> <siteDomain>
# e.g.: node tests/integration.js blueprintcoffee blueprintcoffee.com
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

tests/
  config.test.js        Unit: registry validation
  client.test.js        Unit: allowlist guard
  executor.test.js      Unit: allowlist + timeout
  read-log.test.js      Unit: path resolution + output shape
  read-file.test.js     Unit: path confinement + traversal guard
  integration.js        Manual: end-to-end SSH against real server
```

## Server registry (`servers.json`)

Not committed. Format: see `.env.example` for path config, and `docs/specs/` for full schema.

Each server entry specifies per-site `wordpressRoot` and `logDir` to handle different host layouts (SpinupWP vs custom).

## Security model

Three enforcement layers:
1. **Host allowlist** — only hosts in `servers.json` are connectable
2. **Command allowlist** — only `tail`, `head`, `grep`, `cat`, `ls` permitted in executor
3. **Path confinement** — `read_file` paths must resolve within `wordpressRoot`

Hard caps enforced server-side: 500 lines max, 50 KB max.

## MCP registration (Claude Code)

Add to `.claude/settings.json`:

```json
{
  "mcpServers": {
    "ssh-wp-tools": {
      "command": "node",
      "args": ["/Users/lema/Projects/ssh-triage-mcp/src/index.js"],
      "env": {
        "SSH_MCP_SERVERS_PATH": "/Users/lema/Projects/ssh-triage-mcp/servers.json"
      }
    }
  }
}
```

## Docs

- `docs/specs/` — implementation plan
- `docs/adrs/` — architecture decision records
