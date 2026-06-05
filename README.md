# ssh-triage-mcp

A local MCP server (stdio transport) that SSHs into configured WordPress servers and exposes two tools — `read_log` and `read_file` — for use in Claude triage sessions.

## Overview

During a WordPress incident, you ask Claude things like "show me the last 50 error log lines for blueprintcoffee.com" or "read wp-config.php on that server." This MCP server handles the SSH connection, enforces a strict security model, and returns structured output back to Claude.

**Transport:** stdio (spawned by Claude Code as a child process)  
**Node.js:** ≥20 (ESM)  
**Dependencies:** `@modelcontextprotocol/sdk`, `node-ssh`, `zod`

---

## Production setup

### Prerequisites

- Node.js ≥20
- SSH key with access to your WordPress server(s)
- Claude Code CLI

### 1. Install dependencies

```bash
npm install
```

### 2. Create your server registry

The server registry (`servers.json`) is not committed. Create it from the example:

```bash
cp servers.json.example servers.json
```

Then edit `servers.json` with your real server details:

```json
{
  "servers": [
    {
      "id": "myserver",
      "label": "My Server",
      "host": "1.2.3.4",
      "port": 22,
      "user": "deploy",
      "privateKeyPath": "~/.ssh/id_rsa",
      "sites": {
        "example.com": {
          "wordpressRoot": "/var/www/example.com/public",
          "logDir": "/var/log/nginx"
        }
      }
    }
  ]
}
```

Field reference:

| Field | Description |
|---|---|
| `id` | Short identifier used internally (no spaces) |
| `label` | Human-readable name |
| `host` | SSH hostname or IP |
| `port` | SSH port (usually 22) |
| `user` | SSH username |
| `privateKeyPath` | Path to private key; `~` is expanded to your home directory |
| `sites` | Map of domain → paths. Keys are site domains (e.g. `example.com`) |
| `wordpressRoot` | Absolute path to WordPress installation root on the server |
| `logDir` | Directory where Nginx/Apache logs for this site live |

Multiple servers and multiple sites per server are supported.

**SpinupWP layout example:**

```json
"sites": {
  "example.com": {
    "wordpressRoot": "/sites/example.com/files/",
    "logDir": "/sites/example.com/logs"
  }
}
```

### 3. Configure the `SSH_MCP_SERVERS_PATH` environment variable (optional)

By default the server loads `./servers.json` relative to the working directory. Override with:

```bash
cp .env.example .env
# edit .env: set SSH_MCP_SERVERS_PATH=/absolute/path/to/servers.json
```

### 4. Register with Claude Code

Add the MCP server to your Claude Code settings. For project-scoped registration, edit `.claude/settings.json` in this repo:

```json
{
  "mcpServers": {
    "ssh-wp-tools": {
      "command": "node",
      "args": ["/Users/yourname/Projects/ssh-triage-mcp/src/index.js"],
      "env": {
        "SSH_MCP_SERVERS_PATH": "/Users/yourname/Projects/ssh-triage-mcp/servers.json"
      }
    }
  }
}
```

For global registration (available in all Claude Code sessions), add the same block to `~/.claude/settings.json`.

Use absolute paths — relative paths break when Claude Code spawns the server from a different working directory.

### 5. Verify the connection

Restart Claude Code and run `/mcp` in a new session. You should see `ssh-wp-tools` listed as connected with tools `read_log` and `read_file`.

Test it:

```
Use read_log to fetch the last 10 lines of the error log for example.com
```

---

## Tools

### `read_log`

Tails lines from a WordPress log file on a configured server.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `site` | string | yes | — | Site domain, e.g. `blueprintcoffee.com` |
| `log` | `debug` \| `error` \| `access` | yes | — | Log type |
| `lines` | number | no | 50 | Lines to tail (hard cap: 500) |
| `filter` | string | no | — | Case-insensitive grep filter |

Log path resolution:

| Log type | Resolved path |
|---|---|
| `debug` | `{wordpressRoot}/wp-content/debug.log` |
| `error` | `{logDir}/{site}.error.log` |
| `access` | `{logDir}/{site}.access.log` |

**Example response:**

```json
{
  "site": "example.com",
  "log": "error",
  "resolvedPath": "/var/log/nginx/example.com.error.log",
  "lineCount": 50,
  "content": "2026/06/04 14:23:11 [error] ...",
  "retrievedAt": "2026-06-04T14:23:15.000Z"
}
```

### `read_file`

Reads a file within the WordPress root of a configured site.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `site` | string | yes | — | Site domain, e.g. `blueprintcoffee.com` |
| `path` | string | yes | — | Relative path within WordPress root, e.g. `wp-config.php` |
| `maxBytes` | number | no | 10000 | Max bytes to read (hard cap: 51200) |

**Example response:**

```json
{
  "site": "example.com",
  "requestedPath": "wp-config.php",
  "resolvedPath": "/var/www/example.com/public/wp-config.php",
  "content": "<?php\n/** WordPress config */\n...",
  "truncated": false,
  "retrievedAt": "2026-06-04T14:23:20.000Z"
}
```

`truncated: true` means the file was larger than `maxBytes` and was cut off.

---

## Security model

Three enforcement layers, each failing closed and independent:

**Layer 1 — Host allowlist** (`src/ssh/client.js`): Only hosts defined in `servers.json` are connectable. `getConnection` validates the server ID before any network activity.

**Layer 2 — Command allowlist** (`src/ssh/executor.js`): Only `tail`, `head`, `grep`, `cat`, `ls` may execute. The check happens before the SSH connection is opened. Binary is parsed as `argv[0]` (whitespace split) to avoid shell metacharacter bypass.

**Layer 3 — Path confinement** (`src/tools/read-file.js`): `path.resolve(wordpressRoot, userPath)` is computed and the result must start with `wordpressRoot`. Blocks `../` traversal before the command string is built.

**Hard caps** enforced regardless of what Claude requests:
- `read_log`: 500 lines max
- `read_file`: 51200 bytes (50 KB) max

A bypass in any one layer does not bypass the others — write operations are structurally impossible.

---

## Development setup

### Running tests

```bash
npm test               # run all unit tests once
npm run test:watch     # watch mode
```

Tests use `vitest` with mocked SSH — no real server is needed. All five test files cover a specific module:

| Test file | Covers |
|---|---|
| `tests/config.test.js` | Registry loading and Zod validation |
| `tests/client.test.js` | Host allowlist guard |
| `tests/executor.test.js` | Command allowlist + timeout |
| `tests/read-log.test.js` | Path resolution and output shape |
| `tests/read-file.test.js` | Path confinement and traversal guard |

### Manual integration test

Requires a real `servers.json` with valid SSH credentials:

```bash
node tests/integration.js <serverId> <siteDomain>
# e.g.: node tests/integration.js myserver example.com
```

The script exercises both tools end-to-end and verifies that a path traversal attempt is blocked.

### Smoke-testing the MCP server directly

Send a raw MCP message over stdin to verify the server starts and registers tools correctly:

```bash
printf '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.1"}}}\n{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n' \
  | SSH_MCP_SERVERS_PATH=./servers.json node src/index.js
```

Expected: two JSON responses, the second containing a `tools` array with `read_log` and `read_file`.

---

## Project structure

```
src/
  index.js              MCP entry point — registers tools, starts stdio transport
  config/servers.js     Load + validate servers.json (Zod), lookup functions
  ssh/client.js         Connection pool keyed by server ID, 5-min idle timeout
  ssh/executor.js       runCommand — command allowlist + 10s timeout
  tools/read-log.js     read_log tool handler
  tools/read-file.js    read_file tool handler

tests/
  config.test.js        Unit: registry validation
  client.test.js        Unit: allowlist guard
  executor.test.js      Unit: allowlist + timeout
  read-log.test.js      Unit: path resolution + output shape
  read-file.test.js     Unit: path confinement + traversal guard
  integration.js        Manual: end-to-end SSH against a real server
```

---

## Connection behavior

SSH connections are pooled per server ID with a 5-minute idle timeout. If a connection has been idle for 5 minutes it is closed and a new one is opened on the next tool call. There is no persistent daemon — the process lives only while Claude Code has it spawned.

Graceful shutdown (`SIGINT` / `SIGTERM`) closes all open SSH connections before exiting.

---

## Troubleshooting

**`ssh-wp-tools` not listed in `/mcp`**  
Restart Claude Code after editing settings. Check that the path in `args` is absolute and the file exists.

**`Error: Registry not initialized`**  
The server process failed to start. Check that `SSH_MCP_SERVERS_PATH` points to a valid `servers.json`.

**`Unknown server` or `No server configured for site`**  
The site domain or server ID is not in `servers.json`. Check spelling — site keys are exact domain matches.

**`Command not allowed`**  
The executor rejected a command. Only `tail`, `head`, `grep`, `cat`, `ls` are permitted.

**`Path escapes WordPress root`**  
The path passed to `read_file` resolves outside `wordpressRoot`. Use relative paths only (e.g. `wp-config.php`, `wp-content/uploads`).

**SSH connection refused / timeout**  
Verify the host, port, user, and private key path in `servers.json`. Test manually: `ssh -i ~/.ssh/id_rsa -p 22 deploy@1.2.3.4`.

---

## Docs

- `docs/specs/` — implementation plan
- `docs/adrs/ADR-001-server-registry-design.md` — why `servers.json` is structured the way it is
- `docs/adrs/ADR-002-command-security-model.md` — rationale for the three-layer security model
