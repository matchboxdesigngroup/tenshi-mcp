# Tenshi-MCP

A local MCP server (stdio transport) that connects to configured WordPress servers over SSH and exposes two read-only tools — `read_log` and `read_file` — for use in Claude triage sessions. Both tools read over SFTP; neither runs a remote command.

## Status

The tool layer is under security review. Do not expose this server to untrusted input or use it against production servers until hardening lands. Security-relevant details are discussed in the private platform repo, not in public issues. See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution conventions and [CHANGELOG.md](CHANGELOG.md) for changes.

## Overview

During a WordPress incident, you ask Claude things like "show me the last 50 error log lines for example.com" or "read index.php on that site." This MCP server handles the SSH connection, reads the file over SFTP within the configured site directories, applies fixed size and time limits, and returns structured output back to Claude.

**Transport:** stdio (spawned by Claude Code as a child process)  
**Node.js:** ≥20 (ESM)  
**Dependencies:** `@modelcontextprotocol/sdk`, `node-ssh`, `zod`

---

## Production setup

### Prerequisites

- Node.js ≥20
- SSH key with access to your WordPress server(s), for an account with SFTP enabled (the tools use only the SFTP subsystem; a read-only account is recommended)
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

### 3. Set the `TENSHI_MCP_SERVERS_PATH` environment variable (optional)

By default the server loads `./servers.json` relative to its working directory. To use another file, set `TENSHI_MCP_SERVERS_PATH` in the environment of the process that starts the server. The server does not load `.env` files.

- From an MCP client: the `env` block of the server entry in the client configuration (see step 4).
- From a shell: `export TENSHI_MCP_SERVERS_PATH=/absolute/path/to/servers.json` before `npm start`, or inline:

```bash
TENSHI_MCP_SERVERS_PATH=/absolute/path/to/servers.json npm start
```

`.env.example` lists the variable as a template for your shell or process manager; nothing loads it automatically.

`TENSHI_MCP_SERVERS_PATH` was called `SSH_MCP_SERVERS_PATH` before the rename to Tenshi-MCP. The old name still works as a deprecated fallback: it is read only when `TENSHI_MCP_SERVERS_PATH` is unset or empty (whitespace only counts as empty), and the server prints a one-line warning on stderr at startup. If both are set, the new name wins and the warning says the old one is ignored. Values are used as given, not trimmed. The old name is removed in M5; rename it wherever you set it (the `env` block of your MCP client configuration, your shell profile or `export`, your process manager configuration).

### 4. Register the server in your MCP client

Register the server in your MCP client configuration. For Claude Code, use a project `.mcp.json` in this repo, created from the tracked example:

```bash
cp .mcp.json.example .mcp.json
# edit .mcp.json: replace /path/to/tenshi-mcp with the absolute path of your checkout
```

`.mcp.json` is git-ignored, so your local paths stay out of the repo. `.mcp.json.example` contains:

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

Use absolute paths: the client may start the server from a different working directory.

### 5. Verify the connection

Restart Claude Code and run `/mcp` in a new session. You should see `tenshi-mcp` listed as connected with tools `read_log` and `read_file`.

Test it:

```
Use read_log to fetch the last 10 lines of the error log for example.com
```

---

## Tools

### `read_log`

Returns the last lines of a WordPress log file for a configured site.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `site` | string | yes | — | Site domain, e.g. `example.com` |
| `log` | `debug` \| `error` \| `access` | yes | — | Log type |
| `lines` | number | no | 50 | Lines to return from the end of the log (hard cap: 500) |
| `filter` | string | no | — | Case-insensitive substring, matched literally (at most 200 characters) |

Log path resolution (from the registry only; the `log` value selects one of these):

| Log type | Path | Must resolve inside |
|---|---|---|
| `debug` | `{wordpressRoot}/wp-content/debug.log` | `wordpressRoot` |
| `error` | `{logDir}/{site}.error.log` | `logDir` |
| `access` | `{logDir}/{site}.access.log` | `logDir` |

How it reads:

- Only the last 256 KB of the log are read (one bounded SFTP read from the end of the file). Older content is neither returned nor searched. When the window starts mid-file, its first, possibly partial, line is dropped.
- The filter runs in the server process on each line as a plain substring test, ignoring case. It is never turned into a regular expression or sent to the remote server, so characters such as `.`, `*`, `(` or `|` match themselves.
- The last `lines` matching lines are returned. Lines longer than 2000 characters are cut and end with ` [line truncated]`. The returned content is capped at 51200 bytes (UTF-8); when the cap is hit, the oldest selected lines are dropped.

**Example response:**

```json
{
  "site": "example.com",
  "log": "error",
  "requestedLines": 50,
  "returnedLines": 50,
  "content": "2026/06/04 14:23:11 [error] ...",
  "truncated": { "window": true, "longLines": 0, "bytes": false },
  "retrievedAt": "2026-06-04T14:23:15.000Z"
}
```

`truncated.window` means the log is larger than the 256 KB window; `truncated.longLines` counts cut lines; `truncated.bytes` means older lines were dropped to stay under the byte cap.

### `read_file`

Reads the start of a regular file under the WordPress root of a configured site.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `site` | string | yes | — | Site domain, e.g. `example.com` |
| `path` | string | yes | — | Path relative to the WordPress root, e.g. `wp-content/plugins/example/readme.txt` (at most 1024 characters) |
| `maxBytes` | number | no | 10000 | Max bytes to read (hard cap: 51200) |

**Example response:**

```json
{
  "site": "example.com",
  "path": "wp-content/plugins/example/readme.txt",
  "content": "=== Example ===\n...",
  "bytes": 1234,
  "truncated": false,
  "retrievedAt": "2026-06-04T14:23:20.000Z"
}
```

`path` is the file's canonical path relative to the canonical WordPress root (symlinks resolved). `truncated: true` means the file is longer than `maxBytes` and was cut off.

### Errors

Tool failures return a fixed code and message, never the arguments, a server path or remote error text:

| Code | Meaning |
|---|---|
| `E_NOT_AVAILABLE` | Unknown site, path outside the allowed directory, missing file, not a regular file, or permission denied. These cases are deliberately indistinguishable. |
| `E_INVALID_INPUT` | The arguments failed validation inside the tool. Arguments that fail the MCP schema (for example an unknown `log` value) are rejected earlier by the MCP SDK with its own validation message. |
| `E_TIMEOUT` | The call did not finish within 10 seconds; its SFTP channel was closed. |
| `E_REMOTE` | The connection or the SFTP session failed. |
| `E_INTERNAL` | Unexpected failure inside the tool. |

---

## Security model

The tools read over SFTP only. The design follows the platform ADR on tool-layer remote access (kept in the private platform repository); [ADR-002](docs/adrs/ADR-002-command-security-model.md) records the earlier command-based model, which is superseded in part.

**Registry allowlist** (`src/config/servers.js`, `src/ssh/client.js`): only servers and sites defined in `servers.json` are reachable. Unknown sites are refused before any network activity.

**No remote commands** (`src/ssh/sftp.js`): tools get a read-only session facade with exactly `realpath`, `lstat`, open for reading, `fstat`, bounded `read` and `close`. The facade never exposes the SSH connection, an exec or shell channel, or any SFTP write, rename or remove operation, and no tool builds a command string. `src/ssh/client.js` is the only module that uses the SSH library. The unit tests run every tool against an in-process SSH server that records requests and fail if it ever receives an exec, shell or other non-SFTP request.

**Path confinement** (`src/ssh/confine.js`), for `read_file` and for every log read by `read_log`:

1. Before any network activity, the relative path must stay under the configured root after normalisation; absolute paths, NUL bytes and paths over 1024 characters are refused.
2. On the server, the root and the target are resolved with SFTP `realpath` (symlinks followed). The target must lie strictly under the canonical root, compared by whole path segment, not by string prefix.
3. The target must be a regular file (`lstat` before open, `fstat` on the open handle).

**Limits:** `read_log` returns at most 500 lines and 51200 bytes from the last 256 KB of the log; `read_file` returns at most 51200 bytes. Each call has a 10-second deadline covering connect, path checks and reads; on expiry the SFTP channel is closed and the call returns `E_TIMEOUT`.

**Errors** are the fixed codes listed under [Errors](#errors).

**Not covered yet:** the SFTP account's own rights are not narrowed by this server, so use a dedicated read-only account where you control the host. Further hardening (host-key pinning, a sensitive-file policy with redaction, an audit log) is in progress and tracked privately; until it lands, keep to the status note at the top of this file.

---

## Development setup

### Running tests

```bash
npm test               # run all unit tests once
npm run test:watch     # watch mode
```

Tests use `vitest`. No real server is needed: the SFTP tests start an in-process SSH server built on `ssh2`'s server mode (`tests/helpers/fake-sftp-server.js`) on `127.0.0.1` with an ephemeral port and generated keys, serving a small virtual file tree.

| Test file | Covers |
|---|---|
| `tests/config.test.js` | Registry loading and Zod validation |
| `tests/client.test.js` | Registry guard for SFTP channels, host-key verification seam |
| `tests/sftp.test.js` | Read-only session facade, per-call timeout, session close, read budget |
| `tests/confine.test.js` | Lexical confinement and path-segment comparison |
| `tests/read-log.test.js` | Log selection, tail window, line and byte caps, literal filter, confinement, timeout |
| `tests/read-file.test.js` | Confinement (traversal, symlinks, sibling prefixes), byte cap, timeout |
| `tests/errors.test.js` | Fixed error codes and messages |
| `tests/boundaries.test.js` | Module boundaries: only `src/ssh/client.js` uses the SSH library, tools use the facade |
| `tests/server.test.js` | Protocol: server name, tool list, fixed refusal over stdio, env fallback |
| `tests/audit-check.test.js` | Audit allowlist check |

### Manual integration test

Requires a real `servers.json` with valid SSH credentials and SFTP enabled:

```bash
node tests/integration.js <serverId> <siteDomain>
# e.g.: node tests/integration.js myserver example.com
```

The script exercises both tools end-to-end over SFTP and verifies that a path traversal attempt is blocked.

### Smoke-testing the MCP server directly

Send a raw MCP message over stdin to verify the server starts and registers tools correctly:

```bash
printf '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.1"}}}\n{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n' \
  | TENSHI_MCP_SERVERS_PATH=./servers.json node src/index.js
```

Expected: two JSON responses, the second containing a `tools` array with `read_log` and `read_file`.

---

## Project structure

```
src/
  index.js              MCP entry point — registers tools, starts stdio transport
  config/servers.js     Load + validate servers.json (Zod), lookup functions
  errors.js             Fixed error codes returned to the model
  ssh/client.js         Connection pool keyed by server ID, 5-min idle timeout, SFTP channels only
  ssh/sftp.js           Read-only SFTP session facade with a per-call deadline
  ssh/confine.js        Lexical and canonical (realpath) path confinement
  tools/site.js         Registry lookup for tool calls
  tools/read-log.js     read_log tool handler
  tools/read-file.js    read_file tool handler

tests/
  helpers/fake-sftp-server.js  In-process SSH/SFTP server fake (ssh2 server mode)
  config.test.js        Unit: registry validation
  client.test.js        Unit: registry guard, host-key seam
  sftp.test.js          Unit: session facade, timeout, session close
  confine.test.js       Unit: path confinement
  read-log.test.js      Unit: read_log against the fake
  read-file.test.js     Unit: read_file against the fake
  errors.test.js        Unit: error codes
  boundaries.test.js    Unit: module boundaries of the SFTP layer
  server.test.js        Protocol: server name, tool list, refusal over stdio, env fallback
  audit-check.test.js   Unit: audit allowlist check
  integration.js        Manual: end-to-end SFTP against a real server
```

---

## Connection behavior

SSH connections are pooled per server ID with a 5-minute idle timeout. If a connection has been idle for 5 minutes it is closed and a new one is opened on the next tool call. Concurrent first calls to the same server share one connection attempt. Each tool call opens its own SFTP channel on the pooled connection and closes it when the call ends, fails or times out. There is no persistent daemon — the process lives only while Claude Code has it spawned.

Graceful shutdown (`SIGINT` / `SIGTERM`) closes all open SSH connections before exiting.

---

## Troubleshooting

**`tenshi-mcp` not listed in `/mcp`**  
Restart Claude Code after editing settings. Check that the path in `args` is absolute and the file exists.

**`Error: Registry not initialized`**  
The server process failed to start. Check that `TENSHI_MCP_SERVERS_PATH` points to a valid `servers.json`.

**`E_NOT_AVAILABLE`**  
The site is not in `servers.json` (site keys are exact domain matches), or the path does not resolve to a regular file inside the allowed directory (`wordpressRoot` for `read_file` and the debug log, `logDir` for error and access logs), or the account cannot read it. The tool does not say which, by design. Use relative paths only (e.g. `wp-content/plugins/example/readme.txt`). A log file that is a symlink to a location outside its directory is refused.

**`E_TIMEOUT` or `E_REMOTE`**  
The connection, the SFTP subsystem or a read failed or took longer than 10 seconds. Verify the host, port, user, and private key path in `servers.json`, and that SFTP is enabled for the account. Test manually: `sftp -i /path/to/key -P 22 deploy@192.0.2.10`.

---

## Docs

- `docs/specs/` — implementation plan
- `docs/adrs/ADR-001-server-registry-design.md` — why `servers.json` is structured the way it is
- `docs/adrs/ADR-002-command-security-model.md` — the original command-based security model; superseded in part by the SFTP model above (see the note in the ADR)
