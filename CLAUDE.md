# Tenshi-MCP

Local MCP server (stdio transport) that connects to configured WordPress servers over SSH and exposes read-only `read_log` and `read_file` tools for Claude triage sessions. Both tools read over SFTP; neither runs a remote command.

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

Unit tests use `vitest`; no real server needed. SFTP tests run against an in-process SSH server fake built on `ssh2`'s server mode (`tests/helpers/fake-sftp-server.js`, `127.0.0.1`, ephemeral port, generated keys). Tool tests fail if the fake ever receives an exec, shell or other non-SFTP request.

## CI checks

`.github/workflows/ci.yml` runs on every PR and on pushes to `main`, using the Node version in `.nvmrc` (23): `node scripts/audit-check.mjs` first (locally also `npm run audit:check`; it audits `package-lock.json` before anything is installed), then `npm ci` and `npm test`. The audit check fails on any high or critical `npm audit` advisory not listed, with severity, reason, tracking issue and an expiry date at most 60 days ahead, in `.audit-allowlist.json` (expired, malformed, duplicate and stale entries, advisories whose reported severity differs from their entry in either direction, and advisories with an unknown severity fail too; npm offline, omit-dev, `package-lock=false` and `strict-ssl=false` settings are overridden so the lockfile tree is audited). Secret scanning is not in CI yet (waits for the scanning ADR). Run the same three commands locally before opening a PR. `tests/integration.js` is manual and is not run in CI. Details: [CONTRIBUTING.md](CONTRIBUTING.md#ci-checks).

## Manual integration test

Requires a real `servers.json` with valid SSH credentials and SFTP enabled:

```bash
node tests/integration.js <serverId> <siteDomain>
# e.g.: node tests/integration.js example-server example.com
```

## Project structure

```
src/
  index.js              MCP entry point — registers tools, stdio transport
  config/servers.js     Load + validate servers.json (Zod), lookup functions
  errors.js             Fixed error codes returned to the model
  ssh/client.js         Connection pool keyed by server ID, 5-min idle timeout, SFTP channels only
  ssh/sftp.js           Read-only SFTP session facade, 10s per-call deadline
  ssh/confine.js        Lexical and realpath confinement, path-segment comparison
  tools/site.js         Registry lookup for tool calls
  tools/read-log.js     read_log tool — last lines of a log, literal substring filter
  tools/read-file.js    read_file tool — read files within WordPress root

scripts/
  audit-check.mjs       npm audit gate with allowlist (.audit-allowlist.json)

tests/
  helpers/fake-sftp-server.js  In-process SSH/SFTP server fake (ssh2 server mode)
  config.test.js        Unit: registry validation
  client.test.js        Unit: registry guard, host-key seam
  sftp.test.js          Unit: session facade, timeout, session close
  confine.test.js       Unit: path confinement
  read-log.test.js      Unit: read_log against the fake
  read-file.test.js     Unit: read_file against the fake
  refusal-order.test.js Unit: refusals before any network activity
  errors.test.js        Unit: error codes
  boundaries.test.js    Unit: module boundaries of the SFTP layer
  server.test.js        Protocol: server name, tool list, refusal over stdio, env fallback
  audit-check.test.js   Unit: audit allowlist check
  integration.js        Manual: end-to-end SFTP against real server
```

## Server registry (`servers.json`)

Not committed. Path: `TENSHI_MCP_SERVERS_PATH` in the server process environment, default `./servers.json`. Format: see `servers.json.example`, and `docs/specs/` for the full schema.

Each server entry specifies per-site `wordpressRoot` and `logDir` to handle different host layouts (SpinupWP vs custom).

## Security model

Details in the README security model; the design follows the platform ADR on tool-layer remote access (private platform repo). ADR-002's command allowlist is superseded.

1. **Registry allowlist** — only servers and sites in `servers.json` are reachable; unknown sites are refused before any network activity.
2. **No remote commands** — tools use only the read-only SFTP facade in `src/ssh/sftp.js` (realpath, lstat, open for reading, fstat, bounded read, close). Never add an exec, shell or write path, and never import `src/ssh/client.js`, `node-ssh` or `ssh2` from a tool.
3. **Path confinement** — `read_file` paths and log paths are checked lexically in the tool before any connection is opened (keep it that way: refusals must not depend on the server), then resolved with SFTP realpath (non-canonical replies refused) and compared to the canonical root by path segment; the target must be a regular file (lstat before open, fstat after).
4. **Limits** — `read_log`: 500 lines, 51200 bytes, last 256 KB of the log, lines cut at 2000 characters, filter is a literal case-insensitive substring. `read_file`: 51200 bytes. 10-second deadline per call; on expiry the SFTP channel is closed.
5. **Errors** — fixed codes from `src/errors.js`; never echo arguments, server paths or remote error text.

Not covered yet (tracked privately): host-key pinning (`hostVerifierFor` in `src/ssh/client.js` is the seam), sensitive-file policy and redaction (seam: `openConfinedFile` in `src/ssh/confine.js`), detecting a file replaced between the checks and the open, audit log.

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
