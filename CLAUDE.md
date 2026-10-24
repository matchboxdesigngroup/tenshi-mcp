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
  ssh/host-key.js       Host-key pins: fingerprint form, constant-time verifier
  ssh/sftp.js           Read-only SFTP session facade, 10s per-call deadline
  ssh/confine.js        Lexical and realpath confinement, path-segment comparison, open-time checks
  policy/paths.js       Sensitive-file policy: per-site allowlist, built-in denylist
  policy/redact.js      Credential-line redaction
  tools/site.js         Registry lookup for tool calls
  tools/read-log.js     read_log tool — last lines of a log, literal substring filter
  tools/read-file.js    read_file tool — read files within WordPress root

scripts/
  audit-check.mjs       npm audit gate with allowlist (.audit-allowlist.json)

tests/
  helpers/fake-sftp-server.js  In-process SSH/SFTP server fake (ssh2 server mode)
  helpers/host-key-vectors.js  Fixed public keys with their ssh-keygen fingerprints
  config.test.js        Unit: registry validation, host-key pins
  client.test.js        Unit: registry guard, host verifier
  host-key.test.js      Unit: pin form, constant-time comparison, verifier
  host-key-pinning.test.js  Unit: host-key pinning against the fake
  sftp.test.js          Unit: session facade, timeout, session close
  confine.test.js       Unit: path confinement
  policy.test.js        Unit: denylist, allowlist, redaction
  confinement-policy.test.js  Unit: confinement and policy fixtures against the fake
  site.test.js          Unit: site lookup shape check
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

Each server entry specifies per-site `wordpressRoot` and `logDir` to handle different host layouts (SpinupWP vs custom), and a mandatory `allow` list (`extensions`, `directories`) of what `read_file` may serve. Site names must be host names (never `__proto__`, `constructor` or another `Object.prototype` name); roots must be absolute and canonical (one trailing slash allowed, never `/`). An invalid entry makes the whole registry refuse to load.

Each server also requires `hostKeys`: one to five SHA-256 host-key fingerprints in the OpenSSH form (`SHA256:<base64>`, as `ssh-keygen -lf` prints). Pins are recorded out of band and changed through a reviewed change; the README section "Host-key pins" has the commands and the rotation steps. A server without valid pins makes the whole registry refuse to load (the error names the server id, never the value). Never add trust on first use, an environment override or a switch that skips the check.

## Security model

Details in the README security model; the design follows the platform ADR on tool-layer remote access (private platform repo). ADR-002's command allowlist is superseded.

1. **Registry allowlist** — only servers and sites in `servers.json` are reachable; sites are looked up with `Object.hasOwn` only; unknown sites are refused before any network activity.
2. **Host-key pinning** — `connect` in `src/ssh/client.js` always passes `hostHash: 'sha256'` and the verifier from `hostVerifierFor(server)` (`src/ssh/host-key.js`), on every new connection including reconnects. The verifier compares against every pin in constant time, with no early exit, and rejects during key exchange, before authentication. A mismatch is the fixed `E_HOST_KEY`, with no fingerprint, host or path and no log line. Never connect without the verifier, and never cache a verification result across connections.
3. **No remote commands** — tools use only the read-only SFTP facade in `src/ssh/sftp.js` (realpath, lstat, open for reading, fstat, bounded read, close). Never add an exec, shell or write path, and never import `src/ssh/client.js`, `node-ssh` or `ssh2` from a tool.
4. **Path confinement** — `read_file` paths and log paths are checked lexically in the tool before any connection is opened (keep it that way: refusals must not depend on the server; encodings, backslashes, control, format and look-alike characters are refused), then resolved with SFTP realpath (non-canonical replies and a root resolving to `/` refused) and compared to the canonical root by path segment; the target must be a regular file (lstat before open; after open, fstat must match the lstat's type, mode and owner and a second realpath must return the same path). `read_log` serves only the exact configured log path.
5. **Sensitive-file policy** — `src/policy/paths.js`, enforced inside `checkLexically` and `openConfinedFile` on the normalised and the canonical path: the site's mandatory allowlist (extensions and directories) and the built-in denylist (hidden files, wp-config variants, dumps, backups, archives, keys, credential files; case, Unicode and extension variants). Every new path-reading tool must go through `openConfinedFile` with an allow rule; never relax the denylist from the registry.
6. **Redaction** — `src/policy/redact.js` replaces credential lines in all returned content, before any filter, selection or cut; tools return only `redactedLines`.
7. **Limits** — `read_log`: 500 lines, 51200 bytes, last 256 KB of the log, lines cut at 2000 characters, filter is a literal case-insensitive substring. `read_file`: 51200 bytes. 10-second deadline per call; on expiry the SFTP channel is closed.
8. **Errors** — fixed codes from `src/errors.js` (`E_HOST_KEY` included); never echo arguments, server paths or remote error text.

Not covered yet (tracked privately): a swap reverted between the open and the second realpath that keeps type, mode and owner (SFTP v3 cannot bind a handle to a path), hard links (undetectable over SFTP v3), audit log. Server-side confinement is the backstop.

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
