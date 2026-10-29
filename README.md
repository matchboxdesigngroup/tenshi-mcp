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
      "host": "192.0.2.10",
      "port": 22,
      "user": "deploy",
      "privateKeyPath": "~/.ssh/id_rsa",
      "hostKeys": ["SHA256:EXAMPLEonlyReplaceWithTheVerifiedHostKey000"],
      "sites": {
        "example.com": {
          "wordpressRoot": "/var/www/example.com/public",
          "logDir": "/var/log/nginx",
          "allow": {
            "extensions": [".php", ".txt", ".md", ".css", ".js", ".json", ".html"],
            "directories": ["wp-content/plugins", "wp-content/themes"]
          }
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
| `hostKeys` | Required. SHA-256 fingerprints of the server's SSH host key, in the form `ssh-keygen -lf` prints (`SHA256:` plus base64). One to five entries, no duplicates. See [Host-key pins](#host-key-pins) |
| `sites` | Map of domain → site settings. Keys are site domains (e.g. `example.com`): letters, digits, dots, hyphens and underscores, starting and ending with a letter or digit, no empty label. Names of `Object.prototype` properties (`constructor`, `toString`, ...) and `__proto__` are refused |
| `wordpressRoot` | Absolute path to WordPress installation root on the server. No `.`, `..` or empty segments, control characters or backslashes, not `/`; one trailing slash is allowed |
| `logDir` | Directory where Nginx/Apache logs for this site live. Same rules as `wordpressRoot` |
| `allow` | Required. What `read_file` may serve on this site: `extensions` (1 to 50 entries, a dot and 1 to 16 letters or digits, compared case-insensitively) and `directories` (1 to 50 entries, relative to `wordpressRoot`, matched by whole segment and case-sensitively at any depth; `.` means the whole tree). See [Sensitive-file policy](#sensitive-file-policy) |

Multiple servers and multiple sites per server are supported.

A registry with an invalid site name, root or `allow` refuses to load, like a missing host-key pin; the error names the server and the field, never the rejected value. Extensions and directories that the built-in denylist always refuses (for example `.sql` or `wp-content/backups`) are refused in `allow` as well, so a site cannot be configured to expect them.

**Upgrading from a registry without `allow`:** the registry now refuses to load without it. Add `allow` to every site with the extensions and directories the tools should serve, before upgrading.

#### Host-key pins

Every server must list the SHA-256 fingerprints of its SSH host key in `hostKeys`. On every new connection, including a reconnect after a dropped or idle connection, the key the server presents is checked against these pins during the key exchange, before any authentication is sent. A key that matches no pin is refused with `E_HOST_KEY`. There is no trust on first use, no environment variable and no setting that turns the check off.

The registry refuses to load, and the server does not start, if any server has no `hostKeys`, an empty list, more than five entries, a duplicate (after normalising), or an entry that is not in the `SHA256:<base64>` form. Hex digests and MD5 or SHA1 fingerprints are refused. The error names the server id and the field, never the value. The base64 part may carry its `=` padding or not; it is stored without.

Record pins out of band, from a source you already trust, and add them through a reviewed change to your registry. The two commands below only read and print fingerprints. Tenshi-MCP never runs them.

```bash
# 1. Fingerprints of the keys the server presents on the network (not proof by itself)
ssh-keyscan -p 22 192.0.2.10 2>/dev/null | ssh-keygen -lf -
# 256 SHA256:... 192.0.2.10 (ED25519)

# 2. The same fingerprints from a trusted channel: the hosting provider's console,
#    or on the server itself through a console or session you already trust
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

Pin a fingerprint only when steps 1 and 2 agree. `ssh-keyscan` alone trusts whatever answers at that address, so it is not verification. Use the key type the client negotiates. The SSH library (`ssh2`) prefers Ed25519, then ECDSA, then RSA, and uses the first of these that the server offers. If you are unsure, pin each verified host-key type the server offers. Each one counts toward the five entries.

**Rotation:** before the server's host key changes, add the new fingerprint next to the old one (up to five entries), deploy that registry, rotate the key on the server, then remove the old fingerprint in a second change. While both are listed, either key is accepted.

**Upgrading from a registry without pins:** the registry now refuses to load without `hostKeys`. Add the field to every server, with fingerprints obtained as above, before upgrading.

**SpinupWP layout example:**

```json
"sites": {
  "example.com": {
    "wordpressRoot": "/sites/example.com/files/",
    "logDir": "/sites/example.com/logs",
    "allow": { "extensions": [".php", ".txt"], "directories": ["wp-content/plugins"] }
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

| Log type | Path | Root |
|---|---|---|
| `debug` | `{wordpressRoot}/wp-content/debug.log` | `wordpressRoot` |
| `error` | `{logDir}/{site}.error.log` | `logDir` |
| `access` | `{logDir}/{site}.access.log` | `logDir` |

A log is served only at exactly this path: resolved with SFTP `realpath`, the file must be the configured path under the canonical root. A log that is a symlink, even to another file inside the root, is refused, and so is a log under a directory that is a symlink. The root itself may be a symlink. The built-in denylist applies to log paths as well; the site's `allow` list does not (the three paths above are `read_log`'s own allowlist).

How it reads:

- Only the last 256 KB of the log are read (one bounded SFTP read from the end of the file). Older content is neither returned nor searched. When the window starts mid-file, its first, possibly partial, line is dropped.
- The filter runs in the server process on each line as a plain substring test, ignoring case. It is never turned into a regular expression or sent to the remote server, so characters such as `.`, `*`, `(` or `|` match themselves.
- The last `lines` matching lines are returned. Lines longer than 2000 characters are cut (never inside a surrogate pair) and end with ` [line truncated]`. The returned content is capped at 51200 bytes (UTF-8); when the cap is hit, the oldest selected lines are dropped.
- Lines that look like credentials are replaced by `[redacted credential line]` before anything else runs on them (see [Credential redaction](#credential-redaction)), so the filter, the line count and the caps only ever see redacted lines. The partial first line of a window is classified with the rest (it can carry the key of a value on the next line) and then dropped.
- The byte caps count the UTF-8 bytes of the content before the result is serialised as JSON. The serialised text can be larger: control characters are escaped (up to 6 bytes each), and bytes that are not valid UTF-8 are shown as U+FFFD (3 bytes each).

**Example response:**

```json
{
  "site": "example.com",
  "log": "error",
  "requestedLines": 50,
  "returnedLines": 50,
  "content": "2026/06/04 14:23:11 [error] ...",
  "truncated": { "window": true, "longLines": 0, "bytes": false },
  "redactedLines": 0,
  "retrievedAt": "2026-06-04T14:23:15.000Z"
}
```

`truncated.window` means the log is larger than the 256 KB window; `truncated.longLines` counts cut lines; `truncated.bytes` means older lines were dropped to stay under the byte cap; `redactedLines` counts the returned lines that were replaced by the redaction marker.

### `read_file`

Reads the start of a regular file under the WordPress root of a configured site. The file must pass the site's `allow` list and the built-in denylist (see [Sensitive-file policy](#sensitive-file-policy)), and credential lines are redacted before the content is returned.

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
  "redactedLines": 0,
  "retrievedAt": "2026-06-04T14:23:20.000Z"
}
```

`path` is the file's canonical path relative to the canonical WordPress root (symlinks resolved). `truncated: true` means the file is longer than `maxBytes` and was cut off. `bytes` counts the returned (redacted) content; `redactedLines` counts the lines replaced by the redaction marker. Every line is classified on its whole text before the content is cut: the tool reads up to 4096 bytes past `maxBytes`, so the line the cap falls in is judged on its text beyond the cut, and the choice of `maxBytes` never changes which lines are redacted. A redacted line is returned only as the whole marker, never in part. Markers count toward `maxBytes`: when they make the content longer, the last lines are dropped (and still counted in `redactedLines`) and `truncated` is `true`. An ordinary line can be cut at the cap; such a cut never ends inside a multibyte UTF-8 character: an incomplete character at the cut is dropped, so `bytes` can be up to 3 less than `maxBytes`. The byte caps count the UTF-8 bytes of the content before the result is serialised as JSON. The serialised text can be larger: control characters are escaped (up to 6 bytes each), and bytes that are not valid UTF-8 are shown as U+FFFD (3 bytes each).

### Errors

Tool failures return a fixed code and message, never the arguments, a server path or remote error text:

| Code | Meaning |
|---|---|
| `E_NOT_AVAILABLE` | Unknown site, path outside the root, path refused by the site's `allow` list or the built-in denylist, missing file, not a regular file, file changed between the checks and the open, or permission denied. These cases are deliberately indistinguishable: the result is byte-identical. |
| `E_INVALID_INPUT` | The arguments failed validation inside the tool (for example a `path` over 1024 characters). Arguments that fail the MCP schema (for example an unknown `log` value) are rejected earlier by the MCP SDK with its own validation message. |
| `E_TIMEOUT` | The call did not finish within 10 seconds; its SFTP channel was closed. |
| `E_REMOTE` | The connection or the SFTP session failed. |
| `E_HOST_KEY` | The server presented an SSH host key that matches none of its `hostKeys` pins. The connection was closed before authentication. The message never says which key was expected or received. |
| `E_INTERNAL` | Unexpected failure inside the tool. |

---

## Security model

The tools read over SFTP only. The design follows the platform ADR on tool-layer remote access (kept in the private platform repository); [ADR-002](docs/adrs/ADR-002-command-security-model.md) records the earlier command-based model, which is superseded in part.

**Registry allowlist** (`src/config/servers.js`, `src/ssh/client.js`): only servers and sites defined in `servers.json` are reachable. Sites are looked up by own property (`Object.hasOwn`), and site names must be host names, so `__proto__`, `constructor` and other `Object.prototype` names are never sites. Unknown sites are refused before any network activity.

**Host-key pinning** (`src/ssh/host-key.js`, `src/ssh/client.js`): every connection, including each reconnect, passes `ssh2` a host verifier for that server's `hostKeys` pins (`hostHash: 'sha256'`). The verifier compares the presented key's digest with every pin in constant time, without stopping at the first mismatch, and rejects during the key exchange. A mismatch therefore sends no authentication request and opens no SFTP channel, and the call fails with the fixed `E_HOST_KEY`. A server without valid pins cannot be loaded, and the verifier would reject every key anyway. Mismatches are not logged: no log line carries fingerprints or host details until an audit log exists. See [Host-key pins](#host-key-pins).

**No remote commands** (`src/ssh/sftp.js`): tools get a read-only session facade with exactly `realpath`, `lstat`, open for reading, `fstat`, bounded `read` and `close`. The facade never exposes the SSH connection, an exec or shell channel, or any SFTP write, rename or remove operation, and no tool builds a command string. `src/ssh/client.js` is the only module that uses the SSH library. The unit tests run every tool against an in-process SSH server that records requests and fail if it ever receives an exec, shell or other non-SFTP request.

**Path confinement** (`src/ssh/confine.js`), for `read_file` and for every log read by `read_log`:

1. Before any network activity, the relative path must be plain text and stay under the configured root after normalisation. Refused: absolute paths, NUL, control and format characters (bidirectional overrides, zero-width characters, line separators), unpaired surrogates, backslashes (a separator on some SFTP servers), percent signs (so no encoded form such as `%2e%2e` can be decoded by any layer), and characters that become `.`, `/` or `\` under Unicode compatibility normalisation (full-width forms, the two-dot leader). Paths over 1024 characters fail argument validation. The normalised path must also pass the sensitive-file policy. These refusals, like unknown sites, are made before a connection is opened, so they return `E_NOT_AVAILABLE` even when the server is unreachable.
2. On the server, the root and the target are resolved with SFTP `realpath` (symlinks followed). A reply that is not in canonical form (a `.`, `..` or empty segment, such as a doubled slash) is refused, not normalised, and a root that resolves to `/` is refused. The target must lie strictly under the canonical root, compared by whole path segment, not by string prefix, and its path relative to the canonical root must pass the sensitive-file policy again (a symlink with an allowed name can point at a denied file).
3. The target must be a regular file: `lstat` before open must show a regular file, not a link; after open, `fstat` on the handle must show a regular file with the same type, permissions and owner, and a second `realpath` must return the same path. Nothing is read from a handle that fails these checks.

#### Sensitive-file policy

`src/policy/paths.js`, applied by `src/ssh/confine.js` to every path-reading tool, on the normalised request and again on the resolved path:

- **Allowlist (mandatory, per site):** `read_file` serves a file only if its extension is in the site's `allow.extensions` and it lies under one of `allow.directories`. A file without an extension is never served. `read_log` serves only its three fixed log paths.
- **Denylist (built in, second layer, cannot be relaxed by the registry):** hidden files and directories (any segment starting with `.`: `.env` and its variants, `.git`, `.ssh`, `.htaccess`, `.htpasswd`, ...); any name containing `wp-config` (also `wp_config`, `wpconfig`); editor backups (`name~`, `#name#`); database, dump, backup, archive, key and certificate extensions in either of the last two extensions (`.sql`, `.sqlite`, `.db`, `.dump`, `.bak`, `.old`, `.orig`, `.swp`, `.zip`, `.tar`, `.gz`, `.7z`, `.wpress`, `.pem`, `.key`, `.p12`, `.crt`, `.env`, ...; so `dump.sql.gz` and `export.sql.txt` are refused); These extensions are refused wherever they appear in the name (`dump.sql.1.txt`, `server.key.2026.txt`). Also refused: credential and backup file names (`credentials`, `secrets`, `passwords`, `id_rsa`, `authorized_keys`, `backup`, `dump`, `auth.json`, ...) with any number of parts; any name containing `backup`; names with the words `dump`, `bak`, `credentials`, `secrets`, `passwords` and similar; directories named with `old`, `orig`, `sql`, `database` or those words (`db-dumps/`, `bak/`, `old/`); configuration files named for an environment (`local-config.php`, `production-config.php`, `db-config.php`, `settings.local.php`, `wp.config.php`). For `read_log` only, the site's own name at the start of its log file names comes from the registry and is skipped, so a site such as `backup.example.com` keeps its logs; the rest of the name is checked. Names are compared after Unicode compatibility normalisation and lower-casing, with trailing dots and spaces removed, so `WP-CONFIG.PHP`, full-width forms and `wp-config.php.` are refused too.
- A future directory listing must apply both: list only allowed directories and hide every entry the denylist refuses.

#### Credential redaction

`src/policy/redact.js`: before any content leaves the process, every line that looks like it carries a credential is replaced as a whole by `[redacted credential line]`. The rules cover credential-like names followed by an assignment in the common syntaxes (PHP constants and array keys, `var_dump` and `print_r` output, JSON, YAML, INI, environment files, XML elements), with the value on the next line or in a YAML block scalar redacted too; credential-like query-string parameters (keys, tokens, signatures, codes, nonces); any user information in a URL; `Bearer`/`Basic` values; password options on command lines; prose such as "the password is"; cloud key ids, JSON web tokens and well-known token prefixes; private key blocks (also without an END line, and every line above an END line whose BEGIN is outside the text); and base64-only lines with mixed case and digits (key bodies). Lines are classified on their whole text before any filter, selection or cut (see `read_file` and `read_log` above). Every rule is linear in the line length; the tests check 1 MB hostile lines. Tools return only the number of redacted lines (`redactedLines`), never the redacted text. The rules are heuristics: they over-redact rather than under-redact, but a secret in a format they do not recognise is returned. The allowlist and denylist are the primary control.

**Limits:** `read_log` returns at most 500 lines and 51200 bytes from the last 256 KB of the log; `read_file` returns at most 51200 bytes. Each call has a 10-second deadline covering connect, path checks and reads; on expiry the SFTP channel is closed and the call returns `E_TIMEOUT`.

**Errors** are the fixed codes listed under [Errors](#errors).

**Not covered yet (residuals):**

- The SFTP account's own rights are not narrowed by this server, so use a dedicated read-only account where you control the host; server-side confinement (a read-only account, chroot or a per-site user) is the backstop for the check-then-open and hard-link items below.
- Check then open: SFTP v3 has no `O_NOFOLLOW` and cannot bind an open handle to the inode that was checked, so a path swapped between the checks and the open can make the server open another file. The checks after the open detect a swap that is still in place, or that changed the file's type, permissions or owner, and nothing is read in that case. A swap that keeps the file's type, permissions and owner and is undone before the second `realpath` is not detected, so another file's content can be returned (with redaction applied).
- Hard links cannot be detected over SFTP v3 (the attributes carry no link count or inode). A hard link inside the root to a file elsewhere, also one put in place of a checked file with the same attributes, is served under its own name if that name passes the policy, with redaction applied.
- Refusals are byte-identical, but not identical in cost: a refusal made before any connection (unknown site, lexical or policy refusal of the request) sends no request, and a refusal on the server takes a different number of SFTP round trips depending on where it is decided (for example, a path whose resolved target is outside the root or denied, compared with a missing one). Timing can therefore tell some refusal kinds apart; it does not reveal file contents or whether a file under a denied name exists, because such requests are refused before any connection. With the server unreachable, an unknown site still gets `E_NOT_AVAILABLE` and a known site `E_REMOTE`.
- Redaction is heuristic: a secret in a format the rules do not recognise is returned.
- There is no audit log yet; `redactedLines` is returned so it can record redaction counts. Tracked privately; until it lands, keep to the status note at the top of this file.

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
| `tests/config.test.js` | Registry loading and Zod validation, including `hostKeys`, site names, roots and `allow` |
| `tests/client.test.js` | Registry guard for SFTP channels, `hostVerifierFor` always returns a verifier |
| `tests/host-key.test.js` | Fingerprint form and normalisation, constant-time comparison of every pin, verifier against fixed OpenSSH vectors |
| `tests/host-key-pinning.test.js` | Pinning against the fake: matching pins, rotation, mismatch refused before authentication with no SFTP channel, unpinned registry refused, reconnect re-verified |
| `tests/sftp.test.js` | Read-only session facade, per-call timeout, session close, read budget |
| `tests/confine.test.js` | Lexical confinement, input rules (encodings, look-alikes, control characters) and path-segment comparison |
| `tests/policy.test.js` | Denylist (case, Unicode and extension variants), allowlist matching, credential redaction |
| `tests/confinement-policy.test.js` | Fake server fixtures: symlink out of the root, loop, swapped links, files and directories, hard links, traversal encodings, sensitive names, allowlist misses, non-canonical replies, redaction, refusals byte-identical to not found (in the handler and over the MCP protocol) |
| `tests/site.test.js` | Site lookup refuses entries without roots or allowlist |
| `tests/redaction-cut.test.js` | For every `maxBytes` from 1 to the file length, no part of a credential is returned (several secret shapes, also through the fake server); `read_log` windows that start inside an assignment or a key block; site names in log file names |
| `tests/read-log.test.js` | Log selection, tail window, line and byte caps, literal filter, confinement, timeout |
| `tests/read-file.test.js` | Confinement (traversal, symlinks, sibling prefixes, non-canonical realpath replies, type change after open), byte cap and character boundaries, timeout |
| `tests/refusal-order.test.js` | Refusals that need no server open no connection or SFTP session and do not depend on the server being reachable |
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
  ssh/host-key.js       Host-key pins: fingerprint form, constant-time verifier
  ssh/sftp.js           Read-only SFTP session facade with a per-call deadline
  ssh/confine.js        Lexical and canonical (realpath) path confinement, open-time checks
  policy/paths.js       Sensitive-file policy: per-site allowlist, built-in denylist
  policy/redact.js      Credential-line redaction
  tools/site.js         Registry lookup for tool calls
  tools/read-log.js     read_log tool handler
  tools/read-file.js    read_file tool handler

tests/
  helpers/fake-sftp-server.js  In-process SSH/SFTP server fake (ssh2 server mode)
  helpers/host-key-vectors.js  Fixed public keys with their ssh-keygen fingerprints
  config.test.js        Unit: registry validation
  client.test.js        Unit: registry guard, host verifier
  host-key.test.js      Unit: pin form, constant-time comparison, verifier
  host-key-pinning.test.js  Unit: host-key pinning against the fake
  sftp.test.js          Unit: session facade, timeout, session close
  confine.test.js       Unit: path confinement
  policy.test.js        Unit: denylist, allowlist, redaction
  confinement-policy.test.js  Unit: confinement and policy fixtures against the fake
  site.test.js          Unit: site lookup shape check
  redaction-cut.test.js Unit: redaction independent of the cut and the window
  read-log.test.js      Unit: read_log against the fake
  read-file.test.js     Unit: read_file against the fake
  refusal-order.test.js Unit: refusals before any network activity
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
The site is not in `servers.json` (site keys are exact domain matches), or the path does not resolve to a regular file inside the root (`wordpressRoot` for `read_file` and the debug log, `logDir` for error and access logs), or the site's `allow` list does not cover its extension and directory, or the built-in denylist refuses it, or the account cannot read it. The tool does not say which, by design. Use relative paths only (e.g. `wp-content/plugins/example/readme.txt`). A log file that is a symlink is refused.

**`Registry is invalid: ... hostKeys: ...` at startup**  
A server has no host-key pins or a pin in the wrong form. Add or fix `hostKeys` as described in [Host-key pins](#host-key-pins). The message names the server id and never the value.

**`E_HOST_KEY`**  
The server's host key matches none of its pins. Either the key was rotated without a registry change, the address now reaches a different machine, or someone is intercepting the connection. Do not just copy the new fingerprint from `ssh-keyscan`. Check it against the provider console or another trusted channel first, then add it through a reviewed change.

**`E_TIMEOUT` or `E_REMOTE`**  
The connection, the SFTP subsystem or a read failed or took longer than 10 seconds. Verify the host, port, user, and private key path in `servers.json`, and that SFTP is enabled for the account. Test manually: `sftp -i /path/to/key -P 22 deploy@192.0.2.10`.

---

## Docs

- `docs/specs/` — implementation plan
- `docs/adrs/ADR-001-server-registry-design.md` — why `servers.json` is structured the way it is
- `docs/adrs/ADR-002-command-security-model.md` — the original command-based security model; superseded in part by the SFTP model above (see the note in the ADR)
