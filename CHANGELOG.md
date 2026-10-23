# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Read-only SFTP layer (#1): `src/ssh/sftp.js` gives tools a session facade with only `realpath`, `lstat`, open for reading, `fstat`, bounded `read` and `close`, under one 10-second deadline per call that closes the SFTP channel on expiry; `src/ssh/confine.js` confines paths lexically and then by SFTP `realpath` with path-segment comparison and a regular-file check; `src/errors.js` defines the fixed error codes.
- In-process SSH/SFTP server fake for unit tests (`tests/helpers/fake-sftp-server.js`, built on `ssh2`'s server mode, no new dependency) and tests against it: `tests/sftp.test.js`, `tests/confine.test.js`, `tests/errors.test.js`, `tests/boundaries.test.js`. Tool tests fail if the fake receives any exec, shell or other non-SFTP request (#1).
- Host-key verification seam `hostVerifierFor` in `src/ssh/client.js`. It returns no verifier yet, so host keys are accepted exactly as before; pinning is a tracked follow-up (#1).
- `tests/server.test.js`: starts the server over stdio with the SDK client and checks the reported server name, the tool names and the deprecated-variable warning (#11).
- CI workflow (`.github/workflows/ci.yml`) on pull requests and pushes to `main`: `npm ci`, `npm test`, and an audit check, with actions pinned by commit SHA (#3).
- `.nvmrc` pinning Node 23 for local development and CI, matching the platform local development guide (#3).
- `npm run audit:check` (`scripts/audit-check.mjs`, Node built-ins only): runs `npm audit` online against the public registry with dev, optional and peer dependencies included regardless of `.npmrc`; fails on high or critical advisories not listed in `.audit-allowlist.json`, on advisories re-rated above their entry, on malformed, duplicate, expired or over-60-day entries, and on incomplete npm output; reports stale entries. Unit tests in `tests/audit-check.test.js` (#3).
- `.audit-allowlist.json` with the high and critical advisories present on `main` when CI was added, expiring 2026-11-30; dependency updates tracked in #5.
- `CONTRIBUTING.md` with branching, commit, merge, PR, roles/models, and definition-of-done conventions.
- Issue templates (feature, bug, spike, manual test) and a pull request template.
- `servers.json.example` with placeholder values, referenced by the README and `CLAUDE.md`.
- Status note in `README.md` and `CLAUDE.md`: the tool layer is under security review.

### Changed
- **`read_log` reads over SFTP (#1).** It reads at most the last 256 KB of the configured log with one bounded read, applies the optional filter in this process as a case-insensitive literal substring (at most 200 characters; never a regular expression, never sent to the server), returns the last `lines` matches (cap 500), cuts lines longer than 2000 characters and caps the content at 51200 bytes. Log paths come from the registry only and get the same confinement as `read_file` (inside `wordpressRoot` for the debug log, inside `logDir` for error and access logs). Output: `resolvedPath` and `lineCount` are removed; `requestedLines`, `returnedLines` and `truncated` (`window`, `longLines`, `bytes`) are added.
- **`read_file` reads over SFTP (#1).** The relative path is checked lexically, then resolved with SFTP `realpath` and must lie strictly inside the canonical WordPress root by path segment; symlinks that leave the root, directories and other non-regular files are refused. At most `maxBytes` (cap 51200) are read. Output: `requestedPath` and `resolvedPath` are removed; `path` (canonical, relative to the root) and `bytes` are added; `truncated` is now exact (a file of exactly `maxBytes` is not flagged). `path` is limited to 1024 characters.
- Tool errors are fixed codes (`E_NOT_AVAILABLE`, `E_INVALID_INPUT`, `E_TIMEOUT`, `E_REMOTE`, `E_INTERNAL`) and never contain the arguments, server paths or remote error text; unknown site, outside-root, missing and forbidden paths share `E_NOT_AVAILABLE` (#1).
- Connection pool: concurrent first calls to a server share one connection attempt, a connection that completes after the pool was closed is disposed, and a socket error after connect drops the pooled connection instead of reaching an emitter with no listener. The 5-minute idle timeout is unchanged (#1).
- README, `CLAUDE.md`, `docs/standards/code-review.md` and `tests/integration.js` describe the SFTP model; ADR-002 and the implementation plan carry a superseded-in-part note (#1).
- Renamed the project to Tenshi-MCP (tenshi#3, #11): package name `tenshi-mcp` (package.json and lockfile root), MCP server name reported over the protocol `tenshi-mcp` (was `ssh-wp-tools`), registration key `tenshi-mcp` in `.mcp.json.example` and the README and `CLAUDE.md` examples, README and `CLAUDE.md` titles, and the implementation plan renamed to `docs/specs/2026-06-04-tenshi-mcp-server.md`. Tool names `read_log` and `read_file` are unchanged. The registration key is client-side configuration that the server never reads, so an existing registration under the old key keeps starting the server; rename it to match the docs.
- **Local configuration change (breaking in M5):** the registry path variable is now `TENSHI_MCP_SERVERS_PATH` (was `SSH_MCP_SERVERS_PATH`). The old name is still read as a deprecated fallback, see Deprecated. `.env.example` lists the new name and the old one only as a commented line.
- **`.mcp.json` is no longer tracked** (#11): it is now `.mcp.json.example` with placeholder paths, and `.mcp.json` is git-ignored. Pulling this change deletes the tracked `.mcp.json` from existing checkouts (if you changed it locally, copy it aside before pulling); recreate it with `cp .mcp.json.example .mcp.json` and set your absolute paths. README and `CLAUDE.md` describe registering the server in your MCP client configuration (for Claude Code, a project `.mcp.json`) instead of `.claude/settings.json`; the spec has a correction note.
- README, `CLAUDE.md` and `.env.example` now say that the server does not load `.env` files: `TENSHI_MCP_SERVERS_PATH` must be set in the environment of the process that starts the server (MCP client `env` block, shell `export` or inline). `.env.example` is a template only (#11).
- Example site domains, server ids and absolute paths in docs, tool descriptions and `tests/integration.js` are neutral placeholders (`example.com`, `example-server`, `/path/to/tenshi-mcp`).
- `CONTRIBUTING.md`, `CLAUDE.md`, and `docs/standards/` describe the CI checks and the audit allowlist; the "CI is being added" notes are removed (#3).
- `docs/standards/git.md`, `code-review.md`, and `shell.md` now describe this Node MCP server and the shared conventions (they were copied from an unrelated project).

### Deprecated
- `SSH_MCP_SERVERS_PATH`: read only when `TENSHI_MCP_SERVERS_PATH` is unset or empty (an empty or whitespace-only value counts as unset; other values are used verbatim, not trimmed), with a one-line startup warning on stderr that names the variables and never their values; when both are set the new name wins and the warning says the old one is ignored. Removed in M5 (#11).

### Removed
- `src/ssh/executor.js` (`runCommand`) and `tests/executor.test.js`: no tool runs a remote command or builds a command string (#1).
