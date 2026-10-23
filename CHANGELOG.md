# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- `tests/server.test.js`: starts the server over stdio with the SDK client and checks the reported server name, the tool names and the deprecated-variable warning (#11).
- CI workflow (`.github/workflows/ci.yml`) on pull requests and pushes to `main`: `npm ci`, `npm test`, and an audit check, with actions pinned by commit SHA (#3).
- `.nvmrc` pinning Node 23 for local development and CI, matching the platform local development guide (#3).
- `npm run audit:check` (`scripts/audit-check.mjs`, Node built-ins only): runs `npm audit` online against the public registry with dev, optional and peer dependencies included regardless of `.npmrc`; fails on high or critical advisories not listed in `.audit-allowlist.json`, on advisories re-rated above their entry, on malformed, duplicate, expired or over-60-day entries, and on incomplete npm output. Unit tests in `tests/audit-check.test.js` (#3).
- `.audit-allowlist.json` with the high and critical advisories present on `main` when CI was added, expiring 2026-11-30; dependency updates tracked in #5.
- `CONTRIBUTING.md` with branching, commit, merge, PR, roles/models, and definition-of-done conventions.
- Issue templates (feature, bug, spike, manual test) and a pull request template.
- `servers.json.example` with placeholder values, referenced by the README and `CLAUDE.md`.
- Status note in `README.md` and `CLAUDE.md`: the tool layer is under security review.

### Changed
- Audit gate hardening (#10, CI follow-ups from #4): `scripts/audit-check.mjs` now passes `--package-lock=true` and `--include=prod` to `npm audit`, so `package-lock=false` in an `.npmrc` or the environment can no longer make it audit a freshly resolved tree instead of the lockfile. Stale allowlist entries (advisory no longer reported at high or critical) now fail the job instead of only being printed. An entry's `severity` must now match the reported severity exactly: an advisory re-rated in either direction fails until the entry is updated (it previously failed only when re-rated upwards, so an entry recorded as `critical` covered a `high` advisory). An advisory with an unknown or missing severity always fails, even when its id and package are allowlisted as critical. A `null` or otherwise unexpected `via` item, or a vulnerability entry without a `via` list, fails closed with a message instead of being skipped. npm's top-level `message` (how npm 10 reports an unreachable registry) is printed first. The script also runs when invoked through a symlink (it compared the typed path with the module path and exited 0 without running). CI runs `node scripts/audit-check.mjs` directly instead of `npm run audit:check`, so `node_modules/.bin` cannot shadow `npm`, and runs it before `npm ci` and `npm test`, so no dependency code (install scripts or tests) runs before the audit; the job name `Install, test, audit` is unchanged. CONTRIBUTING.md lists proxy and TLS settings from npm config as a known limit. The allowlist entries are unchanged; only its `$comment` describes the stale rule.
- Renamed the project to Tenshi-MCP (tenshi#3, #11): package name `tenshi-mcp` (package.json and lockfile root), MCP server name reported over the protocol `tenshi-mcp` (was `ssh-wp-tools`), registration key `tenshi-mcp` in `.mcp.json.example` and the README and `CLAUDE.md` examples, README and `CLAUDE.md` titles, and the implementation plan renamed to `docs/specs/2026-06-04-tenshi-mcp-server.md`. Tool names `read_log` and `read_file` are unchanged. The registration key is client-side configuration that the server never reads, so an existing registration under the old key keeps starting the server; rename it to match the docs.
- **Local configuration change (breaking in M5):** the registry path variable is now `TENSHI_MCP_SERVERS_PATH` (was `SSH_MCP_SERVERS_PATH`). The old name is still read as a deprecated fallback, see Deprecated. `.env.example` lists the new name and the old one only as a commented line.
- **`.mcp.json` is no longer tracked** (#11): it is now `.mcp.json.example` with placeholder paths, and `.mcp.json` is git-ignored. Pulling this change deletes the tracked `.mcp.json` from existing checkouts (if you changed it locally, copy it aside before pulling); recreate it with `cp .mcp.json.example .mcp.json` and set your absolute paths. README and `CLAUDE.md` describe registering the server in your MCP client configuration (for Claude Code, a project `.mcp.json`) instead of `.claude/settings.json`; the spec has a correction note.
- README, `CLAUDE.md` and `.env.example` now say that the server does not load `.env` files: `TENSHI_MCP_SERVERS_PATH` must be set in the environment of the process that starts the server (MCP client `env` block, shell `export` or inline). `.env.example` is a template only (#11).
- Example site domains, server ids and absolute paths in docs, tool descriptions and `tests/integration.js` are neutral placeholders (`example.com`, `example-server`, `/path/to/tenshi-mcp`).
- `CONTRIBUTING.md`, `CLAUDE.md`, and `docs/standards/` describe the CI checks and the audit allowlist; the "CI is being added" notes are removed (#3).
- `docs/standards/git.md`, `code-review.md`, and `shell.md` now describe this Node MCP server and the shared conventions (they were copied from an unrelated project).

### Deprecated
- `SSH_MCP_SERVERS_PATH`: read only when `TENSHI_MCP_SERVERS_PATH` is unset or empty (an empty or whitespace-only value counts as unset; other values are used verbatim, not trimmed), with a one-line startup warning on stderr that names the variables and never their values; when both are set the new name wins and the warning says the old one is ignored. Removed in M5 (#11).
