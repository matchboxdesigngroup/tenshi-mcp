# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- CI workflow (`.github/workflows/ci.yml`) on pull requests and pushes to `main`: `npm ci`, `npm test`, and an audit check, with actions pinned by commit SHA (#3).
- `.nvmrc` pinning Node 23 for local development and CI, matching the platform local development guide (#3).
- `npm run audit:check` (`scripts/audit-check.mjs`, Node built-ins only): fails on high or critical `npm audit` advisories not listed in `.audit-allowlist.json` and on expired allowlist entries; reports stale entries. Unit tests in `tests/audit-check.test.js` (#3).
- `.audit-allowlist.json` with the high and critical advisories present on `main` when CI was added, expiring 2026-11-30; dependency updates tracked in #5.
- `CONTRIBUTING.md` with branching, commit, merge, PR, roles/models, and definition-of-done conventions.
- Issue templates (feature, bug, spike, manual test) and a pull request template.
- `servers.json.example` with placeholder values, referenced by the README and `CLAUDE.md`.
- Status note in `README.md` and `CLAUDE.md`: the tool layer is under security review.

### Changed
- `CONTRIBUTING.md`, `CLAUDE.md`, and `docs/standards/` describe the CI checks and the audit allowlist; the "CI is being added" notes are removed (#3).
- `docs/standards/git.md`, `code-review.md`, and `shell.md` now describe this Node MCP server and the shared conventions (they were copied from an unrelated project).
