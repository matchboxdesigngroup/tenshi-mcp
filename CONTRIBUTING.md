# Contributing

This repository is public. Do not put hostnames, IP addresses, usernames, personal paths, real client domains, credentials, or exploit details in code, docs, issues, or PRs. Use placeholders such as `example.com`, `192.0.2.x`, and `/path/to/key`.

Security-relevant work and its details are discussed in the private platform repo, not in public issues.

## Branching

- Branch from `main`. Never commit directly to `main`.
- Branch names: `feat|fix|chore|docs|refactor/<issue#>-<slug>` in kebab-case, for example `fix/12-path-confinement`.
- Keep a branch to one logical concern.

## Commits

Use the shared style: imperative, sentence-case, capital verb, no prefix, no trailing period, 72 characters maximum.

```
Add read_file size cap test
Fix log path resolution for custom layouts
```

Tenshi-MCP history before this PR used lowercase conventional-commit prefixes (`feat:`, `docs:`, `chore:`). That history stays as it is; new commits follow the shared style above. Do not append `Co-Authored-By` lines.

See [docs/standards/git.md](docs/standards/git.md) for details.

## Merge strategy

- Merge commits, so reviewed commits are preserved.
- To bring `main` into a feature branch, merge it with a merge commit. Never rebase or amend pushed work, and never force-push.

## Pull requests

- One PR per branch, base `main`. Use the [PR template](.github/pull_request_template.md).
- Sections: Why, What Changed, How to Test (exactly what you ran and the results), Decisions to revisit, Follow-ups.
- Include a sabotage table (what breaks when the change is reverted or the guard removed). Docs-only PRs write "n/a, docs only" and state the link and path check they ran.
- Update [CHANGELOG.md](CHANGELOG.md) in the same PR.
- The author does not review their own PR, and reviewers are always fresh agents or people.

## Roles and models

| Role | Model | Effort |
|---|---|---|
| PM | Claude Sonnet 5.5 (`claude-sonnet-5-5`) | medium |
| Builder | Claude Opus 5.5 (`claude-opus-5-5`) | medium |
| Reviewer | Claude Opus 5.5 | high |
| Researcher | Claude Sonnet 5.5 | medium |
| Advisor | Claude Opus 5.5 (fresh agent, advises only) | high |

Risk rule: builders and reviewers of anything that decides who can read or do what must be Opus at high effort. That covers webhook verification, agent tool selection and prompts, MCP tools and transport, auth, secrets, data retention, concurrency, and idempotency. Sonnet is fine for docs PRs, small delta checks, UI-only reviews, bookkeeping, and narrow test additions.

## Testing

Use the Node major in [`.nvmrc`](.nvmrc) (Node 23, matching the platform's local development guide), for example `nvm use`.

```bash
npm ci
npm test
npm run audit:check
```

Unit tests use vitest with mocked SSH; no real server is needed. `tests/integration.js` is a manual script against a real server and is not run by `npm test` or CI.

### CI checks

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs on every pull request and on pushes to `main`, on the Node version in `.nvmrc`:

1. `npm ci` (install from the lockfile)
2. `npm test` (Vitest unit tests)
3. `npm run audit:check` (`npm audit`; fails on any high or critical advisory that is not in [`.audit-allowlist.json`](.audit-allowlist.json), and on any expired allowlist entry)

All three must pass before merge. Only the official `actions/checkout` and `actions/setup-node` actions are used, pinned by full commit SHA with the version tag in a comment; the workflow uses no secrets and only reads the repository. Secret scanning is not part of CI yet; it waits for the scanning-approach ADR in the platform repo.

### Audit allowlist

Fix advisories rather than allowlisting them where possible (`npm audit fix`, or an upgrade). When an advisory cannot be fixed in the current PR, add an entry to `.audit-allowlist.json` with the advisory `id` (GHSA), `package`, `severity` (`high` or `critical`, as reported), a `reason`, the tracking `issue`, and an `expires` date (`YYYY-MM-DD`, at most 60 days ahead). Never allowlist an advisory without a tracking issue; extend an expiry only with a reason in the PR.

How the check behaves:

- It runs `npm audit` with `--offline=false --registry=https://registry.npmjs.org/ --include=dev --include=optional --include=peer`, so offline mode, another registry, or `omit=dev` / `production` in `.npmrc` or the environment cannot hide advisories. It fails closed when npm returns an error or an incomplete report.
- An entry matches on advisory id and package together. If the advisory is re-rated above the entry's `severity` (for example high to critical), the check fails until the entry is reviewed.
- It fails on any malformed, duplicated, expired, or over-long entry, and lists all of them at once. Entries whose advisory no longer appears are printed as stale so they can be removed.
- Known limit: because entries match on advisory id and package, a new install path to an already-allowlisted package and advisory is not reported separately.

## Definition of done

The PR is merged at the exact approved head with CI green, acceptance criteria verified, tests and sabotage table in place, and docs and changelog updated.

## Code review and shell scripts

- [docs/standards/code-review.md](docs/standards/code-review.md)
- [docs/standards/shell.md](docs/standards/shell.md)
