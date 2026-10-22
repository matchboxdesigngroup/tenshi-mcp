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

```bash
npm ci
npm test
```

Unit tests use vitest with mocked SSH; no real server is needed. CI is being added in milestone M1; until then run the tests locally before opening a PR.

## Definition of done

The PR is merged at the exact approved head with CI green, acceptance criteria verified, tests and sabotage table in place, and docs and changelog updated. (CI does not exist yet in this repo; this applies once it lands in M1.)

## Code review and shell scripts

- [docs/standards/code-review.md](docs/standards/code-review.md)
- [docs/standards/shell.md](docs/standards/shell.md)
