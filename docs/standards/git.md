# Git Standards

Summary lives in [CONTRIBUTING.md](../../CONTRIBUTING.md); this file has the detail.

## Branch Naming

Format: `<type>/<issue#>-<slug>`, kebab-case, short.

| Prefix | Use |
|---|---|
| `feat/` | New tool or user-facing capability |
| `fix/` | Bug fix |
| `chore/` | Build, config, dependency, or tooling change |
| `docs/` | Documentation only |
| `refactor/` | Internal restructure with no behavior change |

Example: `fix/12-path-confinement`.

## Commit Messages

Imperative, sentence-case, capital verb, no prefix, no trailing period, 72 characters maximum.

```
Add read_file size cap test
Fix log path resolution for custom layouts
Extract path confinement helper
```

- Body (optional): blank line after the subject, then explain why, not what.
- Avoid vague subjects such as `updates` or `misc fixes`. Each commit is a complete thought.
- Do not append `Co-Authored-By` lines.

History note: Tenshi-MCP commits before the docs bootstrap PR used lowercase conventional-commit prefixes (`feat:`, `docs:`, `chore:`). That history is left as is. New commits follow the style above.

## Branch Workflow

1. Branch from `main`.
2. Keep each branch to one logical concern.
3. To bring `main` into your branch, merge it (merge commit). Do not rebase pushed work, amend pushed commits, or force-push.
4. Delete the branch after merge.

## Pull Requests

- Title matches the intended merge commit subject (imperative, 72 characters maximum).
- Body follows [.github/pull_request_template.md](../../.github/pull_request_template.md): Why, What Changed, How to Test, Decisions to revisit, Follow-ups.
- Target `main`. One PR per branch.
- CI is being added in milestone M1; there are no automated checks yet. Run `npm test` locally and report the output.
- Merge strategy: merge commits, so reviewed commits are preserved. No squash or rebase merges.
- The author does not review their own PR.

## What Not to Commit

- `node_modules/` and `.env` (both in `.gitignore`).
- `servers.json` (in `.gitignore`); commit only `servers.json.example` with placeholder values.
- Real hostnames, IP addresses, usernames, personal paths, client domains, keys, or tokens. This repository is public.

## Tagging and Releases

Not yet defined for this repository. Releases will be documented in [CHANGELOG.md](../../CHANGELOG.md) once a release process exists.
