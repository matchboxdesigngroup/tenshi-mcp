# Code Review Standards

## Purpose

Reviews catch bugs and keep the security model intact. They are not style debates. Focus on correctness, architectural fit, and the checklist below.

## Who Reviews

- Reviewers are always fresh agents or people; authors never review their own work.
- Anything that decides who can read or do what (MCP tools and transport, the SFTP access layer, path confinement, auth, secrets, concurrency) gets an Opus high reviewer. See the risk rule in [CONTRIBUTING.md](../../CONTRIBUTING.md).

## Reviewer Responsibilities

- Approve only when you would be comfortable shipping the change yourself.
- Block on correctness bugs, security issues, or clear architectural violations. Offer suggestions for nits.
- Review at the exact head you approve; re-check after any new push.

## Author Responsibilities

- Run `npm test` locally and paste the result in the PR. CI (install, test, audit; see [CONTRIBUTING.md](../../CONTRIBUTING.md#ci-checks)) must also be green.
- Keep PRs focused; unrelated cleanup is a separate PR.
- Respond to every comment: apply the change or explain why not.
- Do not force-push, rebase, or amend after review has started; add commits instead.

## Review Checklist

Use [CLAUDE.md](../../CLAUDE.md) and the ADRs in [docs/adrs/](../adrs/) as the references.

### Security model
- [ ] Host access still limited to servers in the registry (`src/config/servers.js`, `src/ssh/client.js`).
- [ ] Remote access goes through the read-only SFTP facade (`src/ssh/sftp.js`) only: no exec, shell or write request, no command string, and no tool imports `src/ssh/client.js`, `node-ssh` or `ssh2`.
- [ ] Paths read by any tool (including log paths) still confined: lexical check, SFTP realpath, path-segment comparison with the canonical root, regular file only; traversal and symlink cases tested against the fake server.
- [ ] Output caps (line and byte limits) and the per-call timeout still enforced in this server, with the SFTP channel closed on timeout.
- [ ] Caller input never forms a command string, a regular expression or a server path; tool errors use the fixed codes in `src/errors.js` and do not echo input.

### Architecture fit
- [ ] New tools live in `src/tools/` and are registered in `src/index.js`.
- [ ] Config changes are validated by the zod schema in `src/config/servers.js`.
- [ ] No new dependencies without discussion.

### Tests
- [ ] New or changed behavior has a vitest test under `tests/`, including at least one failure or abuse case for security-relevant code.
- [ ] No existing tests removed, skipped, or weakened.
- [ ] Tests use mocked SSH; none require a real server.

### Hygiene
- [ ] No secrets, `.env` values, real hostnames, IPs, usernames, personal paths, or client domains (public repo).
- [ ] No exploit details in code comments, docs, or PR text.
- [ ] [CHANGELOG.md](../../CHANGELOG.md) updated.
- [ ] Commit subjects follow [git.md](git.md).

## Merge Criteria

All relevant checklist items pass, the approving review is on the current head, and CI is green on that head. Merge with a merge commit.
