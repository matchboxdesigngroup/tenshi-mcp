# Shell scripting conventions

This document covers the conventions for every shell script in this repository —
primarily Claude Code hooks in `.claude/hooks/` but also any standalone utility
scripts. The goal is a consistent, auditable style: every script should be
readable without context, behave predictably under partial input, and degrade
safely when something unexpected happens.

## Shebang and shell options

**Shebang.** Always use the env-searched form:

```bash
#!/usr/bin/env bash
```

Never `#!/bin/bash`. The env form is portable across Homebrew, nix, and Linux
environments where bash may not live at `/bin/bash`.

**Shell options.** Two patterns are in use — choose based on the hook's fail
mode (see [Fail modes](#fail-modes) below).

_Standard (fail-open or advisory scripts):_ `set -euo pipefail`

`-e` exits on any non-zero command; `-u` treats unset variables as an error;
`-o pipefail` fails the pipeline if any stage fails.

_Safety-critical (fail-closed scripts):_

```bash
set -uo pipefail

fail_closed() {
  echo "script-name.sh: $1 — defaulting to BLOCK." >&2
  exit 2
}
trap 'fail_closed "unexpected error at line $LINENO"' ERR
```

Omit `-e` and install an `ERR` trap instead. Any shell error — a failed `jq`
call, unreadable stdin, missing command — produces a named diagnostic and blocks
the operation rather than failing silently.

## Doc-block format

Every script opens with a comment block immediately after the shebang —
the primary documentation; no separate README entry needed.

Required sections, in order:

```sh
# script-name.sh
#
# Purpose
#   1–3 sentences: what the script does and why it exists.
#
# When it runs
#   The hook event (PreToolUse / PostToolUse) and the tool it matches,
#   or the invocation context for non-hook scripts.
#
# What it [blocks|warns|acts on]
#   Specific patterns, commands, or file paths the script acts on.
#   List edge cases and explicit allow-list entries here.
#
# Behavior
#   exit 0  → <what happens>
#   exit 2  → <what happens>   (or: "exit 0 always — advisory only")
#
# Failure mode
#   One sentence: fail-open or fail-closed, and the one-line reason why.
#
# Testing
#   A single curl-able (pipe-able) example with the expected outcome:
#     echo '<json>' | ./script-name.sh
#   Expected: <exit code and/or stderr content>.
```

All six sections are required. Adding sections beyond these six requires
updating this document.

## JSON handling — use jq

Claude Code passes hook payloads as JSON on stdin. Parse them with `jq` —
never spawn Python or Node.js from a hook. Hooks fire on every tool call;
spawning a runtime adds latency and a toolchain dependency. `bash + jq` is
always present and fast.

```bash
input="$(cat)"
value="$(printf '%s' "$input" | jq -r '.tool_input.some_field // ""')"
```

Rules:

- Read stdin once into `input`; reuse `$input` for all subsequent `jq` calls.
- Use `printf '%s'` not `echo` — `echo` appends a newline that can corrupt
  multi-line or binary values.
- Default to an empty string with `// ""` so `[[ -z ... ]]` tests work without
  tripping `-u` on unset variables.
- Fail-closed scripts: append `|| fail_closed "jq failed to parse hook input"`
  after the `jq` call.

## Fail modes

Every hook must choose a fail mode and document it in the doc-block.

### Fail-closed

Use when a silent pass-through is worse than a false positive. Examples:
`block-main-commits.sh`, `protect-env.sh`.

- `set -uo pipefail` + `ERR` trap (see [Shebang and shell options](#shebang-and-shell-options)).
- Exit 2 on every unexpected error path with a diagnostic on stderr.
- Over-blocking is acceptable; silent allow is not.

### Fail-open (advisory)

Use when false-positive rate is too high to block, or the hard gate lives
elsewhere. Examples: `typecheck-ts.sh` (CI enforces), `scan-injection.sh`.

- `set -euo pipefail`.
- `exit 0` unconditionally at the end.
- Warnings go to stderr; nothing to stdout.
- Guard tool-not-found paths with `|| exit 0` so the hook degrades silently.

### Exit code semantics

For Claude Code hooks specifically: `0` — allow. `2` — block (Claude Code
surfaces stderr to the agent). Do not use exit code `1`.

For standalone utility scripts, use conventional shell exit codes (`0` for
success, non-zero for failure).

## Quoting

Follow the standard Bash quoting rules:

- **Double-quote variable expansions**: `"$var"`, `"${array[@]}"` — prevents
  word-splitting and glob expansion.
- **Single-quote literal strings**: `'pattern'`, `'--flag'` — no interpolation.
- Never leave a variable unquoted unless you explicitly need word-splitting
  (rare; comment why).

```bash
# Good
base="$(basename "$file_path")"

# Bad — $file_path may contain spaces
base=$(basename $file_path)
```

## Style references

These conventions are Google Shell Style Guide-flavored. For anything not
covered here — function naming, line length, `local` variables, error messages —
defer to: [https://google.github.io/styleguide/shellguide.html](https://google.github.io/styleguide/shellguide.html)

## Complete example

Adapted from `protect-env.sh`. Shows doc-block format, `set -euo pipefail`,
`jq` parsing, quoting, and fail-open behaviour.

```bash
#!/usr/bin/env bash
#
# protect-env.sh
#
# Purpose
#   Refuse Edit / Write operations against environment / secrets files
#   so the agent cannot clobber local credentials.
#
# When it runs
#   PreToolUse, on Edit and Write tools.
#
# What it blocks
#   .env, .env.*, .dev.vars — any environment file.
#   Allowed: .env.example, .env.template, .env.sample, .dev.vars.example
#
# Behavior
#   exit 0  → allow the operation
#   exit 2  → block
#
# Failure mode
#   Fails open — unrecognised paths fall through to exit 0.
#
# Testing
#   echo '{"tool_input":{"file_path":".env"}}' | ./protect-env.sh
#   Expected: exit 2.

set -euo pipefail

input="$(cat)"
file_path="$(printf '%s' "$input" | jq -r '.tool_input.file_path // ""')"
base="$(basename "$file_path")"

case "$base" in
  .env.example|.env.template|.env.sample|.dev.vars.example) exit 0 ;;
esac

if [[ "$base" == ".env" || "$base" =~ ^\.env\..+ || "$base" == ".dev.vars" ]]; then
  echo "Refusing to modify environment file: $file_path" >&2
  exit 2
fi

exit 0
```
