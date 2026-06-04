# ADR-002: Three-Layer Security Model for Production SSH Access

**Date:** 2026-06-04  
**Status:** Accepted

## Context

This MCP server SSHs into production WordPress servers on behalf of Claude. Any command execution vulnerability could allow arbitrary remote code execution. The server runs locally with no authentication layer between it and Claude.

## Decision

Security is enforced in three independent layers, each failing closed:

**Layer 1 — Host allowlist** (`src/ssh/client.js`): Only hosts defined in `servers.json` are connectable. `getConnection` calls `getServerConfig` before opening any SSH connection — if the server ID isn't in the registry, the connection is rejected before any network activity.

**Layer 2 — Command allowlist** (`src/ssh/executor.js`): Only `tail`, `head`, `grep`, `cat`, `ls` may be executed. The check happens before `getConnection` is called — a disallowed command never reaches the SSH layer. Binary is parsed as `argv[0]` (whitespace split), not by shell parsing, to avoid metacharacter bypass.

**Layer 3 — Path confinement** (`src/tools/read-file.js`): File paths are resolved with `path.resolve(wordpressRoot, userPath)` and the result must start with `wordpressRoot + '/'`. This blocks `../` traversal before the command is built.

## Hard caps

- `read_log`: max 500 lines
- `read_file`: max 50 KB (51200 bytes)

These are enforced server-side regardless of what Claude requests.

## Consequences

- **Good:** Each layer is independent — a bypass in one doesn't automatically bypass the others
- **Good:** Command allowlist is enforced before SSH connection (cheaper failure)
- **Trade-off:** `execCommand` runs the command string through the remote shell — pipe characters in `tail ... | grep ...` are intentional and safe since we control the full string. No user-controlled shell metacharacters enter the command.
- **Trade-off:** Write commands are impossible by design — no tool exposes write paths, and the allowlist blocks them even if a tool were added
- **Note:** `grep`, `cat`, `ls` are in the allowlist to support future tool additions; only `tail` and `head` are used by current tools
