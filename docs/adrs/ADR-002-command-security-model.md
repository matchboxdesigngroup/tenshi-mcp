# ADR-002: Three-Layer Security Model for Production SSH Access

**Date:** 2026-06-04  
**Status:** Accepted; superseded in part (command construction)

> **Superseded in part.** The command allowlist (Layer 2) and the `execCommand` trade-off below no longer describe the code. The tools now read over SFTP only: `src/ssh/executor.js` and `runCommand` were removed, no tool opens an exec or shell channel or builds a command string, and remote access goes through the read-only facade in `src/ssh/sftp.js`. The replacement model is decided in the platform ADR on tool-layer remote access, kept in the private platform repository; the README security model describes what the code does now. Layer 1 (registry allowlist) still applies, and is now backed by host-key pinning: every connection verifies the server's host key against the `hostKeys` pins in the registry before authentication, and an unpinned server cannot be loaded. "Only hosts defined in `servers.json`" previously meant only that their address was listed. A machine answering at that address with another key is now refused. Layer 3 (path confinement) still applies and is stronger: paths are also resolved on the server with SFTP `realpath` and compared to the canonical root by path segment, and log files get the same checks. Since #20, every path is also checked against a mandatory per-site allowlist and a built-in denylist of sensitive files, before any connection and again on the resolved path, and credential lines are redacted from all returned content (README, "Sensitive-file policy"). The "write commands are impossible by design" consequence below described the command allowlist; the tools issue no write requests, but the SSH account's own rights are set on the server, not by this code. The text below is kept as the original record.

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
