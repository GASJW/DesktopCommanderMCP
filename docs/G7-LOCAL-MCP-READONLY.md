# G7.2f — Actual local Desktop Commander read-only tool adapter (inert)

## Purpose

Prove that our own signed `deviceId` router + outbound-polling prototype can call an **actual** Desktop Commander MCP child under a standard (non-root) OS account, rather than returning a synthetic answer. This PR does not establish a remote Windows/Linux transport and is not deployed.

## Delivered

- `packages/vpsc-agent/src/local-mcp-readonly.mjs`: starts a **locally configured** Desktop Commander process through `node <absolute-entrypoint> --no-onboarding`, shell disabled, child standard input/output MCP JSON-RPC 2.0, explicit initialize and tools/call; no inherited authentication secrets or unrestricted environment.
- Restricts remote frames to `tools/call` with **exact tool name `read_file`**. `write_file`, `start_process`, `get_config`, `list_directory`, administrative actions and every other tool are rejected **locally before reaching MCP**.
- Local configuration supplies a single real, absolute `allowedRoot`. Request parameters must contain an absolute path and optionally bounded `offset`/`length`; rejects URLs, injected options, relative/traversal paths, symlink escapes, nonregular files and files over 64 KiB. This permission boundary is **in addition** to Desktop Commander's own allowedDirectories, which can be empty in the current project.
- Denies invocation by root on POSIX. Runs with a bounded sanitized environment, process I/O size/timeout guards, one concurrent MCP call, and no automatic replay following an ambiguous timeout. Child stderr is discarded (never sent to clients).
- A local test MCP fixture permits deterministic CI without publishing npm or requiring a preinstalled Desktop Commander.
- **Actual host integration (VPS gui):** using `VPSC_TEST_REAL_MCP_ENTRY=/opt/vps-commander/code/dist/index.js` under `vpscommander`, the same test suite connects to the real installed MCP, reads a temporary fixture file in a bounded directory, and returns a real read_file result. A second test sends an Ed25519-signed agent request via HTTP **localhost only**, routes by a trusted `deviceId`, polls it, invokes the real MCP read_file and returns the result through the G7 router. The independent RDC tool only launched the test on VPS; it was not the test's request transport.
- Fully temporary test directories. No user workspace content or secrets read, no Windows enrollment and no external connection.

## Scope limits and security gates

This module is **not imported into gateway/server.mjs or the published agent CLI**. The working end-to-end is within **one VPS** on 127.0.0.1; it does **not** establish internet HTTPS or an actual second device. The current CLI `@gasjw/vpsc-agent@0.0.0-dev` remains private, unpublishable, and rejects `connect`, `pair`, `root`, etc.

**Important limitations before live use:**

1. The local path guard uses `realpath` and `stat` before passing the same path to the MCP child; a malicious concurrent filesystem actor can replace it between those steps (TOCTOU). A production security boundary needs OS-level confinement/sandboxing and/or descriptor-based reads. Do not enable this adapter on sensitive writable user roots until certified.
2. An authenticated remote frame is not equivalent to **owner authorization**. The future Gateway must apply owner/device/tool permissions, rate limits, logs and server-side grant checks before queueing each operation. The adapter alone does not verify Cloudflare owner JWT.
3. No external hostname is connected. Requires a **separate, authenticated machine-to-machine Cloudflare Access application/hostname**, TLS and agent key proofs; preserve the existing owner-only Commander Access app.
4. The agent's durable signing key and the separate VPS trust store are preparatory. PR #21 durable trust remains Draft pending one-writer, crash recovery, backup and audit gates; this PR is independent of it.
5. Add robust response scrubbing, result redaction policy, backpressure, HTTP long-poll isolation and replay fencing for retries before remote use. Never treat a timeout as evidence that a mutating call failed.
6. Root/Admin is a **separate helper design** (not present here); ordinary local MCP agent is not elevated. Indefinite Root/Admin duration exists only as an inactive policy contract.
7. The VPS gui root partition remains close to 90% used; no service/package installation is performed by this PR.

## Acceptance

- GitHub protected checks and regression suite PASS.
- Real non-root `read_file` integration on VPS with *actual* Desktop Commander binary PASS, including signed loopback routing.
- Windows Gui-PC local MCP child pilot + own Agent HTTPS + owner approval must be validated in separately governed steps.
- No merge or deployment should be construed as enabling remote execution: module and tests are inert unless a dedicated test harness invokes them.

## Cross-platform local test result

Gui-PC (Windows Node 24.16.0): base read-only, injection/traversal, size limits, signed mock loopback routing passed. Creating a symlink returned EPERM without developer/admin privilege, so symlink escape is now an explicitly skipped POSIX-only test on Windows; do not claim Windows symlink/junction safety is certified. No persistent service or npx package was installed.

## Windows installed MCP startup finding

The installed Desktop Commander on Gui-PC replied successfully to MCP initialize after approximately **7.2 seconds** (separately measured; stdout response present, no child stderr). The prior host test used a 7-second deadline for both startup and operations and timed out. The adapter now has a **distinct default startupTimeoutMs=30,000** while retaining the bounded per-operation timeoutMs=8,000 by default; this does not authorize any new tool. Retest with the exact updated GitHub candidate required.
