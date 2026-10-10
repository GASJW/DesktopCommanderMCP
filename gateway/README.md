# VPS Commander — gateway MCP HTTP (V0)

**Status:** prototype local; NOT deployed; NOT externally accessible; no Cloudflare route.

## Goal
Expose the existing Desktop Commander stdio MCP toolset via a minimal stateless HTTP bridge, eliminating the proprietary Desktop Commander remote relay and its quotas. The arbitrary shell/file tools remain available, subject to OS privileges. The upstream command blocklist is not a sandbox.

## Requirements
- Node.js 22+ installed outside /root, accessible to a non-root service account.
- Clone the existing fork, install with the repository lockfile and build: `npm ci && npm run build`.
- Do not expose TCP port 8787 to the public Internet.

## Local development setup
Generate a secret on the VPS (never put it in chat, Git or Notion):

```bash
umask 077
mkdir -p ~/.config/vps-commander
printf 'VPS_COMMANDER_TOKEN=%s\n' "$(openssl rand -hex 32)" > ~/.config/vps-commander/gateway.env
```

From the built repository root:

```bash
set -a
. "$HOME/.config/vps-commander/gateway.env"
set +a
node gateway/server.mjs
```

The gateway binds only to 127.0.0.1 or ::1, even when configured. POST /mcp and GET /healthz both require an Authorization: Bearer secret.

## Isolated test suite
```bash
node --check gateway/server.mjs
node --test gateway/test/gateway.test.mjs
```

The test suite uses a mock stdio MCP executor and checks auth, initialization, tools/list, tools/call, concurrency and origin rejection. Tests against the real Desktop Commander are not yet executed.

## Security blockers before exposing hostname
- V0 has a static bearer secret, not Cloudflare Access Managed OAuth. ChatGPT OAuth is NOT automatically interchangeable with this secret.
- Origin must independently verify Access identity, audience and token freshness. Expired/revoked credentials must be denied before command execution.
- No SSE, resumability, multi-tenant MCP session or server push; only JSON POST in current prototype.
- Single upstream stdio process; max 16 outstanding calls, max 1 MiB JSON body, 120-second call timeout.
- Dedicated OS user, no root, no general sudo and no docker.sock by default.
- No current VPS installation, Cloudflare route or plugin connection.

## Gates
G0: CI/mock tests. G1: build and test genuine executor under dedicated Linux account. G2: Cloudflare Access Managed OAuth and origin token validation, reject unauthorized. G3: route hostname and connect ChatGPT. G4: process restart, output safety, audit and optional controlled privilege escalation. G5: protected PR merge and release verification.

Current Cloudflare resource: tunnel vps-commander exists but remains inactive. Existing cofre tunnel, Pantheon, Hermes and OpenMausBot deployments must be left unchanged.