# G1 — VPS Commander Live Evidence (2026-10-10)

## Scope and authority
Bootstrap on the authorized `gui` Linux VPS using Remote Desktop Commander **temporarily**. Objective is to eliminate the ongoing RDC dependency after a safe deployment. NO Cloudflare public route was created.

## Observed runtime
- Host: `gui` (Ubuntu 24.04.4 LTS, amd64)
- Service user: `vpscommander` (dedicated unprivileged account)
- Source: `/opt/vps-commander/code`; branch `feat/vps-commander-foundation`
- Runtime: `/opt/vps-commander/bin/node` = v22.23.2; copied independent from `/root/.hermes`
- Build: 1083 packages installed via `npm ci --ignore-scripts` by dedicated user; `npm run build` EXIT 0
- Branch checked out during build: `d04a255` (Chrome prefetch disabled by `VPS_COMMANDER_DISABLE_BROWSER_INIT=1`)
- Unit: `/etc/systemd/system/vps-commander.service` with `enabled`, `active (running)`; template in `deploy/systemd/vps-commander.service`
- Endpoint: **127.0.0.1:8787 only**, not 0.0.0.0; unauthenticated GET /healthz = HTTP 401
- Last observed free disk after build ~14 GB (86% used); memory at start ~4.2 GiB available.
- Secrets: random gateway token only in `/var/lib/vps-commander/.config/vps-commander/gateway.env`, mode 0600, service-owned. NEVER COPY INTO GIT.

## Live tool smoke (before systemd activation)
- POST /mcp: unauthorized request denied 401
- GET /healthz with bearer: ready
- initialize: returned MCP response
- tools/list: 26 Desktop Commander tools
- tools/call/read_file: PASS (`/etc/os-release`)
- tools/call/start_process: PASS (`printf VPS_COMMANDER_REAL_TERMINAL_GREEN`)
- tools/call/write_file + read_file: PASS (isolated `/var/lib/vps-commander/workspace/smoke.txt`)
- Node mock test suite: 2/2 PASS on VPS after source rebuild.

## Persistent unit smoke
- `systemctl is-active vps-commander.service` = active.
- `ss` = listener exclusively `127.0.0.1:8787`.
- Unauthenticated GET /healthz = HTTP 401.
- **Full authenticated MCP operations have NOT been re-run against the systemd unit yet**; preserve as pending verification, not assumed PASS.

## Isolation
- Program tree root-owned after building; service executes as `vpscommander` without capabilities or privilege escalation.
- systemd `ProtectSystem=strict`, `ProtectHome=true`, `NoNewPrivileges=true`, writable `/var/lib/vps-commander` and private /tmp.
- Existing `cloudflared`, `cofre`, Pantheon, Hermes, and OpenMausBot services not modified.

## Blockers
**Cloudflare Managed OAuth and origin-side JWT validation are mandatory before publishing** `commander.supercerebro.me`. The gateway currently uses a static local bearer token and MUST NOT be considered a secure public API. The Cloudflare tunnel `vps-commander` is reserved but remains inactive.

## Useful commands (over SSH)
- `systemctl status vps-commander.service`
- `journalctl -u vps-commander.service -n 50 --no-pager`
- `ss -lnt '( sport = :8787 )'`
- `systemctl stop vps-commander.service` (rollback)
- `systemctl disable --now vps-commander.service` (disable autostart and stop)

## Key improvement
The executor now persists under systemd and no longer needs an active Remote Desktop Commander session. A future ChatGPT connection still requires OAuth and Access certification.
