# G3.1 — Gateway/Executor Isolation (2026-10-10)

## Current status
**RED observed in current G2 production, implementation GREEN in tests, G3.1 not deployed.**
Tests and candidate code must not be confused with OS-level isolation certification.

## Problem (real, read-only)
Via the custom ChatGPT Commander plugin on VPS gui:
- uid=994(vpscommander) runs BOTH the HTTP gateway and shell executor.
- `test -r /var/lib/vps-commander/.config/vps-commander/gateway.env` returned true.
- `test -r /proc/<gateway_pid>/environ` returned true.
Only readability was checked. No secret contents were requested, copied, displayed or stored.

## Design
Create two separate systemd services and Linux UIDs:
- Gateway: `User=vpsc-gateway`, `Group=vpsc-ipc`, `ProtectSystem=strict`, `ProtectProc=invisible`, `InaccessiblePaths=/var/lib/vps-commander`.
- Executor: `User=vpscommander`, `Group=vpsc-ipc`, shell and files; owned workspace `/var/lib/vps-commander/workspace`.
- Gateway connects to `/run/vps-commander-ipc/mcp.sock` rather than spawning the executor.
- Executor owns the socket directory (0750) and the socket file (0660); group is `vpsc-ipc`.
- JWT Cloudflare Access verification stays in the gateway. Old local bearer file is archived root-only for rollback and removed from the executor-readable directory after success.
- Dedicated Cloudflare Tunnel still routes to `127.0.0.1:8787`; DNS, Access policies and the cofre tunnel are unchanged.

## Evidence candidate GREEN
- GitHub Actions for gateway transport tests passed; later local candidate test suite **11/11 PASS** on VPS gui.
- The local suite included signed Access JWT checks, stateless MCP relay, Unix socket connectivity, token inheritance negative test, systemd unit static guards, and bootstrapping safeguards.
- Real Desktop Commander via **candidate Unix socket** executed `tools/list` (26 tools), `start_process` (`G3_REAL_SOCKET_GREEN`), and `read_file` (`/etc/os-release`) successfully.
- Candidate used an ephemeral socket and gateway listener. Real production gateway/Cloudflare connector services were not restarted.

## Scoped installation and rollback
Prepared files:
- `gateway/executor-socket.mjs` standalone stdio MCP worker over Unix socket.
- `gateway/server.mjs` extended to use `VPS_COMMANDER_EXECUTOR_SOCKET`.
- `deploy/systemd/vps-commander-executor.service` non-root executor unit.
- `deploy/systemd/vps-commander-g3.service` separate gateway unit.
- `deploy/bootstrap-g3-isolation.sh` fail-closed bootstrap with root-only backup and automatic rollback on error.

**Do not run the bootstrap through the unprivileged Commander plugin.** It requires an owner-approved direct root SSH session.
Before execution, ensure no long-running Commander tasks need continuity; cutover restarts `vps-commander.service` briefly.

Suggested owner SSH workflow (NOT performed):
```bash
sudo git -c safe.directory=/opt/vps-commander/code -C /opt/vps-commander/code fetch origin
sudo git -c safe.directory=/opt/vps-commander/code -C /opt/vps-commander/code switch --track origin/feat/g3-executor-isolation
sudo bash /opt/vps-commander/code/deploy/bootstrap-g3-isolation.sh
```

Gate after cutover:
- `systemctl is-active vps-commander.service vps-commander-executor.service cloudflared-vps-commander.service` each active.
- `systemctl show -P User`: gateway `vpsc-gateway`, worker `vpscommander`.
- Unix socket group/mode `vpsc-ipc` / 660.
- Executor cannot read gateway process `/proc/PID/environ` or gateway private home; old token file removed from readable executor home.
- ChatGPT custom Commander authenticates and runs harmless `tools/list`, `start_process`, `read_file`, `write_file` after cutover.
- Tunnel and cofre healthy; unauthenticated public MCP still HTTP 401.

### Rollback
The installer auto-restores the backed-up G2 gateway unit and legacy token on errors, disables the new worker and recovers the tunnel. The backups stay under `/root/vps-commander-g3-backup` (root-only).
Manual rollback should be performed by a privileged operator only; see the bootstrap's `rollback()` function. Never remove Cloudflare DNS, Access, or tunnel settings to solve a local isolation failure.

## Not in G3.1
Auditable per-command logs (G3.2); failure-recovery exercises (G3.3); runtime resource/response caps (G3.4); expanded OAuth penetration tests (G3.5).

## Exit criteria
**G3.1 cannot be marked GREEN until the distinct-UID production cutover and post-cutover live ChatGPT smoke have PASS evidence.**
PR #2 remains Draft, stacked on G2 PR #1. No merge, no privilege escalation.
