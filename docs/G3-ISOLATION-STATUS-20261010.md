# G3.1 — CERTIFICAÇÃO LIVE GREEN (2026-10-10)

**Estado operacional atual: G3.1 GREEN para isolamento dos dois serviços e smoke MCP autenticado.** As seções históricas abaixo descrevem os estados anteriores ao cutover e não devem ser interpretadas como status atuais.

## Evidência do bootstrap efetuado pelo owner via SSH
- `git fetch` corrigido incluindo a branch G3 no refspec; `switch --track origin/feat/g3-executor-isolation` feito; 11/11 testes no bootstrap PASS.
- Bootstrap reportado: `G3_EXECUTOR_ISOLATION=BOOTSTRAP_GREEN`; unidades systemd criadas/reiniciadas e verificadas.
- Inspeção posterior **pelo próprio plugin ChatGPT Commander**: `vps-commander.service` active com `User=vpsc-gateway`; `vps-commander-executor.service` active com `User=vpscommander`.
- `cloudflared-vps-commander.service` e `cloudflared.service` ativos na VPS. API Cloudflare confirmou **vps-commander healthy (4 conexões)** e **cofre healthy (4 conexões)**.
- IPC: `/run/vps-commander-ipc/mcp.sock` é socket Unix, proprietário `vpscommander`, grupo `vpsc-ipc`, permissões `0660`.
- Shell remoto autenticado via plugin: `id` retornou UID 994 `vpscommander` e GID `vpsc-ipc`; `G3_REAL_CHATGPT_TERMINAL_GREEN` executou com sucesso.
- Falha original corrigida (checagem de permissões sem ler credenciais):
  - `test -r /proc/<gateway-main-pid>/environ` executado pelo plugin como `vpscommander`: **DENIED**.
  - `test -r /var/lib/vps-commander-gateway`: **DENIED**.
  - `test -r /var/lib/vps-commander/.config/vps-commander/gateway.env`: **DENIED** (arquivo removido no bootstrap, com cópia rollback root-only segundo script).
- `read_file /etc/os-release`: PASS (Ubuntu 24.04.4 LTS).
- `write_file` em `/var/lib/vps-commander/workspace/g3-chatgpt-e2e-20261010.txt`: PASS; leitura de volta comprovou `G3_1_E2E_WRITE_GREEN` e `TRANSPORT=CHATGPT_CUSTOM_MCP`.
- A utilização do plugin com essas chamadas comprova fluxo autenticado ChatGPT → Cloudflare Access → gateway → Unix socket → executor.
- Uma checagem suplementar contendo vários comandos em um único `start_process` foi bloqueada por configurações da plataforma OpenAI; não houve tentativa de contorná-la. Isso não invalidou as checagens individuais anteriores.

## Limites do aceite
- G3.1 certifica isolamento de identidades e os caminhos sensíveis **efetivamente testados**; não prova segurança absoluta nem elimina ataques possíveis através de ferramentas do sistema ou permissões futuras.
- Ainda não fizemos os gates de auditoria de comandos (G3.2), resiliência/failover (G3.3), limites e contenção (G3.4), e testes de autorização abrangentes (G3.5).
- **PR #2 continua Draft** até revisão governada e decisão de integração. G2 PR #1 permanece separado.
- Pantheon, Hermes, OpenMausBot, políticas e DNS existentes não foram alterados por esse cutover.

---

## Git bootstrap incident: single-branch checkout (2026-10-10)

First owner SSH cutover attempt FAILED **before running any G3 bootstrap**.
The original G1 checkout was cloned with `--single-branch` and tracks only
`+refs/heads/feat/vps-commander-foundation:refs/remotes/origin/feat/vps-commander-foundation`.
`git fetch origin` did not fetch `feat/g3-executor-isolation`; therefore `git switch --track origin/feat/g3-executor-isolation` returned `fatal: invalid reference` and the bootstrap path was absent.

Evidence via Commander: remote `ls-remote` confirms branch `feat/g3-executor-isolation` exists at e5f488f195cad49920978866a7913dc43eb77237; existing services `vps-commander.service` and `cloudflared-vps-commander.service` both active; checkout tree clean; worker unit absent. No production migration occurred.

Remedy over owner direct SSH (run in this order):
```bash
sudo git -c safe.directory=/opt/vps-commander/code -C /opt/vps-commander/code remote set-branches --add origin feat/g3-executor-isolation
sudo git -c safe.directory=/opt/vps-commander/code -C /opt/vps-commander/code fetch origin
sudo git -c safe.directory=/opt/vps-commander/code -C /opt/vps-commander/code switch --track origin/feat/g3-executor-isolation
sudo bash /opt/vps-commander/code/deploy/bootstrap-g3-isolation.sh
```
Do not call the bootstrap if branch switch fails. The script restarts the MCP briefly and should be run only over direct SSH. After bootstrap, certify OAuth tools and secret isolation from this chat.

---
# G3.1 — Gateway/Executor Isolation (2026-10-10)

## Current status
**Histórico pré-cutover:** RED observado no G2, implementação candidata GREEN, G3.1 ainda não implantado naquele momento.
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
