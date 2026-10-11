# G5 — Governed Commander Operations (2026-10-11 UTC)

## Scope and operational evidence

G5.1 delivers a **non-root read-only health diagnostic**, **root-only local configuration snapshot**, and a **read-only release-admission gate** for protected `main`. These three components are independent: a healthy runtime never requires switching the active Git checkout just because documentation or CI changed in GitHub.

### Real baseline (VPS gui)

- Four systemd units active: `vps-commander.service`, `vps-commander-executor.service`, `cloudflared-vps-commander.service`, and the pre-existing `cloudflared.service` (cofre). No service restarted.
- Gateway user `vpsc-gateway`; executor user `vpscommander`; gateway Access mode with audit active and origin only `127.0.0.1:8787`.
- Local anonymous `GET /healthz` **HTTP 401**; private Unix socket present. The authorized ChatGPT Commander client was previously confirmed G3.5 GREEN.
- RAM available ~4709 MiB; swap used ~3275 MiB; memory PSI `some avg10=0.00`; root disk **87% used**, 13 GiB available. This is a capacity WARNING, not proof that the Commander is causing memory pressure.
- Active checkout `feat/g3-access-hardening` at runtime functional commit `1bc99bf...`, clean when checked by administrative root. `main` is protected and includes all G1–G4. The six critical runtime source/unit blobs were already verified identical to the operational G3.5 commit, so **no redeploy** was justified.

## New operational tools

### A. Non-root diagnosis — `deploy/g5-health.sh`

Usable through the ChatGPT Commander `start_process` without granting root:

```bash
bash /opt/vps-commander/code/deploy/g5-health.sh
```

*(After that script is installed from a reviewed commit; during PR validation use the candidate checkout path.)*

Read-only checks: 4 systemd units; gateway/executor UID boundaries; Access/audit on; gateway `Wants` rather than hard `Requires` on executor; loopback port binding; origin unauthorized 401; Unix socket; 3 source module modes; root disk capacity; memory PSI. Produces `G5_HEALTH=GREEN`, `GREEN_WITH_WARNINGS`, or `RED` (nonzero exit for RED). WARN at disk utilization >=85%; never automatically clears disk/swap or restarts services. Local systemd tunnel `active` alone does **not** prove Cloudflare edge connectivity or complete OAuth flow. For end-to-end proof, issue a real authenticated ChatGPT Commander tool call and verify tunnel health through Cloudflare separately.

**Live candidate smoke:** `G5_HEALTH=GREEN_WITH_WARNINGS`, disk 87%, `G5_MEMORY_PSI_SOME_AVG10=0.00`; security and availability gates all PASS.

### B. Local configuration snapshot — `deploy/g5-backup.sh`

Manual, direct root SSH only. Never invoke as a root escalation through the unprivileged MCP. Performs fail-closed source/service checks and creates an immutable-by-convention `0700` root-only directory under `/var/backups/vps-commander/snapshot.*`. Stores:

- `0600` tarball of **only** the three VPS Commander systemd units plus the Access drop-in `20-access.conf` (contains access configuration; treat as confidential).
- `0600` manifest with timestamp, active Git SHA/branch, tar SHA-256 and explicit flags `offsite_verified=no` and `cloudflared_token_included=no`.
- Archive integrity is immediately checked by SHA-256 and listing. No secret values are logged.

```bash
sudo bash /path/to/reviewed/deploy/g5-backup.sh
```

**Limit:** backup is on the **same VPS/disk**, not an offsite or disaster-recovery backup. It does not copy Cloudflare tunnel credentials (remain in existing protected location), Git source (backed by protected GitHub), home directories, databases, or Pantheon/Hermes assets. Do not claim total VPS recovery or rotate/remove the existing tunnel token after creating this backup.

### C. Safe update decision — `deploy/g5-release-guard.sh`

Manual root SSH, **no service modification**. Validates source worktree clean, services active, anonymous HTTP 401, actual GitHub `main` branch protection, exact main SHA, and the two successful GitHub Actions checks (`gateway-tests`, `Check for spelling errors`). Fetches only the protected main tracking ref, never `git switch`, `reset`, `checkout`, `pull`, or `systemctl restart`.

Compares exact live commit and protected main for runtime paths (`gateway/`, `src/`, `package*.json`, `tsconfig.json`, `deploy/systemd/`).

- No runtime delta → `G5_RELEASE_GUARD=GREEN_NO_DEPLOY_NEEDED`, no restart or branch switch.
- Runtime delta → `G5_RELEASE_GUARD=HOLD_CANDIDATE_BUILD_AND_CUTOVER_REQUIRED` (nonzero), not an authorization to deploy.
- Invalid protection/checks/source/origin → RED and nonzero.

```bash
sudo bash /path/to/reviewed/deploy/g5-release-guard.sh
```

## Controlled failure playbook

1. If the gateway fails, run G5 health first. Administrative inspection of `systemctl status vps-commander.service` and `journalctl -u vps-commander.service --since ...` follows, with sanitized excerpts. Do not dump JWT, email allowlists, tunnel tokens or EnvironmentFiles.
2. If `EACCES` appears after a root Git branch change, compare modes of the three **tracked non-secret** gateway modules against Git mode `100644`. Correct narrowly only after confirmation; never `chmod -R` or `chown -R` on the VPS.
3. If executor drops, expect G3.3 reconnect events; do not automatically replay mutating tools, and never restart gateway merely to recover the worker.
4. Tunnel can temporarily be `activating` as a side effect of restarting the gateway due to systemd `Requires`; allow reasonable stabilization before declaring outage. Do not touch the independent `cofre` unit.
5. For rollback after future release, inspect the root-private local snapshot manifest and archive digest first; compare intended units one by one and restore explicitly with a separate approved root maintenance procedure, followed by `systemctl daemon-reload`, an authorized gateway-only controlled restart if strictly required, local 401 and ChatGPT OAuth smoke. **No blind tar extraction to `/`, no automatic service restarts or token rotation.**

## Tests and gates

- `deploy/test/g5-operations.test.mjs`: five tests for script syntax, fail-closed health, simulated inactive service, root-only snapshot boundaries and absence of mutating release commands.
- Candidate G5 on live host: G5 tests **5/5 PASS** and complete gateway/deploy suite **43/43 PASS**; health read-only `GREEN_WITH_WARNINGS` for disk threshold. 
- Root-only backup and release admission require real administrative check after reviewed PR. Do not claim completed before execution.
- No new Cloudflare policy, DNS, user privilege, unit, gateway runtime or application code is changed in G5.1.

## Next gates

**G5.1:** Merge reviewed PR; execute one root-private backup, verify its digest and record evidence; run root-only release guard on live checkout. 
**G5.2:** Only if a future runtime delta exists: build/test candidate under an isolated path, validate source lineage, take local rollback snapshot, perform root-authorized cutover with PID/identity/tunnel/JWT certification; halt and roll back on RED. Keep backup credential scope narrow, plan separately for encrypted offsite backup.
**G5.3 (optional):** Scheduled low-impact health check that reports changes only; do not create a daemon/timer or notification schedule without agreeing on cadence.

_GitHub is code authority, the VPS is operational truth. Existing Commander-specific Notion evidence is a handoff; Pantheon/Hermes canonical docs remain separately in their designated Google Drive folder and were not changed._ 
