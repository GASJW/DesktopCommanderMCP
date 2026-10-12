# G6 — Owner-approved root developer mode (not deployed)

## Objective

Reproduce the **RDC root-level execution capability** using the self-hosted Commander Gateway while keeping the Cloudflare Access **Owner Only** boundary. This is an optional, high-privilege administrative mode for the owner's own VPS. The user explicitly requested full root execution and prefers authorization until manual revocation.

**Not the same as G7's future per-device administrative grants:** this G6 mode intentionally exposes the current full Desktop Commander MCP tool surface as root to anyone who can authenticate as the authorized owner. It is broad privilege, not granular least-privilege sandboxing.

## Observed starting point (VPS gui, Ubuntu 24.04)

- Productive `/opt/vps-commander/code` on `e599678fcec71725ff16303e99b87db236746f02`; active standalone Gateway `vps-commander.service` running as `vpsc-gateway`.
- Separate `vps-commander-executor.service` running as `vpscommander`, connected to Gateway over `/run/vps-commander-ipc/mcp.sock` (0660 `vpsc-ipc` group).
- Cloudflare Access validation on the Gateway; local anonymous `/mcp` returns 401. The executor itself does not listen on a public port.
- Original executor limits include `NoNewPrivileges=yes`, capability bounding set empty, and strong systemd filesystem isolation. **Simply setting `User=root` without examining those inherited restrictions would not provide full root parity.**
- Root filesystem approximately 91% used (~9.3 GiB available).
- Existing G6 audit journal records owner identity, RPC operation, tool name, outcome and HTTP status. **It does not durably record a complete shell command and its full arguments, nor block execution if journal logging fails.** Do not claim complete privileged-command audit. Root actions remain high risk.

## Current status

The automated activation of a root executor was previously **blocked by the tool's safety enforcement**. This PR is only a versioned candidate / direct-console owner runbook. **No tool-mediated attempt to bypass that block, no privileged service change or forced merge/deploy.**

This PR ships three scripts:
- `deploy/g6-owner-root-activate.sh`: strongly guarded administrative activation; drops in only the executor's systemd override, never alters the Gateway service, disables selected executor sandbox flags to provide root parity, arms a 7-minute automatic rollback timer, restarts the executor only, and verifies systemd user/group/socket plus unauthorized 401.
- `deploy/g6-owner-root-revert.sh`: explicitly restores `vpscommander`, refusing to remove an unrelated/modifed override.
- `deploy/g6-owner-root-confirm.sh`: after an independently verified root Commander tool call, cancels the automatic timer for **indefinite developer mode until manual revocation**. Confirming without a real Commander/root test is forbidden.

The script requires a direct administrative root console plus `VPSC_OWNER_ROOT_CONSENT=I_ACCEPT_FULL_ROOT_MCP` and refuses unexpected production code revisions, foreign overrides or inactive services. It backs up the original unit in a root-owned directory `/root/vpsc-g6-root-dev`.

## Administrative execution — manual only, after review

1. Open a **separate, live root-capable SSH/console** before any cutover and keep it available for rollback. Do not run activation through Commander, RDC, an LLM tool, cron, or a remotely editable non-root workspace.
2. Review the exact PR commit and its scripts. Copy verified scripts to a **root-owned 0700 directory** under `/root`; refuse unreviewed source changes. Do not run them directly out of a `vpscommander`-writable Git worktree. Validate `bash -n` and file hashes.
3. On that root console, explicitly invoke the reviewed `g6-owner-root-activate.sh` with the consent environment variable. The 7-minute timer will automatically execute the root-private rollback copy if unconfirmed.
4. In the separate ChatGPT Commander session, confirm an *actual* `start_process` result `id -u = 0` and appropriate path-level root operation against a disposable file. Confirm Gateway remains owner-only and public anonymous authentication still returns 401. **A systemd MainPID UID of 0 alone is not sufficient to claim the remote tool can do root operations.**
5. Back in the already-open root console, invoke `g6-owner-root-confirm.sh` with the same consent variable within seven minutes only after all checks pass. This stops the rollback timer; the mode then persists until manually revoked.
6. To revoke, use the root-private `/root/vpsc-g6-root-dev/revert.sh` from an independent root shell. Confirm the original executor user `vpscommander`, gateway `vpsc-gateway`, MCP login and existing tunnels. **Do not delete the root backup until successful rollback**.

Scripts intentionally do not modify Git main, Cloudflare policy, Access issuer/audience, token storage, app/G7 branches, the cofre, or other stacks. This operation requires a brief executor restart and can temporarily interrupt a current MCP session; recovery through the existing Gateway reconnect mechanism must be independently checked.

## Known risks / admission gate

The existing Cloudflare owner-only authentication is necessary but does not make root execution intrinsically safe. With this mode enabled, every authorized `tools/call` available from the MCP executor can potentially run as UID 0, including process execution and sensitive file reads/writes. A compromised owner session or an unintended tool call has host-level impact. Existing audit is metadata-oriented and non-fail-closed. No fake claim of complete forensic coverage.

Do not combine this G6 root cutover with G7 ingress/agent activation or Cloudflare Service Auth modifications. Leave RDC/SSH as a recovery channel until multiple independent root and rollback tests pass. A platform-level tool refusal can still occur regardless of the Unix UID of the executor.

The intended long-term product is G7's separately authorized, time-scoped or indefinite-per-device Root/Admin grants and durable audit. This G6 pilot is an explicit interim owner choice, subject to independent administrative activation.

**This PR does not activate any root capabilities.**
