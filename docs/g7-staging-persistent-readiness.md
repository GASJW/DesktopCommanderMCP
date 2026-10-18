# G7 isolated persistent staging package (prepared, not activated)

This package prepares two inert systemd unit templates, non-runnable config examples, and an operator runbook for a future local-only G7 staging service. It does not install accounts or units, create credentials, start processes persistently, enroll a real device, configure Cloudflare, or change G6. The services use the standalone G7 staging entrypoints and remain separate from `gateway/server.mjs`.

The persistent entrypoint flag (`--persistent-staging`) rejects `NODE_TEST_CONTEXT` and every environment key in the `VPSC_STAGING_TEST_*` or `VPSC_STAGING_FIXTURE_*` namespaces before reading configuration. The units also unset the current fixture selectors and do not load any EnvironmentFile. Disposable pilots retain the ordinary entrypoint mode and their existing fixture checks.

## Read-only VPS preflight evidence

Observed as an unprivileged user on 2026-10-17:

- `/opt/vps-commander/bin/node` is Node 22.23.2; `/usr/bin/node` is Node 18.19.1. Units pin Node 22 by absolute path.
- systemd 255 is available. `systemd-analyze` is installed. `npm`, `git`, `tar`, and `curl` are available to the non-root account. No unit was written or loaded.
- G6 Gateway is `vpsc-gateway:vpsc-ipc` on `127.0.0.1:8787`; G6 executor is a separate service/account. The tunnel listener observed at `127.0.0.1:20242` is also excluded. No G6 config or secret was read.
- `/opt/vps-commander/code` and G6 state are root-owned and are not referenced by these templates. Staging code is planned under `/opt/vps-commander/g7-staging`; state under two distinct `/var/lib/vpsc-g7-staging-*` roots.
- The existing Desktop Commander service runs as root. These units instead declare separate non-root Gateway and agent accounts, empty capability sets, `NoNewPrivileges=yes`, read-only code/config, and disjoint writable state roots.
- The filesystem had about 3.6 GiB free of 98 GiB, memory availability about 2.1 GiB, and four CPUs. A new activation must recheck these values and stop if less than 2 GiB is free under `/var/lib`; the observed 97% disk use is a material operational risk.
- There are several occupied listeners. Port 18443 is only a candidate in the examples; check it again immediately before activation and bind exclusively to `127.0.0.1`. G6 listeners are never reused.
- `/tmp` is private to root on this host. The disposable pilot must set a private owner-owned `TMPDIR` or use its existing `/var/tmp` fallback; global temporary directory permissions are not changed.

The measurements are a snapshot, not an ongoing reservation. A later final read-only check found 2.6 GiB free, and port 18443 had no listener at that time; neither observation reserves capacity or the port. They do not prove that a later port or resource check will pass. I attempted `systemd-analyze verify` as the non-root account against the inert templates and temporary copies; systemd returned `Failed to setup working directory: Permission denied` before unit validation. Offline security analysis also could not read the root-only system unit search paths. I did not elevate privileges or install units. The unit contract is covered by local static assertions; native systemd verification remains `BLOCKED_ENVIRONMENT` until a later authorized operator can run the documented verifier.

## Versioned files and target layout

- Units: `deploy/g7-staging/systemd/vpsc-g7-staging-gateway.service` and `deploy/g7-staging/systemd/vpsc-g7-staging-agent.service`.
- Inert configs: `deploy/g7-staging/config/gateway.json.example` and `deploy/g7-staging/config/agent.json.example`. Their `REPLACE_...` values are intentionally invalid. Never install these files unchanged.
- Readiness and rollback procedure: this document.

Future layout, subject to activation review:

| Purpose | Path | Owner/mode |
|---|---|---|
| reviewed immutable release | `/opt/vps-commander/g7-staging/releases/<reviewed-commit>`; `current` points to it | `root:root`, code not writable by service |
| Gateway config and Gateway-only keys | `/etc/vpsc-g7-staging-gateway` | `vpsc-g7-staging-gateway`, directory `0700`, files `0600` |
| agent config and its CA copy | `/etc/vpsc-g7-staging-agent` | `vpsc-g7-staging-agent`, directory `0700`, config `0600`, CA `0644` |
| Owner audit/WAL | `/var/lib/vpsc-g7-staging-gateway/audit` | Gateway account, `0700` |
| trust, machine binding, grants, policy | separate `trust`, `bindings`, `grants`, `policy` subdirectories under the Gateway state root | Gateway account, each `0700` |
| identity, execution ledger, approved operation root | separate `identity`, `ledger`, `approved-root` subdirectories under the agent state root | agent account, each `0700` |

No path under `/opt/vps-commander/code` or `/var/lib/vps-commander` is permitted. Keep the synthetic Owner signing private key outside both Gateway and agent release/config/state roots, in a separate owner-only client directory inaccessible to the service accounts. The Gateway JSON contains the synthetic Owner control token, machine service secret, policy private key, and paths to Gateway TLS/machine keys, so it must be mode `0600`; the agent JSON also contains its machine secret and is mode `0600`. Keep the machine key, TLS private key, and Owner control token synthetic and unique to this staging instance. Store the device Ed25519 key only in its agent identity directory. Do not put any value into a unit file, shell command argument, Git commit, journal message, or shared G6 credential store.

The Gateway and agent each have their own Unix identity and persistent state. The Gateway's health endpoint is available only on loopback. The agent pins the Gateway hostname, TLS CA, and `127.0.0.1` destination in its client. The I5D persistent runtime uses `createAuthenticatedMachineIngress()` as an in-process handler: it accepts only Gateway-minted machine JWTs, verifies the durable Client-ID/device/fingerprint binding and current trust, then forwards the signed agent frame to the existing channel transport. It opens no second HTTP listener. The disposable I5A/I5B harness keeps a separate explicit test-only loopback adapter; the persistent entrypoint does not import or enable it. No agent route is mounted into G6 and no public listener or Cloudflare integration is introduced.

## Credential and first enrollment preparation

This package does not generate or install persistent credentials. Before activation, an Owner-approved operator must provision distinct synthetic Owner and machine RSA keypairs, different issuer/audience values, synthetic Owner control and machine service tokens, a TLS key/certificate with SAN `g7-staging.test`, and a synthetic Ed25519 policy keypair. The example issuer names are fixed synthetic claim values, not network endpoints; the Gateway verifies signatures against the configured local JWKS and does not fetch those issuers. Keep the Owner signing private key with the separate synthetic Owner client. The Gateway receives the Owner verifier JWKS and identity values, machine verifier JWKS and signing key, policy private key, TLS private key/certificate, Owner control token, and synthetic machine service secret. The agent config receives its synthetic machine client ID and matching service secret, owner-approved device ID, policy public key, and TLS CA; the agent's Ed25519 identity private key remains in its identity directory. Generate all material outside the repository and transfer it through a secret-safe channel, not command-line literals.

The Gateway must be running before the existing Owner Only route can approve a synthetic device. The safe first-start order is: provision Gateway-only config and empty Gateway stores; start Gateway alone and check its loopback health endpoint; run `scripts/g7-staging-owner-provision.mjs` from the isolated Owner client account with an independently compared pairing request ID, code, and fingerprint; persist its returned I2-backed binding in the agent identity store; then start the agent. The client signs a short-lived synthetic Owner JWT outside the Gateway, uses TLS CA pinning plus exact Origin/CSRF and stage-control checks, performs each mutation once, and stops on an ambiguous response. It creates one `read_file` grant restricted to the approved root. The approved `deviceId` and bound v3 device identity must match before the worker can connect. No hostname-based or automatic enrollment is allowed. Confirm the Gateway journal contains `READY` and a healthy `/healthz` response before Owner operations; confirm the agent journal contains both `READY` and `ONLINE` after it connects. The CLI cannot edit trust, WAL, binding, or grant files. Persistent staging remains blocked until the systemd templates are natively verified and capacity has adequate headroom.

The config examples pin candidate loopback port `18443`, but this is not a reservation. Before creating secrets or installing units, check port, free space, memory, account isolation, and that no G6 path is mounted or referenced. The systemd `Restart=no` setting is intentional: recovery must be operator-controlled, with no automatic restart racing a reconciliation.

## Local disposable smoke test

Run from a reviewed checkout as a non-root user with Node 22 and a private temporary directory. This creates only synthetic in-memory or temporary material and launches Gateway and agent as separate child process groups. It builds and invokes the real Desktop Commander MCP entrypoint, reads a disposable file, runs one restricted governed write, tests restart/revocation and verifies all process groups stop before deleting the temporary state.

```sh
export PATH=/opt/vps-commander/bin:/usr/bin:/bin
export TMPDIR="$HOME/g7-staging-tmp"
install -d -m 0700 "$TMPDIR"
npm ci --ignore-scripts --no-audit --no-fund
npm run build
VPSC_STAGING_NODE=/opt/vps-commander/bin/node \
VPSC_STAGING_MCP_ENTRYPOINT="$PWD/dist/index.js" \
node --test packages/vpsc-agent/test/staging-runtime.test.mjs
```

The test runner intentionally enables fixture scenarios only in child test processes. Persistent systemd units use `--persistent-staging`, which rejects these variables even if they are present. Do not run the test suite with a persistent unit configuration or real state directories. Afterward, verify no child process remains and remove only the private temporary test directory owned by the invoking user.

## I5C local certification evidence (2026-10-17)

On Node 22.23.2 as non-root `itagil`, the disposable process pilot completed 5/5 top-level tests in 158.0 seconds. It built and invoked the real `dist/index.js`, completed a temporary-file read and governed write, restarted Gateway/agent separately, verified a fresh session and revocation, and left no pilot Gateway/agent process or listener. The live-job scenarios recorded: (1) Owner cancellation after agent receipt and after executor-start/process-live proof; the agent acknowledged cancellation, stopped the process, fenced the response, retained an ambiguous ledger outcome, and a subsequent read succeeded without replay; (2) grant revocation while the process was live; revocation and cancellation acknowledgement were observed before the 10-second job timeout, with an ambiguous fenced result and no replay; (3) device revocation while live; heartbeat rejected the revoked session, cancellation delivery became unavailable, the 10-second timeout stopped the process, and the result remained `AMBIGUOUS_TIMEOUT` with no replay. The before-execution cancellation path was also exercised and did not create an execution intent.

The staging package tests passed 5/5. The relevant Gateway and agent regression run covered 42 test files and exited 0 with 452 passing dots and no skip/failure markers. `node --check`, `git diff --check`, and the local secret scan passed. `systemd-analyze verify` remains `BLOCKED_ENVIRONMENT`: as a non-root caller it fails before parsing with `Failed to setup working directory: Permission denied`; no unit was installed and no privilege escalation was attempted. Hosted CI remains `BLOCKED_EXTERNAL`. These results certify temporary local staging behavior only; they do not certify persistent activation or production release.

## Install and validate commands for a later approved activation

**Do not run these commands as part of I5C.** They require a separate Owner decision to create accounts, install files under `/opt`, `/etc`, and `/etc/systemd/system`, provision synthetic secrets, and start persistent processes. The code release must be an explicitly reviewed commit after its PR dependency chain is accepted; do not install from an unreviewed working tree. The release build must include `dist/index.js` and production dependencies: `git archive` does not include ignored build output or `node_modules`. Build and smoke-test the exact reviewed commit in a private non-root directory, then prune development dependencies and copy that immutable tree into the root-owned release directory. Recheck capacity before building; stop if less than 2 GiB are available.

First repeat the preflight and verify the candidate port and at least 2 GiB free:

```sh
id vpsc-g7-staging-gateway || true
id vpsc-g7-staging-agent || true
test "$(df -Pm /var/lib | awk 'NR==2 {print $4}')" -ge 2048
if ss -H -ltn 'sport = :18443' | grep -q .; then echo 'port 18443 is occupied' >&2; exit 1; fi
/opt/vps-commander/bin/node --version
systemd-analyze --version
```

After approval, an administrator may create two dedicated system accounts and install the reviewed release and units. First build and validate the exact reviewed commit as a non-root release builder from a clean checkout. Set `REVIEWED_COMMIT` to the reviewed full SHA before running this block; it fails if the checkout differs or has local modifications:

```sh
set -eu
: "${REVIEWED_COMMIT:?Set REVIEWED_COMMIT to the exact reviewed full SHA}"
test "$(git rev-parse HEAD)" = "$REVIEWED_COMMIT"
test -z "$(git status --porcelain)"
test "$(/opt/vps-commander/bin/node --version)" = v22.23.2
test "$(df -Pm "$HOME" | awk 'NR==2 {print $4}')" -ge 2048
BUILD_ROOT="$HOME/g7-staging-build-$REVIEWED_COMMIT"
mkdir -m 0700 "$BUILD_ROOT"
git archive "$REVIEWED_COMMIT" | tar -x -C "$BUILD_ROOT"
cd "$BUILD_ROOT"
PATH=/opt/vps-commander/bin:/usr/bin:/bin npm ci --ignore-scripts --no-audit --no-fund
PATH=/opt/vps-commander/bin:/usr/bin:/bin npm run build
test -s dist/index.js
PATH=/opt/vps-commander/bin:/usr/bin:/bin VPSC_STAGING_NODE=/opt/vps-commander/bin/node VPSC_STAGING_MCP_ENTRYPOINT="$BUILD_ROOT/dist/index.js" /opt/vps-commander/bin/node --test packages/vpsc-agent/test/staging-runtime.test.mjs
PATH=/opt/vps-commander/bin:/usr/bin:/bin npm prune --omit=dev --ignore-scripts --no-audit --no-fund
PATH=/opt/vps-commander/bin:/usr/bin:/bin npm ls --omit=dev --depth=0
test -s dist/index.js
```

Then create the service identities, copy the validated runtime tree into a root-owned immutable release, and install the inert unit files:

```sh
sudo groupadd --system vpsc-g7-staging-gateway
sudo useradd --system --gid vpsc-g7-staging-gateway --home-dir /nonexistent --shell /usr/sbin/nologin vpsc-g7-staging-gateway
sudo groupadd --system vpsc-g7-staging-agent
sudo useradd --system --gid vpsc-g7-staging-agent --home-dir /nonexistent --shell /usr/sbin/nologin vpsc-g7-staging-agent
RELEASE="/opt/vps-commander/g7-staging/releases/$REVIEWED_COMMIT"
sudo install -d -o root -g root -m 0755 "$RELEASE"
sudo cp -a "$BUILD_ROOT/." "$RELEASE/"
sudo chown -R root:root "$RELEASE"
sudo chmod -R a-w "$RELEASE"
sudo ln -s "$RELEASE" /opt/vps-commander/g7-staging/current.new
sudo mv -Tf /opt/vps-commander/g7-staging/current.new /opt/vps-commander/g7-staging/current
sudo install -o root -g root -m 0644 deploy/g7-staging/systemd/vpsc-g7-staging-gateway.service /etc/systemd/system/
sudo install -o root -g root -m 0644 deploy/g7-staging/systemd/vpsc-g7-staging-agent.service /etc/systemd/system/
sudo systemd-analyze verify /etc/systemd/system/vpsc-g7-staging-gateway.service /etc/systemd/system/vpsc-g7-staging-agent.service
sudo systemd-analyze security vpsc-g7-staging-gateway.service vpsc-g7-staging-agent.service
sudo systemctl daemon-reload
```

Then provision the configuration and credentials through an Owner-approved secret channel. Create distinct service-owned subdirectories at mode `0700`; write completed configs atomically with mode `0600`; verify all config ancestors are not writable by group/other and all private keys are single-link regular files. Create all listed store directories and the agent's approved root as empty `0700` directories owned by the corresponding service account. Install the agent's public CA copy as an agent-owned `0644` regular file. Never copy G6 state or identities.

Start Gateway alone first. Its configuration and empty Gateway stores must already be protected; keep the agent stopped. Verify health using the agent account because its CA file is inside a mode-`0700` directory. Then run the reviewed synthetic Owner provisioning CLI from its isolated owner-only account to durably approve the independently confirmed pairing, bind the machine identity, and create the restricted grant. Persist the returned binding through the existing agent identity-store API and verify its fingerprint matches the agent's local Ed25519 identity. Start the agent only after those checks.

```sh
sudo systemctl start vpsc-g7-staging-gateway.service
sudo -u vpsc-g7-staging-agent curl --fail --silent --show-error \
  --resolve g7-staging.test:18443:127.0.0.1 \
  --cacert /etc/vpsc-g7-staging-agent/ca.crt \
  https://g7-staging.test:18443/healthz
# Owner Only pairing, approval, binding, and grant run via the reviewed synthetic client here.
# Stop and leave Gateway alone if that client or the offline identity tool is unavailable.
sudo systemctl start vpsc-g7-staging-agent.service
sudo systemctl is-active vpsc-g7-staging-gateway.service vpsc-g7-staging-agent.service
sudo journalctl --unit=vpsc-g7-staging-gateway.service --since=-10m --no-pager
sudo journalctl --unit=vpsc-g7-staging-agent.service --since=-10m --no-pager
# Confirm READY/ONLINE and perform the Owner-authorized local smoke read first.
# Only afterward, if the Owner explicitly approves persistence across host restarts:
sudo systemctl enable vpsc-g7-staging-gateway.service vpsc-g7-staging-agent.service
```

For an Owner-authenticated operation, use only the synthetic Owner client and a file created under the agent's approved root. Never place an Owner token on the command line. Verify the returned device ID, policy revision, trust revision, and audit/ledger evidence. This health/read test is a local staging check; it does not authorize public access or production use.

## Shutdown, recovery, and rollback

Normal shutdown is always agent first, Gateway second. `Restart=no` prevents systemd from relaunching either service after exit. During recovery, apply a runtime launch fence before examining state:

```sh
sudo systemctl mask --runtime vpsc-g7-staging-agent.service vpsc-g7-staging-gateway.service
sudo systemctl stop vpsc-g7-staging-agent.service
sudo systemctl stop vpsc-g7-staging-gateway.service
sudo systemctl is-active vpsc-g7-staging-agent.service vpsc-g7-staging-gateway.service || true
sudo systemctl show vpsc-g7-staging-agent.service vpsc-g7-staging-gateway.service -p MainPID -p ControlGroup -p ActiveState -p SubState
sudo systemd-cgls --unit vpsc-g7-staging-agent.service
sudo systemd-cgls --unit vpsc-g7-staging-gateway.service
pgrep -a -u vpsc-g7-staging-agent || true
pgrep -a -u vpsc-g7-staging-gateway || true
```

Record both unit cgroups, MainPID values, process start times, and the known MCP child processes. Confirm that no writer or reconciler remains and that no `/proc/<pid>/fd` points into the Gateway audit/trust/binding/grant roots or the agent identity/ledger roots. If `/proc` is hidden, any process is unclassified, or any known supervisor can restart a writer, stop here and preserve the locks. A boolean passed to an I2 function is an operator attestation; it does not perform this process verification.

Use the existing read-only `analyzeOwnerPairingRecovery()` on the exact audit and trust directories. No recovery CLI is bundled; the command below is an explicit read-only invocation under the Gateway account. Preserve its structured output and lock listing:

```sh
sudo -u vpsc-g7-staging-gateway /opt/vps-commander/bin/node --input-type=module -e '
import { analyzeOwnerPairingRecovery } from "/opt/vps-commander/g7-staging/current/gateway/dashboard/owner-pairing-reconciliation.mjs";
const result = analyzeOwnerPairingRecovery({
  auditDirectory: "/var/lib/vpsc-g7-staging-gateway/audit",
  trustDirectory: "/var/lib/vpsc-g7-staging-gateway/trust",
});
process.stdout.write(JSON.stringify(result) + "\n");
'
```

Do not start the Gateway while locks or inconsistent evidence are under review. Only after an Owner has explicitly authorized recovery and the operator independently confirms no writers, invoke `reconcileOwnerPairingRecovery()` once with `operatorConfirmedNoActiveWriters: true`; that boolean records the operator's attestation and does not establish quiescence. Preserve the pre-state, function result, then re-run the analyzer and verify the post-state. The exact authorized invocation is:

```sh
sudo -u vpsc-g7-staging-gateway /opt/vps-commander/bin/node --input-type=module -e '
import { reconcileOwnerPairingRecovery } from "/opt/vps-commander/g7-staging/current/gateway/dashboard/owner-pairing-reconciliation.mjs";
const result = reconcileOwnerPairingRecovery({
  auditDirectory: "/var/lib/vpsc-g7-staging-gateway/audit",
  trustDirectory: "/var/lib/vpsc-g7-staging-gateway/trust",
  operatorConfirmedNoActiveWriters: true,
});
process.stdout.write(JSON.stringify(result) + "\n");
'
```

Never automatically invoke `clearStaleOwnerPairingRecoveryLocks()`. Use it only after proving the reconciliation process itself is dead and its lock evidence is classified stale. Corrupt, contradictory, incomplete, active, or unverified evidence remains blocked; do not delete or recreate stores, WAL, grants, identity, ledger, temporary files, or locks to make startup pass.

Rollback affects G7 staging only:

1. Keep the runtime mask in place and verify both service cgroups are empty.
2. Preserve a mode-`0700` incident snapshot of the two staging config directories and all Gateway/agent state directories; do not edit or delete the original evidence.
3. Restore the previous reviewed G7 code symlink only if its compatibility with current state has been reviewed. Restore configuration files from a protected backup only after reviewing them. Do not roll back trust revisions or replace current state with an old state snapshot.
4. If a diagnostic reports ambiguity, corruption, unexpected revision, stale unknown lock, or history mismatch, keep both services stopped and escalate with the saved evidence.
5. To leave staging inactive, leave the units runtime-masked and stopped. To resume only after an explicit Owner decision and successful consistency checks, remove the runtime masks and start Gateway first, then agent.

After confirming quiescence, preserve state before changing configuration or code. Use a unique incident directory and keep it outside the active state roots:

```sh
INCIDENT_ID="$(date -u +%Y%m%dT%H%M%SZ)"
SNAPSHOT="/var/lib/vpsc-g7-staging-incidents/$INCIDENT_ID"
sudo install -d -o root -g root -m 0700 /var/lib/vpsc-g7-staging-incidents
sudo mkdir -m 0700 "$SNAPSHOT"
sudo install -d -o root -g root -m 0700 "$SNAPSHOT/gateway-config" "$SNAPSHOT/agent-config" \
  "$SNAPSHOT/gateway-state" "$SNAPSHOT/agent-state"
sudo cp -a /etc/vpsc-g7-staging-gateway/. "$SNAPSHOT/gateway-config/"
sudo cp -a /etc/vpsc-g7-staging-agent/. "$SNAPSHOT/agent-config/"
sudo cp -a /var/lib/vpsc-g7-staging-gateway/. "$SNAPSHOT/gateway-state/"
sudo cp -a /var/lib/vpsc-g7-staging-agent/. "$SNAPSHOT/agent-state/"
sudo chmod 0700 "$SNAPSHOT" "$SNAPSHOT"/*
```

Only after reviewing the selected prior release and its state compatibility, update the code symlink atomically. Replace the value with the exact previously reviewed SHA; do not run this if no prior release exists:

```sh
: "${PREVIOUS_REVIEWED_COMMIT:?Set the compatible prior reviewed SHA}"
PREVIOUS_RELEASE="/opt/vps-commander/g7-staging/releases/$PREVIOUS_REVIEWED_COMMIT"
test -d "$PREVIOUS_RELEASE"
sudo ln -s "$PREVIOUS_RELEASE" /opt/vps-commander/g7-staging/rollback.new
sudo mv -Tf /opt/vps-commander/g7-staging/rollback.new /opt/vps-commander/g7-staging/current
```

Do not restore any old trust, grant, WAL, binding, identity, or execution-ledger snapshot over the current stores. If consistent recovery cannot be demonstrated, preserve both original state and incident snapshot and keep the services masked and stopped.

```sh
sudo systemctl unmask vpsc-g7-staging-agent.service vpsc-g7-staging-gateway.service
# Start Gateway, confirm health, then start agent only after Owner authorization.
```

The rollback never changes, stops, restarts, or reads G6 configuration/state. The templates do not enable automatic trust/grant recovery, auto-enrollment, automatic replay, or a public listener.

## Known limitations and authorization boundary

- Hosted GitHub Actions remains `BLOCKED_EXTERNAL`; local test results do not certify a production release.
- Port 18443 must be checked again; capacity is constrained by the host's near-full filesystem.
- This is synthetic same-host loopback staging with a staging-only machine-ingress boundary, not the final production transport or a remote-device enrollment.
- No persistent Owner provisioning client or automatic recovery CLI is added. The existing Owner Only client and explicit operator review are activation prerequisites.
- User/group creation, `/opt`, `/etc`, `/var/lib`, and systemd writes; provisioning any secret/certificate/key; starting or stopping persistent G7 services; Owner pairing/binding/grant; recovery lock handling; and any public/network/Cloudflare exposure require separate explicit Owner approval. Main merge, production deploy, G6 changes, and real-device enrollment remain out of scope.
