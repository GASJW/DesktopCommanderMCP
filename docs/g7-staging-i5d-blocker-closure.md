# G7 I5D persistent staging blocker closure

This change closes the unsafe machine-ingress boundary and adds the first synthetic Owner provisioning client. It prepares the staging package for review; it does not activate persistent staging, install systemd units, modify G6, or create production credentials.

## Persistent machine ingress boundary

The persistent runtime now calls `createAuthenticatedMachineIngress()` directly inside its existing TLS Gateway listener. This handler opens no listener and requires all of the following before forwarding an agent frame:

- A Gateway-minted M2M JWT that passes the configured issuer, audience, signature, expiry, and Client-ID verifier.
- A durable machine binding resolved from the store, including its client ID, device ID, fingerprint, binding revision, and I2 approval/trust revisions.
- Current trust for that exact device ID and fingerprint.
- A request device ID consistent with the bound device, followed by the existing signed-agent-frame/session/replay checks.

The external `/agent/*` edge separately requires the configured synthetic machine Client-ID and service secret, rejects Owner/browser credentials, and mints the short-lived JWT inside the Gateway. The TLS server remains loopback-only. `gateway/server.mjs` does not import this staging composition.

The internal JWT is a short-lived bearer assertion, not a one-use token: it has no `jti` cache. It is never accepted from the external client, and possession of the assertion by itself does not authorize a device frame. Each connect consumes a fresh Ed25519-signed challenge once; every subsequent agent request signs the route and body with the current session and a strictly increasing sequence, which the shared transport rejects on replay. This replay guarantee depends on keeping the authenticated handler inside the current Gateway composition; do not expose it as a listener or reuse the internal JWT as an external credential.

The disposable pilot keeps `startMachineIngressLoopback()` as an explicitly enabled test adapter. Persistent staging does not call it, set `enableTestIngress`, or load `VPSC_STAGING_TEST_*`/`VPSC_STAGING_FIXTURE_*` selectors. Persistent entrypoints reject those selectors before opening configuration. This preserves separate test and persistent compositions without introducing a second identity system.

## Synthetic Owner provisioning

Run `scripts/g7-staging-owner-provision.mjs` from a non-root, owner-only client account after the test device independently displays its request ID, comparison code, and Ed25519 fingerprint. The operator supplies one JSON confirmation object over stdin. The client:

1. Connects only to `127.0.0.1`, validates TLS against the configured local CA and hostname, and accepts only the fixed synthetic staging Owner identity.
2. Mints a short-lived RS256 Owner JWT in memory from a private key outside Gateway and agent release/config/state paths.
3. Uses the Owner pending API, exact Origin and CSRF, then submits one durable I2 approval.
4. Creates one durable Client-ID/device binding and one `read_file` grant constrained to one staging root with fixed byte/length/offset limits.
5. Returns only non-secret revisions, IDs, a validated binding receipt, and a bounded grant record needed by the existing agent identity-store procedure.

The client never edits trust, WAL, machine-binding, grant, or identity files. It does not enroll by hostname. Any lost response, timeout, server error, or malformed successful response after a mutation is classified as ambiguous; the command does not retry or continue. An operator must follow the recovery procedure and preserve all locks/evidence.

The process pilot now starts the actual Owner CLI as a separate child process and feeds it synthetic confirmation data over stdin. This proves the client-to-Gateway API sequence with independent processes and real TLS, but the pilot's confirmation input is test-fixture data; it does not prove a human's out-of-band comparison procedure.

## Read-only VPS preflight (2026-10-18)

Observed as `itagil` on host `gui`, Node `v22.23.2`, systemd `255.4`:

- `/` and `/var/lib` share a 100,218 MiB filesystem. `df -Pm /var/lib` reported 2,623 MiB available (98% used).
- Memory available was 2.5 GiB. Swap was 3.8 GiB total with only 3 MiB free. CPU count and current utilization must be checked again immediately before activation.
- `127.0.0.1:18443` had no listener at inspection time. It is not reserved. G6's existing listeners remain separate; no G6 config or secret was inspected.
- The planned release `/opt/vps-commander/g7-staging`, Gateway/agent config directories under `/etc`, and separate Gateway/agent state roots under `/var/lib` were absent. Their parent directories are root-owned; no directories or permissions were changed.
- Units pin Node 22, loopback Gateway bind, distinct service accounts, `NoNewPrivileges=yes`, empty capabilities, `ProtectSystem=strict`, separated `StateDirectory`/`ConfigurationDirectory`, and explicit memory/CPU/task/file-descriptor limits. systemd 255 recognizes these directive families, but this run did not complete native unit parsing.
- Prior measurements found a complete development `node_modules` tree of about 756 MiB, a tracked source archive of about 59.3 MiB, and a built Desktop Commander `dist` of about 3.5 MiB. The production-only dependency artifact was not measured here. At the current 2,623 MiB free, preserving the existing 2 GiB activation floor leaves at most about 575 MiB for the entire copied runtime, production dependencies, and install overhead. Therefore disk headroom is not certified. Do not free space by deleting caches, logs, worktrees, or other VPS files; an authorized operator must first measure the immutable production artifact and provide enough additional headroom to retain at least 2 GiB free afterward.

### Native systemd verification blocker

The unprivileged native command was run against both versioned unit templates:

```sh
systemd-analyze verify deploy/g7-staging/systemd/vpsc-g7-staging-gateway.service deploy/g7-staging/systemd/vpsc-g7-staging-agent.service
```

It exits 1 with `Failed to setup working directory: Permission denied`. A prior read-only `strace` located the failing operation at `mkdir("/tmp/systemd-analyze-*", 0700) = -1 EACCES`; `/tmp` is root-private (`0700`) and this `systemd-analyze` build ignores `TMPDIR`. `/etc/systemd/system` is also not readable to the unprivileged account. No global permission was changed and no escalation was attempted. Thus native unit verification remains `BLOCKED_ENVIRONMENT`, not PASS.

After a separate Owner-authorized activation procedure installs the reviewed files, an authorized operator must run:

```sh
sudo systemd-analyze verify /etc/systemd/system/vpsc-g7-staging-gateway.service /etc/systemd/system/vpsc-g7-staging-agent.service
```

Do not install the units solely to make this check pass; systemd verification is still a required pre-activation gate.

## Activation decision

`ACTIVATION_READINESS=RED`. The persistent runtime now has a cryptographic machine-ingress boundary and a synthetic Owner bootstrap client, but systemd's native verifier did not reach unit parsing and the measured free-space margin is too small to certify the release artifact. The production-only dependency size is still unknown. Keep staging inactive until an authorized operator validates the exact immutable release and both native unit files, rechecks capacity/ports/process limits, and separately approves account, credential, installation, and startup actions.

Hosted GitHub Actions remain externally disabled. Local tests can certify this development change but do not certify a production release.
