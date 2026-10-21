# G7 I8I isolated dual-worker design

## Decision

Use two independent worker processes on each host: retain the current I7
process and start a separate I8 process with a newly generated Ed25519
identity, device ID, M2M Client-ID and secret, identity directory, execution
ledger and approved read root. Never copy I7 identity material or durable
state. A governed single-worker cutover is unnecessary for the offline pilot
and would create avoidable I7 disruption.

Linux and Windows I8 workers join the same isolated I8 realm. That realm has
its own loopback Gateway port, TLS CA/certificate, policy key and durable
stores, separate from I7. Each I8 device gets its own binding, grant and M2M
credential. The workers use the existing agent implementation and receive
different private `agent.json` files. Windows identity envelopes remain
DPAPI current-user protected; the worker must run unelevated as the same user.

The offline composition is `createIsolatedG7Realm` with its activation
callback invoking `startIsolatedG7AgentGateway` from
`gateway/owner/isolated-agent-gateway.mjs`. The callback must supply the
realm-local trust, binding, grant and Owner stores. The Gateway rejects
non-loopback listener configuration, mismatched TLS hostname/key, reused
protected policy-key fingerprints, and client credential collisions. It
accepts Owner access tokens only through the verified Auth0 bearer path and
advertises only `read_file`.

## Offline certification coverage

`gateway/test/isolated-realm-provisioning.test.mjs` composes a disposable
Auth0 Owner authority, signed administrative approvals, fresh device proofs,
durable bindings and `read_file` grants. It starts two separate Linux worker
processes with distinct identities and ledgers, verifies TLS hostname
validation and device routing, and checks path/tool denial. A separate
disposable I7 pilot runs concurrently; the I8 workers stay usable through its
Gateway restart and one I8 worker's forced process failure/recovery. The test
also fences a completed result after grant revocation and checks device and
Owner revocation without replay. `packages/vpsc-agent/test/windows-security.test.mjs`
checks separate Windows DPAPI identities, bindings and clean ledgers.

## Native Windows-to-Linux network certification

`gateway/test/isolated-realm-provisioning.test.mjs` includes an opt-in native
Windows worker test. Run it from a nonroot WSL2 ext4 checkout with Windows
interop enabled and the same commit present in the Windows checkout:

```sh
VPSC_I8I_WINDOWS_TO_LINUX_E2E=1 \
VPSC_WINDOWS_REPO_ROOT='C:\\path\\to\\DesktopCommanderMCP' \
node --test --test-name-pattern='native Windows I8 worker' \
  gateway/test/isolated-realm-provisioning.test.mjs
```

The disposable Linux Gateway binds only to the realm's configured
`127.0.0.1:<port>`. A temporary WSL-side relay binds to the private `eth0`
address, accepts only the Windows host's WSL route address, and forwards to
that fixed loopback Gateway port. Each TCP stream starts with a fresh random
challenge and an HMAC proof using a test-only key passed over the parent/child
pipe. The native Windows controller exposes its relay only on
`127.0.0.1`; the worker continues to use the pinned TLS hostname and CA. TLS
terminates only at the Gateway, where the existing machine credential and
signed Ed25519 frames are verified. The relay never accepts a caller-selected
upstream host or port.

The test performs synthetic Owner approval, Windows DPAPI identity creation,
pairing, binding and `read_file` grant issuance; READY/ONLINE and a content-hash
checked read; hostname, CA, machine-credential, path and tool denials;
cancellation, result-delivery fencing, worker restart, transport loss/recovery,
grant/device revocation and ledger no-replay checks. It also runs the existing
disposable I7 pilot concurrently. Both the Windows worker and temporary relay
are stopped and their disposable state is removed by test teardown. No host
file, proxy, firewall, SSH, production credential, public listener or live G7
configuration is changed.

The test is opt-in because it requires native Windows Node, WSL2 private
network reachability and a nonroot Linux Gateway runtime. A Linux-only mock or
loopback-only fixture is not a substitute for this network certification.

## Future live rollout — separate approval required

1. Obtain a distinct Owner authorization for live I8 provisioning and rollout.
   Confirm the real Auth0 subject, issuer, resource, `g7.read` scope and the
   independent administrative approval authority. Do not map the staging
   Owner to Auth0.
2. Read-only preflight I7 process IDs, current configuration, trust/binding/
   grant revisions, audit health and ledger recovery state. Preserve a
   versioned rollback snapshot. Stop if any I7 state is ambiguous.
3. Install a versioned I8 release and private realm directories alongside
   I7. Generate new I8 TLS, policy and machine-signing keys. Keep I7 keys,
   certificates, credentials and stores unchanged.
4. Start only the I8 Gateway manually on its dedicated loopback port. Keep
   public ingress, tunnel startup and boot autostart disabled unless separately
   approved. Verify the TLS hostname and CA from each worker host.
5. Through the supported realm provisioning API, bootstrap the verified Owner,
   pair each device with fresh Ed25519 possession proof, record an independent
   signed administrative approval, create the exact M2M binding, then issue
   only an approved-root `read_file` grant. Never copy I7 bindings or grants.
6. Start each I8 worker manually and unelevated with its own `agent.json`,
   identity directory and ledger directory. Verify READY, ONLINE, heartbeat,
   TLS, a bounded approved read, denied out-of-root access, denied tool
   escalation, audit and clean per-device ledger recovery. Recheck I7 health
   and revisions without dispatching test requests to I7.
7. Keep services manual until a separate startup-policy approval. Record
   release hashes, configuration hashes with secrets excluded, revisions and
   process identities in the rollout evidence.

## Rollback

Stop only the verified I8 worker processes and the dedicated I8 Gateway, in
that order. Keep the I8 identity, binding, grant, audit and execution stores
intact for investigation. Do not restore an old I8 snapshot over newer durable
state, reuse a revoked credential, replay an ambiguous request, or change I7.
If the I8 ledger or Gateway result is ambiguous, leave I8 stopped and reconcile
through the documented recovery APIs before any restart. Re-enable I8 only
under a new explicit rollout approval.

## Open evidence

Historical `STALE_LOCK` and `ECONNRESET` incidents remain open with unknown
root causes. The offline certification does not reclassify or resolve either
incident. Neither incident is evidence that live I8 rollout is safe.
