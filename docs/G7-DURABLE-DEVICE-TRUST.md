# G7.2e — Durable VPS-side approved device identities (inert)

**Status:** standalone server-side store under review, not imported by `gateway/server.mjs` and not deployed. This branch is synchronized with current `main` at `249ac1af8d279bad623f657368e987d1c57fd467` (G7 inert HTTPS agent client merge); its HEAD is `d90ef909f8469c1adea0e88ff12db7f22ef7872d`. The merge added no changes to the trust-store implementation.

## Problem being solved

An authorized agent's Ed25519 signing key already survives restart locally (Linux file permissions, Windows DPAPI). The VPS registry previously lived only in RAM, so approved devices got new deviceIds or disappeared at every restart. This PR persists **only public trust records** with stable deviceIds and revisioned revocations.

## Delivered

- `gateway/devices/registry.mjs`: `initialTrustedDevices` for strictly validated owner-supplied trusted records and `snapshotTrustedDevices()`. The private session, challenges, heartbeat state and online status are **never persisted or restored**.
- `gateway/devices/durable-trust.mjs`: explicit local Linux/POSIX directory required, owner-only 0700 directory + 0600 records file, O_NOFOLLOW for reads, O_EXCL and fsync before rename for writes, fsync of containing directory for crash durability. Refuses symlinks including dangling ones, unsafe modes, malformed schema, duplicate identities, bad fingerprints, unsupported OS and exhausted revision counter.
- The wrapper exposes an internal registry façade without trust/revoke mutators; only separate owner-authorized server operations may request trust/revoke (not connected to any HTTP API). On mutation it builds a candidate registry, writes a revisioned **atomic file snapshot before acknowledging**, and then replaces the current in-memory trusted state.
- Every mutation invalidates old sessions for **all devices** in this initial fail-closed design. Agents must establish fresh signed sessions afterwards. This deliberately favors safe recovery over preserving connections.
- **Critical failure behavior:** if any persistence step fails, the wrapper permanently blocks further registry/session calls for that process. Do not continue routing with an uncertain persisted/revoked state; repair storage, restart, verify on-disk data and retry an unconfirmed operation.
- Revoked devices are absent from durable records after successful revocation and cannot reconnect following restart. Current design does **not** maintain a tombstone history for forensic/inventory purposes.
- No private signing keys or Cloudflare Access tokens are written to server storage. Records include public deviceId, name, platform, Ed25519 public key and fingerprint only.

## Explicit limitations / gates before actual deployment

1. Single-writer design assumption. Multi-process startup, concurrent writers, recovery under disk exhaustion, consistency fencing across gateway replicas, and robust crash fault-injection tests are **not yet certified**. Do not mount this store in multiple Gateway processes.
2. Durable owner-approved pairing requires real owner auth, approval revocation APIs, rate limits, audit, key rotation, storage migrations/backups and explicit denial if audit cannot record outcomes.
3. Device requests still need independently authenticated Cloudflare Access Service Auth on a **separate application/hostname** from the existing commander owner-only Access app, verified TLS, and application-level Ed25519 signed frames. This PR does not touch Cloudflare.
4. The agent package is still private 0.0.0-dev and its CLI does not connect or execute tools. The test HTTP loopback is inoperative unless explicitly started by tests.
5. Permission-sensitive server paths should be provisioned for dedicated `vpsc-gateway` service user with owner-only ACLs, not shared with `vpscommander`, root general home or a public webroot. No path provisioning performed in this PR.
6. Root/Admin indefinite option from earlier merge remains a **duration policy only**; no elevated process or remote shell. G6 production remains at old checkout, unchanged.
7. Disk in VPS gui observed at ~90% root utilization; keep bounded on-disk records and do not deploy additional daemons before capacity gate.

## Tests

The suite covers stable deviceId across same-process and **new OS process**, offline after restart, owner-only POSIX modes, symlink and dangling-symlink denial, corrupt metadata/fingerprint and duplicates, revocation durable across restart, all-session fencing on state mutation, write failure poisoning of active state, exact schema, revision overflow and public-keys-only records.

Tests run with ephemeral temporary directories only; they neither enroll Gui-PC nor mutate production. Current local verification on the synchronized branch: `node --test gateway/test/durable-trust.test.mjs` as an unprivileged user — **19 PASS, 0 FAIL**. GitHub checks on HEAD: `gateway-tests` and `Check for spelling errors` — **success**. This is source and test evidence only; the PR remains Draft and no G7 feature is wired into production.

**Next safe milestone:** build an authenticated owner-admin approval plane and separate agent machine ingress in a new PR, with full threat model, audit and staged pilot. Do not create a public endpoint just to make the local test server reachable.
