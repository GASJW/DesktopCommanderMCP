# G7.1 — Device Registry Foundation (inert candidate)

> Histórico: este documento descreve os gates anteriores ao baseline I5F. O follow-on I7 implementa parte do escopo descrito abaixo em um release candidate separado; ainda não está implantado no Gateway ativo.

**Goal:** Prepare our own-Gateway device identity and observation model to replace RDC routing in future stages. This PR does **not** provide multi-device execution, enrollment endpoints, an npx agent, root access, or production rollout.

## Owner-approved target

ChatGPT → Cloudflare Access owner-only → VPS Commander Gateway → authenticated device transport → selected Windows/Linux agent → locally running Desktop Commander.

- Agents connect outbound to OUR gateway, never to the original RDC service, its device authorization or Supabase Realtime.
- Device identity is not a recent MCP client identity, and is not a discovered computer.
- Explicit owner-controlled pairing, device selection, revocation, and future per-device permissions.
- npx is an agent startup mechanism, not by itself an authentication or transport protocol.
- The existing local Unix-socket executor remains the only production execution path until future gates pass.

## G7.1 scope

- gateway/devices/registry.mjs: inert, in-process registry (not imported by production Gateway).
- gateway/test/device-registry.test.mjs: isolated cryptographic, validation and replay tests.
- Trust a single Ed25519 public identity per device; metadata validation, UUIDv4 deviceId and duplicate rejection.
- Signed device-bound, time-limited, one-use challenge; consume on invalid signatures and expired responses.
- Fresh sessions and monotonically increasing heartbeat sequence for observed online state.
- Fail-closed on expired lease, invalid session ID, replay or revoked device.
- List metadata (deviceId, name, platform, online, lastSeenAt) without keys, tokens or pretending any other host is connected.
- Zero new public routes, network listeners, persistence, privilege changes or service restarts.
- In-memory only: all registrations vanish when process exits; no claim of durable enrollment.

## G7.2 — deferred secure transport

- Separate agent ingress and authorization compatible with Cloudflare architecture; never expose /mcp or /dashboard to unverified devices, nor hand out owner OAuth tokens to agents.
- Persist trusted keys with bounded storage and backup; secure owner approval/revocation; throttled pairing, fencing and reconnection, key rotation.
- Packaged, reviewed, pinned-version npx agent on authorized Windows/Linux hosts, making outbound authenticated connections only.
- Explicit deviceId in tool routing; reject unknown/offline/unapproved devices; bounded remote call transport, queue and no blind replay.
- Verified local executor status as a separate signal from heartbeat. Real two-host tests only after mock E2E and review.

## G7.3 — deferred privileged execution

Keep standard agents non-root and non-administrator. Build an independent, auditable root/admin capability with explicit per-operation owner authorization, narrow allowlisted tasks, expiration and rollback tests. Never grant blanket sudo or silently run arbitrary remote npx scripts as root.

## Admission gates / limitations

- G7.1 is eligible for protected PR and test validation only; do not deploy as an active feature.
- G7.2 needs protocol threat model, independent agent ingress verification, real endpoint security and user-approved pilot.
- G7.3 requires separate privileged-operation threat model/approval.
- A signature proves possession of a private key, not physical-machine attestation or consent. Heartbeat measures a session, not child-process health.
- Preserve G6 production and PR #10 G5.2. Do not touch Cloudflare DNS/policies, cofre, Pantheon, Hermes or OpenMausBot.

## I7 follow-on

The I7 candidate adds a native Windows worker, DPAPI/NTFS identity and ledger storage, additive per-device M2M configuration and explicit `deviceId` routing. See [G7 I7 Windows and multi-device RC](G7-I7-WINDOWS-MULTIDEVICE-RC.md) for its behavior, test boundary, pilot connection, and rollback. Those capabilities remain inactive on the live Gateway until a separately approved rollout.
