# G7.2b — Owner-approved device pairing + local npx package scaffold

Status: **inert candidate, not a connected remote agent**. Stacked on G7.2a PR #17, which is stacked on G7.1 PR #15.

## Owner objective

Use our own VPS Commander Gateway as the exclusive control plane. Windows/Linux agents will eventually connect **outbound** to it, with explicit deviceId, owner-approved pairing, authenticated transport, local Desktop Commander execution and separate Root/Admin permissions. No dependency on the original RDC hosted service or Supabase.

## Delivered in this PR

- gateway/devices/pairing.mjs: in-memory pairing coordinator. A candidate requests a short-lived nonce and public fingerprint; its Ed25519 private-key signature proves possession. **Possession alone cannot enroll the device**. A distinct privileged, owner-authenticated approval must match the exact fingerprint before calling registry.trustDevice.
- Untrusted pairing expires, can be denied, is bounded by maxPending, rejects duplicate pending keys, consumes invalid proofs, and does not show a new device online until a separately authenticated session heartbeat.
- Owner queue contains only public name/platform, fingerprint, display comparison code, requestId, proof status and createdAt. The code is *not* an authenticator.
- packages/vpsc-agent: dependency-free Node.js package-shaped scaffold with bin vpsc-agent, doctor and help. Runtime requires Node 20+. Pairing proof helper generates an **ephemeral Ed25519 identity in memory**, signs the exact coordinator challenge; private key is not returned or persisted.
- The CLI deliberately **rejects** connect, pair, root, and unsupported commands. It neither executes remote commands nor opens network connections. This is not yet published to npm: package version is 0.0.0-dev and private=true.
- Unit and synthetic end-to-end checks cover pairing lifecycle, wrong signatures, replay, TTL, wrong fingerprint, capacity, offline state, agent signer compatibility and forbidden CLI commands.

## Required G7.2c gates BEFORE production

1. Durable owner-approved pairing store, migration, revocation, rate limiting, tombstones and replay mitigation across restarts. No cleartext private keys in GitHub, Notion, logs, browser, or server.
2. Dedicated authenticated outbound transport from device to Gateway with verified TLS and agent identity, segregated from current Cloudflare Access owner JWT; threat-model Cloudflare Tunnel/Access ingress BEFORE adding any route. Do not weaken /mcp or /dashboard.
3. Agent durable identity storage with Windows owner-only ACL and Linux/macOS restrictive filesystem permissions; trusted pairing UI requires owner confirmation against the displayed fingerprint and physical/local code. Session fencing and key rotation must be proved.
4. Client dispatcher with bounded payloads, explicit deviceId, read/write tool authorization, no retry on ambiguous outcome, signal local executor health separately from session presence.
5. npm package published only after code/provenance/signature review, version pinned (never use @latest in unattended installations). Run and certify on Gui-PC Windows and VPS Linux nonroot, user-approved enrollment.
6. Keep ordinary agents unprivileged. G7.3 per-device Root/Admin grant, including **Indefinida até revogação manual**, remains independently reviewed; never execute arbitrary npx scripts as root.

## Safety

No updates to gateway/server.mjs, active /mcp routes, systemd, DNS, Cloudflare, cofre, Pantheon, Hermes, OpenMausBot or PR #10 G5.2. No service restart/production deploy. Tests are local/synthetic only, never evidence that Gui-PC is paired or executes tools.

Follow-up: finish transport design and implementation on a **new branch** after reviewing this PR. Integrate stacked #15 then #17 then this PR only after gates; do not treat tests as authorizing production activation.
