# G7.2c — Outbound signed HTTP loopback pilot (inert, not public)

**Status:** prototype tested on the Linux VPS `gui`, but no agent is connected to the real Commander Gateway in production. This PR is stacked on G7.2b PR #18 (then #17, then #15). It adds NO routes to the deployed `gateway/server.mjs`.

## Architecture and implemented protocol

Target: ChatGPT/Cloudflare Access owner-only -> VPS Commander Gateway -> explicit deviceId -> authenticated outbound agent using our own infrastructure -> Desktop Commander running locally as a non-privileged user.

In this isolated pilot, an agent starts requests to an **ephemeral local HTTP listener bound only to `127.0.0.1`**. There are no inbound host ports, no Cloudflare changes, no public DNS, and no remote command execution. The agent is synthetic, not yet the installable npx agent that can control a real computer.

- Device pairing still requires an Ed25519 proof **and separate owner approval**, and never enrolls automatically.
- `/agent/challenge` issues a short-lived device-bound challenge for a previously trusted identity. `/agent/connect` verifies its signature and issues a fresh session ID.
- The client uses Ed25519 to sign **every** subsequent request, binding method, exact path, deviceId, sessionId, strictly increasing sequence, and SHA-256 of the **raw request body** into one canonical message. The server checks the signature using the approved public key and atomically advances the sequence/heartbeat. Session IDs alone cannot authenticate.
- `/agent/heartbeat` establishes observed liveness and attaches the router to the exact authenticated device session; `/agent/poll` obtains a queued tool-request frame; `/agent/result` verifies authenticated responses bound to requestId/deviceId/sessionId and never replays a mutating call automatically.
- Outbound polling is intentionally short-lived in this pilot; remote transport and WebSocket economics/idle timeout decisions are not yet accepted.
- A real loopback HTTP test uses a synthetic mock response; this does NOT prove local Desktop Commander child execution.
- Reject browser Origin, unsupported method/routes, invalid media, malformed/oversized bodies, missing signatures, tampering, duplicate/reordered sequences, wrong keys, revoked/stale sessions and offline devices. The pilot bounds raw bytes before decoding, uses strict UTF-8 decoding, and verifies signed request contents independently of network chunk boundaries; malformed UTF-8 is rejected.
- All pilot entry points require explicit `enableLoopbackPilot:true`, bind to `127.0.0.1`, and demand port 0 (OS-assigned ephemeral). Client refuses non-loopback URL, TLS hostnames, and embedded credentials in its test helper.

## Files

- `gateway/devices/registry.mjs`: internal cryptographically verified signed-frame/sequence method.
- `gateway/devices/loopback-pilot.mjs`: standalone test-only listener, NOT imported by active gateway.
- `packages/vpsc-agent/src/frame.mjs`: shared canonical request signer (also imported by the pilot server).
- `packages/vpsc-agent/src/pairing.mjs`: agent-side device-handshake and signed frame primitives, private key still ephemeral in memory.
- `packages/vpsc-agent/src/loopback-client.mjs`: loopback-only HTTP test client with explicit deviceId and no real tool execution.
- `gateway/test/device-loopback-pilot.test.mjs`: real HTTP loopback protocol/adversarial tests.
- Two existing tests updated for new internal method shape. The agent package is still **private**, `0.0.0-dev`, and not published.

## SECURITY GATES BEFORE ANY G7.2d PUBLIC CONNECTION

1. **Dedicated agent ingress:** review separately-scoped Cloudflare Access Service Auth using distinct per-device service tokens (or an equivalent independently audited M2M mechanism), explicit default-deny, and a **different hostname/application** from current owner-only `/mcp` and `/dashboard`. Authenticate and rate-limit at edge and origin; Ed25519 is defense-in-depth, not a substitute for edge authentication, TLS or owner consent. Cloudflare documents M2M [service tokens](https://developers.cloudflare.com/cloudflare-one/access-controls/service-credentials/service-tokens/), and [proxied WebSockets](https://developers.cloudflare.com/network/websockets/). **Neither DNS nor Access policies have been changed.**
2. **Durable identities:** protect private keys with Windows owner-only ACLs / native OS facilities and Linux `0600` and narrow owner account permissions; persist device registry, pairing approvals/revocations and anti-replay state across crash/restart, with key rotation and recovery. Ephemeral keys in the current prototype are NOT a production identity solution.
3. **No trust of raw headers:** only call `acceptSignedFrame`, router `attachTransport` and `acceptResponse` from a verified ingress. The owner approval handler must independently verify signed Cloudflare owner JWT and explicit device/fingerprint; never expose internal methods on the public agent ingress. The owner session must never be given to an agent.
4. **Actual remote agent:** pinned npm version/provenance, install as a normal user on Windows and Linux with explicit owner consent. Authenticate to our Gateway over validated TLS. Run local Desktop Commander child under least privilege, with per-tool policy and observable child readiness, and test real read-only execution on each target.
5. **Ambiguous writes:** timeout/disconnect/queue ambiguity yields no automatic replay, and revocation/fencing prevents late responses. Document what to do with operations whose dispatch outcome is uncertain.
6. **Root/Admin is separate:** ordinary npx agent NEVER runs as root. G7.3 grants with 10m/30m/60m/Indefinida até revogação manual need a separate privileged helper, explicit authorizations and durable audit, not an arbitrary shell under a dashboard toggle.
7. Capacity gate: root filesystem on VPS `gui` was **90% used** during this development. No extra services/npm publication until disk headroom and rollback tests are accepted.

## Admission

This is a **functional loopback simulation**, not a green light for a public transport. Code remains isolated, no unit/systemd restart, no merge or deploy, no credentials generated except test identities kept in memory. The full suite must pass plus protected GitHub CI. Preserve G6 production and G5.2/PR #10.
