# G7.2a — Explicit device routing and no-replay transport contracts (inert)

## Objective

Build the next layer of our own multi-device Commander: ChatGPT -> existing owner-only Gateway -> explicitly selected deviceId -> outbound authenticated agent -> local Desktop Commander. **No dependency on the original RDC backend, its identity service or Supabase.**

This PR adds only transport-independent routing primitives and tests. The actual network transport, installable npx agent, approval UX and production wiring are not yet implemented.

## Contents

- gateway/devices/registry.mjs: adds internal isLiveSession(deviceId, sessionId), explicitly bound to a previously trusted Ed25519 public key + verified one-time signature + fresh signed-in session + valid heartbeat.
- gateway/devices/router.mjs: an **in-memory, unexposed** router. No HTTP endpoints or listener. It requires a concrete deviceId; does not default to VPS gui.
- gateway/test/device-router.test.mjs: authenticated route to selected identity, untrusted/unavailable device rejection, wrong session/response rejection, timeout, refusal to replay, detach, concurrency, oversize input/output, revocation, reconnection fencing.
- gateway/test/device-registry.test.mjs: updated API shape test to account for new internal isLiveSession method.

## Internal protocol

The prospective Gateway transport should pass only authenticated sessions to attachTransport. Following an authenticated device selection and per-tool policy check, callDevice dispatches a bounded JSON frame with version=1, deviceId, sessionId, requestId, method=tools/call and params{name,arguments}. A verified response must match all three IDs. Duplicate or stale responses are ignored. Timeout, send failure, session swap, device revocation and disconnect never trigger an automatic tool replay. Errors distinguish OFFLINE, BUSY and AMBIGUOUS_* to support human review before reissuing mutating commands.

Note: An accepted heartbeat is only session liveness, not proof of local MCP executor readiness. Device-level health checks are still required.

## Security boundaries not yet implemented

- The router is deliberately not wired into gateway/server.mjs and does not implement Cloudflare owner authorization, session/pairing durability, role policies, privilege elevation or transport authentication. Its attachTransport and acceptResponse methods **must remain internal** and only be invoked by a separately authenticated/verified agent protocol. Do not expose them as arbitrary remote APIs.
- G7.1 registry is still in-memory and not durable. Handshake cryptographic identity does not by itself attest a machine; secure approval and local private-key storage are deferred.
- No package, npm publishing, new systemd service, public route, DNS/Cloudflare Access modification, or root access is added.
- Cross-platform execution and per-host consent require Windows/Linux pilot on trusted devices before any route is enabled.
- Before real execution, implement outgoing agent connection (mTLS or appropriately authenticated TLS with device cryptographic challenge), server-side owner pairing/approval, rate-limiting, per-device RBAC, bounded remote queues, durable revoke/rotation, audit and structured protocol errors.
- The future agent can be started via a **pinned-version npx distribution published only after build/signature review**. npx is a local bootstrap; it must not itself run as root.
- The Root/Admin duration contract lives independently in PR #16 and remains inactive until the G7.3 privileged-helper design and acceptance.

## Existing production guarantees

G6 remains live on /opt/vps-commander/code, exact main merge e599678f. All current /mcp requests still execute only through the existing vpscommander local Unix socket. Do not merge/deploy G7.2a as an active feature just because unit tests pass. G7.1 PR #15 must be reviewed/integrated before G7.2a (stacked branch).

## Acceptance

- Existing 54 baseline tests plus 18 registry and 12 router tests = 84.
- GitHub required checks on the candidate branch success.
- Only then separately decide how to authenticate outbound agent transport and how to install a pilot without disrupting G6.
