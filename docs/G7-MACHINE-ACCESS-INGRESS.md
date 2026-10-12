# G7.2g — Dedicated machine Access JWT and double-authenticated agent ingress (inert)

## Purpose

Implement the internal security contract for a **separate** Cloudflare Access Service Auth application used by Windows/Linux Commander agents. DO NOT reuse the existing owner-email authentication application protecting `commander.supercerebro.me/dashboard` and `/mcp`. No Cloudflare DNS, tunnel, application, policy, service token or secret is created by this PR.

## Cloudflare documentation and identity distinction

Per Cloudflare's [application token documentation](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/application-token/), a service-token application JWT has `type=app`, `sub=""` and `common_name` containing the **service token Client ID**. This differs materially from an interactive owner JWT, which is subject/email based. See [Service tokens](https://developers.cloudflare.com/cloudflare-one/access-controls/service-credentials/service-tokens/) and [Access policies](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/).

## Source

- `gateway/devices/machine-access.mjs` independently verifies the `Cf-Access-Jwt-Assertion` JWT: issuer and 64-hex app audience, application token type, empty machine `sub`, exact allowlisted `common_name` Client ID, RS256 signature against Access JWKS, expiry, issued-at, not-before, maximum token age, key ID, limits, refresh and fail-closed JWKS retrieval. It **does not authorize a human session or a different device**.
- `gateway/devices/machine-ingress-loopback.mjs` is a **standalone test-only** machine-auth HTTP ingress, requiring explicit enable, `127.0.0.1`, ephemeral port; it has no remote/public listener. It binds verified machine Client ID to a fixed server-provided `deviceId` and proxies only five agent methods to the existing internally-loopback Ed25519 pilot.
- Every challenge/connect is checked against the bound deviceId; subsequent requests require that same deviceId **plus independently validated Ed25519 session-bound signatures**. A valid M2M JWT alone is never sufficient to execute a tool.
- The outer ingress drops machine assertion/owner cookies/service secrets, forwarding only the original JSON request bytes and selected signed agent headers. Browser Origin, unsupported endpoints, invalid media, missing/invalid JWT and device impersonation are rejected. Response/request sizes and proxy deadline are bounded.
- `gateway/test/device-machine-access.test.mjs` signs synthetic JWTs using ephemeral RSA test keys to test issuer/audience/signature/clientId/expiry/key refresh/human-vs-machine denial.
- `gateway/test/device-machine-ingress.test.mjs` exercises actual HTTP loopback with a fake Access-signed service JWT and the real G7 signed agent and local read-only MCP fixture (not a fake router result). Test-only key material is generated in memory.

## Security caveats / what is still NOT implemented

1. There is **no actual Cloudflare Service Auth application or service token**. Before live service, create a **new dedicated hostname/application**, explicit Service Auth policy with specific tokens only (not "Any Access Service Token"), and protected tunnel origin. Validate that Cloudflare Access supplies a signed machine application JWT to the origin; never rely on the unauthenticated request headers alone.
2. The server must keep the existing owner-only application unchanged. It needs owner-authenticated pairing approval, server-side durable trust/revocation (PR #21), key rotation, distributed single-writer correctness, rate limits, audit and recovery before live onboarding.
3. Machine Client IDs must bind one-to-one to authorized `deviceId` records via an owner-controlled store. An agent must never choose the ID simply by modifying headers or `common_name`.
4. The current HTTP pilot is **unencrypted** because it runs solely in loopback and is not publishable. The eventual agent will reach Cloudflare over validated **HTTPS**, with individually protected credentials and a pinned agent package. No direct public HTTP or privileged/root listener is permitted.
5. The local MCP adapter added in PR #22 has a remaining filesystem TOCTOU risk absent OS-level containment. Do not expose arbitrary directory reads, start_process, write_file, or root/admin tools to live agent traffic yet. The server should be configured to serve only a tightly allowlisted scope on a normal OS user.
6. Session failure/timeout is ambiguous; do not auto-replay operations. Revocation must fence in-flight operations and persist reliably.
7. Dashboard selection and Root/Admin 10m, 30m, 1h or Indefinida até revogação manual are separate future integrations, not unlocked by this module.
8. A real Windows-to-VPS command was **not** performed by these tests. The VPS loopback authenticated proxy and an agent co-located on the VPS used synthetic Access JWTs. This PR does not depend on remote RDC for the request flow, but the RDC is still the administrative development channel.

## Admission

- Pass local Node tests and required protected GitHub CI.
- Keep `gateway/server.mjs` untouched; never add the loopback listener to production.
- Keep the existing G6 production checkout, Cloudflare Access Owner Only, tunnel, executor and recovery path unchanged; root partition remained ~90% used during this work.
- A separate production ingress rollout must have explicit preflight and rollback, secure service-token delivery, access policy audit and dual-host pilot before declaring G7 remote operation.
