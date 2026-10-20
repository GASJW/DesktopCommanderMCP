# G7 I8A ChatGPT bridge (opt-in, not activated)

The staging Gateway mounts this route only when its private configuration has a
`chatgptBridge` object. With the object absent, `/chatgpt/mcp` and the protected
resource metadata route return 404. The example staging config deliberately
omits it. This feature branch has not been deployed to the active Gateway.

The bridge advertises only `read_file`. Every call must include an explicit
`deviceId` and absolute `path`; device trust, Owner binding, the current durable
grant, approved root and result authorization fence are enforced by the
existing G7 handler. The bridge cannot create identities, bindings, grants or
other Gateway state.

## User authentication and Owner mapping

The tunnel authenticates its transport to OpenAI. It does not identify the
ChatGPT user to G7. The bridge therefore accepts only an OAuth bearer access
token and verifies it locally as a signed RS256 JWT against configured public
JWKS keys. It checks issuer, resource audience, expiry, not-before, issue time,
client ID, `g7.read` scope and the exact configured subject. It ignores
`cf-access-jwt-assertion` supplied by a caller. The verified issuer/subject is
then mapped explicitly to the exact existing G7 Owner issuer/subject; all G7
device and grant checks still run using that Owner identity.

The optional `chatgptBridge` configuration has these fields:

- `issuer`: canonical HTTPS OAuth issuer.
- `resource`: canonical HTTPS MCP resource identifier; OAuth tokens must use it
  as their audience.
- `resourceMetadataUrl`: HTTPS URL visible through the selected tunnel and used
  in OAuth challenges.
- `clientIds`: exact OAuth client IDs permitted to call the bridge.
- `jwks`: public RSA keys only, each with `kid` and `alg: "RS256"`.
- `principalMapping`: exact OAuth `subject` plus `ownerIssuer` and
  `ownerSubject`; both Owner fields must match the current Gateway Owner.

This resource server does not create or operate an authorization server. The
existing IdP must publish OAuth/OIDC discovery and JWKS, support OAuth 2.1
authorization code with PKCE S256 and a ChatGPT-compatible client registration
method (CIMD, DCR or a predefined client), preserve the requested `resource` in
its access token, and issue a JWT with the configured client ID and scope. The
authorization server must be reachable to ChatGPT independently; the Secure
MCP Tunnel does not tunnel the authorization server. If any of these checks
cannot be met, calls fail closed.

The staging Gateway's Owner is a synthetic test identity. It must never be
used as production authentication. A future live integration must map the
external IdP subject to the real, already-bound G7 Owner and deploy only after
separate approval. The pinned JWKS keys in runtime configuration are public;
their rotation must be coordinated with the IdP before new signing keys are
used.

## Secure MCP Tunnel prerequisites

OpenAI's tunnel keeps the MCP server private. An operator must create/select a
Platform tunnel and a restricted runtime key, run the supported `tunnel-client`
in the same network boundary as the loopback Gateway, and configure its HTTP
target to the private HTTPS `/chatgpt/mcp` URL. Preserve TLS hostname and CA
verification. The tunnel client needs outbound HTTPS to `api.openai.com:443`
and local reachability to the Gateway; it requires no public G7 listener.
Configure the ChatGPT custom MCP server with **Connection: Tunnel**, the same
tunnel, and OAuth authentication. The Platform tunnel permission and ChatGPT
workspace connection permission are separate. Keep the runtime key outside
this repository and outside the Gateway JSON config.

Creating or editing a Platform tunnel requires **Tunnels Read + Manage**.
Running `tunnel-client` and selecting the tunnel in ChatGPT requires **Tunnels
Read + Use** plus the appropriate ChatGPT workspace permission. Use the
supported client and verify its profile with
`tunnel-client doctor --profile <profile> --explain`; confirm the client is
ready and actively polling before testing discovery. The service currently
limits each serialized tunnel request or response to 10 MiB and gives the
complete queued request 120 seconds from queue entry through final response.
The tunnel host needs outbound HTTPS only; do not open inbound Gateway ports.
The existing `omb-tunnel-client.service` was observed active for OpenMausBot,
but it has not been verified as an OpenAI tunnel and was left untouched.

The bridge supports stateless Streamable HTTP JSON-RPC, protocol versions
`2025-03-26`, `2025-06-18` and `2025-11-25`, and the standard protected-resource
metadata route. POST requires both JSON and event-stream media types in
`Accept`; the endpoint returns JSON and rejects GET with 405 because it has no
server-initiated event stream. Unsupported `MCP-Protocol-Version` values fail
with 400; absent headers retain the protocol's 2025-03-26 compatibility rule.
`read_file` declares OAuth `g7.read` and read-only annotations.
Unauthenticated discovery exposes only that schema; unauthenticated or invalid
`tools/call` requests receive the OAuth challenge metadata and never reach the
device router. The generated request ID is stable for a retry with the same
Owner, JSON-RPC ID, device, tool and arguments, so reconnects and OAuth token
refreshes cannot turn the same MCP call into a new device operation. Since the
bridge is stateless, the same Owner and JSON-RPC ID/payload are treated as one
call across sessions; callers should use a new JSON-RPC ID for a distinct
read. The existing durable device ledger remains the final at-most-once
execution fence.

## Local synthetic certification

`gateway/test/chatgpt-read-only-bridge.test.mjs` creates short-lived test keys,
a loopback-only HTTP server and mock G7 policy dependencies. It does not use
the VPS, real Owner credentials, Cloudflare, an OpenAI tunnel, or ChatGPT
plugin configuration. Removing this test config returns the feature to 404.
