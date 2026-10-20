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
separate approval. The bridge uses only the public JWKS keys pinned in its
configuration; it does not fetch or refresh JWKS. Rotate by deploying the new
public key alongside the current key before the IdP starts signing with it,
then retain the old key until its last token is past the one-hour token limit
plus the 30-second clock tolerance. Unknown `kid` values fail closed.

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
ready and actively polling before testing discovery. The tunnel host needs
outbound HTTPS to `api.openai.com:443` and local reachability to the Gateway;
it needs no inbound Gateway port. Preserve TLS verification: the configured
target hostname must match the certificate SAN, and the tunnel host must trust
the staging CA. OpenAI documents custom CA bundles for tunnel-client. OAuth
discovery for the MCP resource can pass through the tunnel, but the OAuth
authorization server itself must be reachable independently. The documented
request envelope limit is 10 MiB and deadline 120 seconds.

### Read-only readiness evidence (2026-10-20)

- Platform UI showed the personal organization and an existing tunnel named
  `OpenMausBot Owner MCP`, associated with one workspace. The signed-in user
  appeared as organization owner, but the UI did not expose a separate
  `Tunnels Read + Use` grant and the ChatGPT plugin-to-tunnel association was
  not confirmed.
- The VPS `omb-tunnel-client.service` was active, but its binary/profile was
  not verified as OpenAI's supported client. `tunnel-client` was not on the
  Gui-PC PATH. No client was installed or changed. The official release page
  showed v0.0.16 as latest at inspection time.
- A read-only TLS handshake to Gateway loopback `127.0.0.1:18443` returned a
  certificate with subject/issuer `CN=g7-staging.test` and SANs
  `DNS:g7-staging.test` and `IP:127.0.0.1`. A future tunnel profile must use a
  matching SAN and explicitly trust the staging certificate/CA; the current
  CA bundle path/profile was not inspected or changed.
- ChatGPT showed an existing legacy `Commander` app with broad “Allow all”
  permissions. It is not the I8A read-only app; no I8A plugin was configured.
- OpenAI's current help article lists full custom MCP support for
  Business/Enterprise/Edu and read/fetch access for Pro; Plus is not listed.
  Because the signed-in account is Plus, plugin eligibility remains unverified
  and requires a supported account/workspace before integration.
- The only configured IdP located in the project/live metadata was Cloudflare
  Access Managed OAuth at `https://plain-block-9a74.cloudflareaccess.com`.
  Read-only discovery advertised authorization code, refresh-token grant,
  PKCE S256, public-client authentication (`none`) and DCR. It did not
  advertise `scopes_supported`; the published OIDC JWKS endpoint returned two
  RS256 keys with a four-hour cache lifetime. No token was requested and no
  client was registered.
- Cloudflare Managed OAuth issues opaque access tokens. For Cloudflare MCP
  applications, Cloudflare expects the origin to validate its signed
  `Cf-Access-Jwt-Assertion`; the loopback Secure MCP Tunnel path currently
  bypasses that Access edge, while I8A validates a locally verifiable JWT.
  The assertion must never be trusted merely because a caller supplied its
  header. Consequently, this IdP is not directly compatible with the current
  loopback bridge, and an audience containing the I8A resource plus `g7.read`
  was not demonstrated.
- The current G7 Owner is synthetic staging identity. Its production mapping
  is therefore unavailable. The exact stable `iss` + `sub` of a real G7 Owner
  must be verified independently and explicitly mapped; email alone is not a
  sufficient mapping key.

The minimal safe path for a loopback-only tunnel is an authorized human-user
OAuth/OIDC issuer that returns a signed JWT validated by the bridge, supports
authorization code + PKCE S256, DCR/CIMD or an approved public client,
`g7.read`, the exact MCP resource as `aud`, public JWKS with a documented
overlap/rotation process, and refresh tokens (`offline_access` where required
by ChatGPT). Bind its verified stable subject to the real existing G7 Owner.
No such compatible issuer or mapping was verified here. An alternative
Cloudflare route would require the MCP origin to be reached through the
existing Access edge and to cryptographically validate the edge assertion;
that route is not part of this inert bridge and would need separate design and
approval.

Official references checked for this snapshot:

- [Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)
- [ChatGPT custom MCP connections](https://help.openai.com/en/articles/12584461-connecting-custom-mcp-servers-in-chatgpt)
- [ChatGPT OAuth requirements](https://developers.openai.com/plugins/build/auth)
- [ChatGPT MCP request metadata](https://developers.openai.com/plugins/reference)
- [tunnel-client releases](https://github.com/openai/tunnel-client/releases)
- [Cloudflare Access Managed OAuth](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/managed-oauth/)

The bridge supports stateless Streamable HTTP JSON-RPC, protocol versions
`2025-03-26`, `2025-06-18` and `2025-11-25`, and the standard protected-resource
metadata route. POST requires both JSON and event-stream media types in
`Accept`; the endpoint returns JSON and rejects GET with 405 because it has no
server-initiated event stream. Unsupported `MCP-Protocol-Version` values fail
with 400; absent headers retain the protocol's 2025-03-26 compatibility rule.
`read_file` declares OAuth `g7.read` and read-only annotations.
Unauthenticated discovery exposes only that schema; unauthenticated or invalid
`tools/call` requests receive the OAuth challenge metadata and never reach the
device router. The generated request ID hashes the verified Owner, ChatGPT's
anonymized `openai/session`, JSON-RPC ID, device, tool and arguments. The
session field is correlation only, never authentication. Token refresh and
transport retries keep the ID stable; a different conversation or different
arguments produce a new ID. Exact reuse of the same session, JSON-RPC ID and
payload cannot distinguish a retry from a new identical read. Such a caller
must use a fresh JSON-RPC ID for each new invocation; duplicates remain
fail-closed at the existing durable device ledger and are never replayed.

## Local synthetic certification

`gateway/test/chatgpt-read-only-bridge.test.mjs` creates short-lived test keys,
a loopback-only HTTP server and mock G7 policy dependencies. It does not use
the VPS, real Owner credentials, Cloudflare, an OpenAI tunnel, or ChatGPT
plugin configuration. Removing this test config returns the feature to 404.
