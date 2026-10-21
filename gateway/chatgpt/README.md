# G7 I8A ChatGPT bridge (opt-in, not activated)

The integrated I8J isolated-realm endpoint is documented in
[`docs/G7-I8J-CHATGPT-MCP-INTEGRATION.md`](../../docs/G7-I8J-CHATGPT-MCP-INTEGRATION.md).
It mounts `POST /chatgpt/mcp` inside the isolated Gateway and does not expose
the legacy `/mcp` route as a ChatGPT alias. The historical `chatgptBridge`
configuration below describes the earlier standalone bridge contract only.

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

For a resource at `/chatgpt/mcp`, RFC 9728 derives its metadata path as
`/.well-known/oauth-protected-resource/chatgpt/mcp`. The bridge validates this
path against `resource` and serves the metadata there; the root-only path is
not used for a path-qualified resource. Set `resourceMetadataUrl` to the
externally reachable HTTPS URL for that derived path.

### Auth0 read-only verification (2026-10-20)

Public GET requests to the tenant's OIDC discovery document, OAuth
authorization-server metadata, JWKS, and ChatGPT's supplied CIMD document did
not start an authorization flow or expose a token. The issuer exactly matches
the configured trailing-slash issuer. Both Auth0 metadata documents advertise
`client_id_metadata_document_supported: true`,
`authorization_response_iss_parameter_supported: true`, PKCE S256, and token
endpoint methods `none` and `private_key_jwt`. They advertise
`authorization_code` and `refresh_token`; `offline_access` is listed in
`scopes_supported`, and no DCR registration endpoint is published. The current
public JWKS contains two RSA-2048 RS256 signing keys. No key material is stored
in this report.

The public ChatGPT CIMD document uses its own HTTPS URL as `client_id`, declares
`private_key_jwt` and the authorization-code/refresh-token grants, and publishes
a public JWKS URL. OpenAI documents that ChatGPT uses the CIMD URL as the OAuth
`client_id`; Auth0 documents that its default access-token profile represents
the client in `azp`, while RFC 9068 uses `client_id`, and that CIMD's
`external_client_id` is the alternate identifier used during authorization.
The read-only Dashboard shows both the external CIMD URL and internal Auth0
client ID. The exact value emitted in `azp` was not observed because token
exchange is out of scope. The bridge accepts either claim dialect, but rejects
a token if both are present with different values; deployment must allowlist
only the exact value verified in a separately authorized test.

The Auth0 CIMD Management API operation is a `POST` create/update upsert keyed
by `external_client_id`, not a read-only client lookup, and was not called.
The Dashboard independently shows internal client ID
`tpc_8Gh7siSu4HFHVqNQBHgZAA` and the ChatGPT callback URL. `g7.read` is not an
OIDC discovery scope; its application grant was confirmed separately in the
API's Application Access table.

The configured API Identifier equals the bridge resource identifier. The
operator reports Resource Parameter Compatibility enabled; this read-only
Dashboard inspection independently confirmed the API uses the `Auth0`
access-token profile with RS256 signing.
Auth0's default profile uses `azp`; RFC 9068 would instead use `client_id`. The
tenant's internal CIMD client ID and external metadata URL are different. The
Dashboard and public CIMD metadata do not show which value the authorization
server will place in `azp`, so do not allowlist both as a guess; the exact claim
value remains unverified without an authorized read-only issuance observation.

The API Dashboard currently shows `Allow Offline Access` disabled, despite the
application's refresh-token rotation setting. Therefore a ChatGPT refresh
token for this API is not ready: Auth0 requires both `offline_access` and this
API setting for offline refresh tokens. The API's Application Access page
shows the ChatGPT CIMD application has 1/1 user-delegated permission granted
(`g7.read`); Client Access is 0/1. The API Identifier is
`https://g7-staging.test/chatgpt/mcp`, and the active tunnel profile's local
upstream is `https://127.0.0.1:18443/chatgpt/mcp`. The former is the canonical
OAuth resource; the latter is only the tunnel client's upstream URL. OpenAI
documents that OAuth discovery is forwarded through the tunnel, but the tunnel
is stopped, so the resource metadata has not yet been observed end-to-end.

The authorized Auth0 user record is a Google identity and its stable `sub` was
read from the Dashboard without requesting or exchanging a token. Its value is
kept out of this repository. The record identifies the candidate subject, but
it is not an approved Owner transition by itself.

The existing G7 Owner model accepts Cloudflare Access principals only. The
staging runtime fixes that principal to
`https://g7-owner-staging.cloudflareaccess.com`; the ChatGPT bridge now rejects
that synthetic issuer at startup. Bindings store both the 24-hex Owner ID and
the Owner identity digest, the binding snapshot must reconcile to the append-
only Owner audit history, and grants are keyed to the digest. No supported API
currently transfers or aliases those records to an Auth0 `iss` + `sub`, and
there is no cross-store transaction/recovery protocol for changing the
canonical Owner. A direct config remap would either preserve a synthetic
identity or orphan existing binding/grant authorization. Do not perform that
remap or rewrite/reset durable stores.

The safe next implementation is an explicit Owner-approved identity-transition
protocol with append-only intent/outcome audit, authenticated proof of the
Auth0 subject, conflict/revocation rules, and a store API that preserves the
existing binding/grant references and revisions. This protocol is not present
in I8A/I8C and was not invented in this preactivation patch. The read-only
Dashboard `user_id` is the candidate `sub`; before any authorized token test,
the Owner must approve the transition semantics and the migration API must be
implemented and certified.

Auth0 currently publishes two signing keys; the JWKS response does not identify
which key is current or queued for rotation. The bridge pins public keys in
deployment configuration and fails closed on an unknown `kid`; the added
synthetic suite verifies overlapping old/new keys and unknown-key denial.
Before a real key cutover, include the next key, retain the prior key until its
tokens expire, then remove it. Automatic JWKS retrieval/rotation is not
implemented.

### I8D read-only Auth0 evidence (2026-10-20)

- The `ChatGPT` client is shown as Third-party CIMD, with external ID
  `https://chatgpt.com/oauth/client.json` and internal Auth0 client ID
  `tpc_8Gh7siSu4HFHVqNQBHgZAA`.
- The API settings show token profile `Auth0`, signing `RS256`, JWE off,
  `Allow Offline Access` off, and per-application access policies.
- The API access table shows 1/1 user-delegated permissions for ChatGPT and
  0/1 Client Access permissions. No access token was requested, so actual
  `aud`, `scope`, and `azp` claim values were not inspected.
- The Auth0 user record showed one `google-oauth2` identity and a recent login.
  The exact subject is deliberately excluded from versioned evidence.
- A read-only SSH query confirmed the tunnel profile upstream is the loopback
  MCP URL above; the daemon and bridge remain inactive.

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
- [Auth0 third-party application controls](https://auth0.com/docs/get-started/applications/third-party-applications/security-controls)
- [Auth0 access-token profiles](https://auth0.com/docs/secure/tokens/access-tokens/access-token-profiles)
- [Auth0 CIMD registration API](https://auth0.com/docs/api/management/v2/clients/register-or-update-a-cimd-client-via-metadata-uri)
- [MCP authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [RFC 9728 Protected Resource Metadata](https://datatracker.ietf.org/doc/html/rfc9728)

The bridge supports stateless Streamable HTTP JSON-RPC, protocol versions
`2025-03-26`, `2025-06-18` and `2025-11-25`, and the RFC 9728 path-derived
protected-resource metadata route. POST requires both JSON and event-stream
media types in `Accept`; the endpoint returns JSON and rejects GET with 405
because it has no server-initiated event stream. Unsupported
`MCP-Protocol-Version` values fail with 400; absent headers retain the
protocol's 2025-03-26 compatibility rule.
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

## I8F isolated Auth0 Owner realm

The synthetic staging Owner cannot be transferred to Auth0 by editing its
bindings or grants. I8F adds an offline Auth0 principal verifier, a separate
hash-chained Owner authority journal with signed bootstrap/recovery approvals,
and an inert loopback realm activation barrier. The bridge can resolve only an
active Owner from that authority and rechecks it before dispatch and result
delivery. I7 state and its Cloudflare path remain untouched.

I8F does not enable live administration: the Auth0 tenant has no verified
`g7.owner` scope/client, grant and pairing stores are not coordinated by a
cross-store transaction, and the device agent supports one binding/ledger per
identity. No production key or device enrollment is included. See the [Owner
transition and activation runbook](./OWNER_TRANSITION_RUNBOOK.md).

## Local synthetic certification

`gateway/test/chatgpt-read-only-bridge.test.mjs`,
`gateway/test/isolated-chatgpt-owner.test.mjs`, and
`gateway/test/durable-owner-authority.test.mjs` use short-lived synthetic keys,
disposable stores, and loopback-only mock policy dependencies. They do not use
the VPS, real Owner credentials, Cloudflare, an OpenAI tunnel, or ChatGPT
plugin configuration. The isolated realm is not imported by the live server.
