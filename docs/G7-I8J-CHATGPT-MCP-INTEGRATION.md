# G7 I8J — isolated ChatGPT MCP integration

**Status: offline candidate; not deployed or activated.** This document covers
the integrated ChatGPT endpoint inside the isolated I8 realm. It does not
change the active I7 Gateway or its stores.

## MCP and protected-resource contract

The isolated realm exposes one ChatGPT MCP resource at `POST /chatgpt/mcp`.
It supports MCP initialization and `tools/list`; the advertised tool set is
exactly `read_file`. The root-only `/mcp` alias is not served. The independent
machine-authenticated `/agent/*` routes continue to serve worker transport.

Protected Resource Metadata is served by unauthenticated `GET
/.well-known/oauth-protected-resource/chatgpt/mcp`. Its `resource` and
`authorization_servers` values come from the isolated Owner authority, and it
advertises only `g7.read`. A missing or invalid Owner bearer token on
`tools/call` produces the MCP OAuth challenge metadata; other protected
requests use `WWW-Authenticate`. The metadata URL configured for the listener
must use HTTPS and the canonical metadata path derived from the resource.

The OAuth verifier enforces the Owner authority's exact issuer and resource
audience, expiration and not-before time, RS256 signature and known `kid`, an
allowlisted `client_id` or `azp` (both must agree if both appear), the exact
subject mapping, and `g7.read`. Tokens containing `g7.owner` are denied. The old
synthetic Cloudflare staging Owner is not accepted. The current Owner authority
is checked again at dispatch and at result delivery. Existing device
approval/binding, live-session, durable grant, approved-root, and late-result
fences remain in the path. No ChatGPT authorization grants `g7.owner`.

Request identity is stable across a transport retry or token refresh: it binds
the verified Owner, `openai/session`, JSON-RPC ID, device, tool and canonical
arguments. Reusing the same session, RPC ID and payload is ambiguous and is
rejected by the durable request/grant fence (`DUPLICATE_REQUEST`); callers
must use a fresh RPC ID for a new invocation. An unknown result is never
replayed automatically.

## Isolated Gateway configuration

The listener accepts `chatgpt.resourceMetadataUrl`; issuer, resource and
authorized client IDs are sourced from the isolated Owner authority rather
than duplicated in another configuration. A startup mismatch is fail-closed.
The listener host must remain `127.0.0.1` and match the realm's configured
port. See the non-executable templates in [`../config/g7-i8j/`](../config/g7-i8j/).

The committed templates are planning inputs, not runnable Gateway
configuration. Provision the TLS, machine credentials, Auth0 public keys and
Owner authority through their dedicated secret/key custody mechanisms. Keep
private keys, client secrets, real subjects, access/refresh tokens, tunnel
runtime keys and certificate private keys out of Git and ordinary logs.

## Proposed private route and remaining assumptions

Proposed data path:

```text
ChatGPT custom MCP connection (Tunnel)
  -> dedicated OpenAI Secure MCP Tunnel
  -> isolated I8 loopback HTTPS listener: /chatgpt/mcp
  -> isolated Auth0 Owner authority and current device/grant fences
  -> read_file-only I8 worker
```

The supported OpenAI tunnel is outbound and is designed to keep the MCP
origin private. Official guidance allows resource OAuth discovery to pass
through the tunnel; the authorization server must independently be reachable
to ChatGPT. A live tunnel route, ChatGPT workspace permission, tunnel runtime
key, custom CA trust, TLS hostname, and actual discovery exchange have not
been exercised in this offline task. The selected tunnel target must preserve
the certificate SAN and CA checks and end at the I8 listener, never I7.

The following are deliberately unverified and must not be inferred from the
synthetic suite:

- **Canonical resource URI:** it must exactly equal the I8 Owner authority's
  configured `resource` and the Auth0 API Identifier/audience. A prior I7
  staging identifier or the tunnel's local upstream URL is not automatically
  the I8 resource.
- **Discovery through the selected tunnel:** protocol documentation supports
  forwarding discovery, but the real profile, path mapping and returned
  metadata have not been tested end-to-end.
- **Auth0 JWT claims:** synthetic RS256 tokens prove the verifier's rules, not
  which `client_id`/`azp`, `aud` or `scope` the real CIMD exchange emits. The
  exact observed client claim must be allowlisted; do not allow both candidate
  IDs as a guess.
- **Refresh issuance:** no real OAuth exchange was made. Prior read-only
  evidence recorded Auth0 API “Allow Offline Access” as disabled; verify the
  effective setting and refresh-token behavior before activation. If ChatGPT
  needs refresh tokens, Auth0 must allow the appropriate offline access and
  rotate refresh tokens.
- **Remote Windows-to-VPS worker transport:** the native Windows/Linux test
  used a disposable authenticated relay inside WSL. It does not certify a
  production route from a remote Windows host to the VPS. The ChatGPT MCP
  tunnel carries the ChatGPT resource, not the worker's separate `/agent/*`
  machine traffic. That private transport needs its own approved, tested
  design.

### Auth0 changes to evaluate separately (not applied)

1. Confirm or create the isolated I8 API Identifier equal to the exact
   `ownerAuthority.resource`; do not repurpose I7's resource by assumption.
2. Define and grant only `g7.read` to the ChatGPT CIMD client. Never grant
   `g7.owner` to that client.
3. After a separately authorized token issuance, allowlist only the observed
   ChatGPT client claim and verify issuer, audience, scope, expiry and `kid`.
4. Confirm authorization-code + PKCE S256, CIMD compatibility and required
   refresh-token/offline-access settings. Keep JWKS public-key rotation
   overlap coordinated; unknown `kid` remains denied.
5. Map the exact verified Auth0 subject only to the approved isolated I8
   Owner. The synthetic I7 staging Owner is never promoted or aliased.

## Release, key custody, gates and rollback

The versioned `G7-I8J-ChatGPT-MCP-RC1` manifest records the base, implementation
commit and hashes of changed source/templates plus dependency inventory. The
isolated realm must retain separate roots for configuration, Owner authority,
provisioning, audit, trust, binding, grant, policy, execution ledger and
runtime. Keep Auth0 public JWKS material separate from private signing keys;
retain overlapping public keys through the maximum token lifetime and clock
skew, then remove the retired key in a reviewed versioned update. Rotate
machine, TLS, policy and control keys through the existing realm procedures;
never copy I7 key material.

Live activation requires separate explicit Owner approval for each applicable
change: Auth0 API/client settings and subject mapping; I8 Owner bootstrap and
signed administrative approval; device pairing/binding and read grant; private
tunnel selection/profile and runtime key; the separate Windows-to-VPS worker
transport; and manual Gateway/worker start. No live activation or these
mutations are included here.

If a future approved rollout fails, stop only the exact I8 tunnel client and
I8 workers, then the I8 Gateway. Keep all I8 durable state and audit evidence;
never restore an older snapshot over newer trust/grant/ledger state or replay
an ambiguous operation. Verify I7 process, configuration, revisions and
read-only health before and after; do not send test reads to I7. Roll back
only versioned I8 runtime/configuration after confirming no unresolved I8
execution or result delivery remains. If ambiguous, leave I8 stopped for
reconciliation. This plan does not authorize execution.

Historical `STALE_LOCK` and `ECONNRESET` incidents remain open and retain their
previous classifications. This candidate neither resolves nor reclassifies
them.

## Certification evidence

The synthetic Linux E2E composes metadata discovery, initialization, tool
discovery, Auth0 claim denial, approved reads, Owner/device/grant revocation,
late-result fencing, and I7 fixture isolation. The native Windows-to-Linux E2E
uses a disposable nonroot Linux Gateway, a private authenticated temporary
relay, native Windows Node and DPAPI identity; it verifies the content hash,
TLS host/CA rejection, machine credential rejection, path/tool denial,
restart, revocation, one durable execution on duplicate request, and fail-
closed recovery. Both are offline fixtures only. Full applicable suite results
and per-run evidence hashes are recorded in the release evidence manifest.

OpenAI references checked 2026-10-21:

- [Secure MCP Tunnels](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)
- [ChatGPT custom MCP connections](https://help.openai.com/en/articles/12584461-connecting-custom-mcp-servers-in-chatgpt)
- [OAuth for ChatGPT MCP](https://developers.openai.com/plugins/build/auth)
