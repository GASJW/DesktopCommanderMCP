# G7 standalone staging runtime

This runtime composes the existing I2–I4C modules in a dedicated staging process. It is not imported by `gateway/server.mjs`, does not alter G6, and has no systemd or public-listener setup.

## Reproducible disposable pilot

Build Desktop Commander from this checkout first; the pilot uses only the explicit `VPSC_STAGING_MCP_ENTRYPOINT` path and rejects symlinks, hard links and writable artifacts.

```sh
npm ci
npm run build
VPSC_STAGING_MCP_ENTRYPOINT="$PWD/dist/index.js" node scripts/g7-staging-pilot.mjs --json
```

Run as a nonroot user with Node 22. If `/tmp` is inaccessible, the script uses `/var/tmp` and creates a random mode `0700` directory there. It creates synthetic Owner, M2M, Ed25519, policy-signing, and TLS material in memory or in mode `0600` files, then removes the complete temporary tree after all child processes stop. It never contacts a production Gateway or Cloudflare endpoint.

The script starts `gateway/staging/server.mjs` and `packages/vpsc-agent/bin/g7-staging-worker.mjs` as separate processes. It pairs and approves a synthetic device, writes a durable machine binding and restricted grants, reads a temporary file through the built Desktop Commander MCP server, performs a create-only governed write, tests agent `SIGKILL` recovery and graceful Gateway restart, revokes a grant and device, checks separate Owner/M2M failures and rejects a cross-device challenge, then verifies that all captured process groups are gone before deleting state.

## Individual process entrypoints

The Gateway accepts only `node gateway/staging/server.mjs --config /private/path/gateway.json`. The worker accepts only `node packages/vpsc-agent/bin/g7-staging-worker.mjs --config /private/path/agent.json`. Both reject root execution. Configuration files must be regular owner-owned mode `0600` files; state and identity directories must be separate owner-only directories. Gateway storage paths are validated by the existing durable stores. The Gateway listener is pinned to `127.0.0.1`; its health endpoint is `GET /healthz`.

Gateway configuration is version 1 and has these exact top-level fields:

```json
{
  "version": 1,
  "hostname": "g7-staging.test",
  "listen": { "host": "127.0.0.1", "port": 0 },
  "tls": { "keyPath": "/private/tls.key", "certificatePath": "/private/tls.crt" },
  "owner": {
    "issuer": "https://synthetic-owner.cloudflareaccess.com",
    "audience": "64 lowercase hex characters",
    "email": "staging-owner@example.test",
    "subject": "synthetic-owner-subject",
    "origin": "https://g7-staging.test",
    "controlToken": "64 lowercase hex characters",
    "jwks": [{ "kty": "RSA", "alg": "RS256", "kid": "owner-key-id", "n": "...", "e": "AQAB" }]
  },
  "machine": {
    "issuer": "https://synthetic-agent.cloudflareaccess.com",
    "audience": "a different 64 lowercase hex string",
    "clientId": "synthetic-client-id",
    "serviceSecret": "synthetic secret, at least 24 characters",
    "signingKeyPath": "/private/machine-jwt.key",
    "jwks": [{ "kty": "RSA", "alg": "RS256", "kid": "machine-key-id", "n": "...", "e": "AQAB" }]
  },
  "policy": {
    "directory": "/private/policy",
    "privateKeyPem": "synthetic Ed25519 PKCS8 PEM",
    "publicKeyPem": "matching synthetic Ed25519 SPKI PEM"
  },
  "storage": {
    "auditDirectory": "/private/audit",
    "trustDirectory": "/private/trust",
    "bindingDirectory": "/private/bindings",
    "grantDirectory": "/private/grants"
  }
}
```

Owner and machine issuers, audiences, and RSA keys must differ. The Owner private signing key belongs only to the Owner client. The machine signing key and service token are synthetic staging credentials and must be owner-only. The machine TLS edge verifies the service Client-ID/secret and then injects a short-lived synthetic machine JWT; it does not emulate Cloudflare administration. The TLS certificate SAN must match `hostname`; clients pin that certificate as their CA and keep hostname validation enabled.

The agent configuration is version 1 with the exact fields `version`, `hostname`, `port`, `deviceId`, `clientId`, `clientSecret`, `identityDirectory`, `allowedRoot`, `ledgerDirectory`, `mcpEntrypoint`, `policyPublicKeyPem`, `caPath`, and `pollIntervalMs`. Its `identityDirectory` must already hold a v3 Owner machine binding matching `deviceId`, `clientId`, and the Ed25519 fingerprint. `mcpEntrypoint` must point to the real built Desktop Commander `dist/index.js`; the executor still enforces the configured `allowedRoot` and fixed operation profiles.

The staging Owner control routes require all of: a valid synthetic Owner JWT, exact staging Origin, and the mode `0600` configuration's `controlToken`. They provide only binding, restricted grant, grant-revocation, and device-revocation operations. Pairing approval continues through the I2 Owner route with its own JWT and CSRF token. The agent never receives the Owner JWT or control token.

After the Gateway prints a `READY` record containing its assigned loopback port, configure the agent with that port and start it as a second process. Do not persist either process with systemd in this release. Send `SIGTERM` and wait for the `STOPPED` record before deleting private state. A Gateway crash may leave durable-store locks; startup intentionally fails closed and never clears them automatically. Use the existing I2 reconciliation procedure only against disposable staging state after confirming writer quiescence.

## Cancellation and recovery limits

Closing the Owner HTTP request propagates cooperative cancellation through the router and agent. A cancellation after delivery can be ambiguous; it does not roll back a completed write and is never retried automatically. The standalone pilot records that its Owner transport abort occurred, but does not claim that the remote command had entered execution before the abort. Deterministic delivered-job cancellation and ledger correlation remain covered by the I3/I4C regression suite (`packages/vpsc-agent/test/i3-durable-https.integration.test.mjs`); this pilot cancellation sub-gate is therefore reported as not certified by the standalone pilot.

The trust, Owner WAL, machine-binding, grant, and agent execution-ledger stores remain separate durable files. The runtime claims no cross-file atomicity. Missing or corrupt evidence, stale sessions, unexpected revisions, and unresolved execution outcomes remain fail-closed. This local pilot does not certify hosted CI, public ingress, production release, Cloudflare integration, persistent service operation, or a real device enrollment.
