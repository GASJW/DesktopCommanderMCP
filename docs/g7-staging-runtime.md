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

The script starts `gateway/staging/server.mjs` and `packages/vpsc-agent/bin/g7-staging-worker.mjs` as separate processes. It pairs and approves a synthetic device, writes a durable machine binding and restricted grants, reads a temporary file through the built Desktop Commander MCP server, performs a create-only governed write, tests agent `SIGKILL` recovery and graceful Gateway restart, then kills the idle Gateway with `SIGKILL`. After verifying every captured Gateway and agent process group is gone, it analyzes the WAL/trust evidence and invokes the existing I2 reconciler with explicit no-active-writers confirmation on this private disposable state. It confirms `RECONCILED_CONSISTENT`, restarts the Gateway and agent with fresh sessions, revokes a grant and device, checks separate Owner/M2M failures and rejects a cross-device challenge, then verifies all process groups are gone before deleting state.

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

After the Gateway prints a `READY` record containing its assigned loopback port, configure the agent with that port and start it as a second process. Do not persist either process with systemd in this release. Send `SIGTERM` and wait for the `STOPPED` record before deleting private state. A Gateway crash may leave durable-store locks; startup intentionally fails closed and never clears them automatically. The pilot clears them only after the known writer process groups are confirmed stopped and the I2 analyzer reports a consistent recoverable state. Use the I2 reconciliation procedure only against disposable staging state after confirming writer quiescence.

## Cancellation and recovery limits

The ordinary `node scripts/g7-staging-pilot.mjs --json` run does not enable test fixtures. The automated nonroot Node 22 test (`packages/vpsc-agent/test/staging-runtime.test.mjs`) starts the same Gateway and worker entrypoints as independent processes, then enables a test-runner-only fixture for three disposable runs: Owner cancellation, grant revocation, and device revocation during an active operation. The fixture only uses the already constrained `run_command` `count_lines` profile; its test hook substitutes a fixed `/usr/bin/sleep 30`, never a shell or caller-selected executable.

For Owner cancellation before local execution, the agent emits a receipt signal, waits for the authenticated control poll, and then calls the real executor with an aborted signal. The test confirms that the executor wrote no I4 intent and that a later real MCP read succeeds. The Owner connection has already closed, so the Gateway conservatively returns an accepted `ambiguous` cancellation acknowledgement; the report keeps the agent's local `cancelled` result and the Gateway's `ambiguous` result separate. An accepted Gateway `ambiguous` acknowledgement is not treated as a transport failure and cannot be upgraded to `cancelled`.

For active-job scenarios, the agent signals its request ID and child PID after OS spawn. Before requesting cancellation or revocation, the pilot verifies through `/proc` that the exact `/usr/bin/sleep 30` PID is live, has the agent PID as parent, belongs to the staging user's UID, and runs in its own process group. It then waits for the child to stop and checks one matching I4 intent and one `ambiguous` outcome. Owner cancellation and grant revocation receive an authenticated agent acknowledgement. Device revocation fences the session; if the revoked session cannot deliver an acknowledgement, the pilot keeps the Owner result non-successful and the executor outcome ambiguous. None of these outcomes imply rollback. No request is replayed. A subsequent operation is allowed only when the durable executor state remains consistent.

For grant revocation, job start, durable policy-revocation response, and the agent's authenticated cancellation acknowledgement are compared with the Linux monotonic clock. Both the commit and ACK must be observed before the fixed 10-second command timeout with a 500 ms margin. For device revocation, job start, trust-revocation request/commit, and the agent's rejected heartbeat or control poll are compared the same way. The test requires both trust commit and session rejection to precede that timeout with the same margin. These checks prevent a normal executor timeout from being mistaken for revocation-driven fencing. The pilot then verifies the child exited and the Owner result remains ambiguous without replay.

Run the automated cancellation certification from a nonroot Node 22 environment after building the local MCP entrypoint:

```sh
VPSC_STAGING_NODE="$(command -v node)" \
VPSC_STAGING_MCP_ENTRYPOINT="$PWD/dist/index.js" \
node --test packages/vpsc-agent/test/staging-runtime.test.mjs
```

The test runner passes a private fixture selector only to the staging worker. The worker rejects that selector outside `NODE_TEST_CONTEXT`; the normal staging CLI has no active-job fixture option. Worker and Gateway process groups are checked and stopped before each private scratch tree is removed.

The trust, Owner WAL, machine-binding, grant, and agent execution-ledger stores remain separate durable files. The runtime claims no cross-file atomicity. Missing or corrupt evidence, stale sessions, unexpected revisions, and unresolved execution outcomes remain fail-closed. This local pilot does not certify hosted CI, public ingress, production release, Cloudflare integration, persistent service operation, or a real device enrollment.

## Persistent isolated staging handoff (planned only)

This is an operational handoff for a later, separately approved activation. No account, service unit, credential, or persistent staging process is created by this change.

- Use a dedicated nonroot staging account and group. Bind the Gateway only to `127.0.0.1`; keep the hostname in a staging-only local client mapping and use a staging CA/certificate. Do not add a public listener, Cloudflare route, real device, or production Owner identity.
- Keep Gateway and agent configs, Owner test material, machine secret/key, TLS key, and policy signing key in separate owner-only directories (`0700` directories, `0600` files). Use synthetic staging credentials only; provision them outside the repository and never put them in unit files or command arguments.
- Give trust, Owner audit/WAL, machine binding, grants/policy, device identity, and execution ledger separate persistent directories. Restrict write access to the corresponding staging process account. Preserve locks and histories across restart; startup must analyze state and fail closed on unresolved recovery rather than deleting locks or recreating stores.
- If persistence is approved later, use two distinct service units, `vpsc-g7-staging-gateway.service` and `vpsc-g7-staging-agent.service`, with absolute Node/script/config paths, `User=`/`Group=` set to the staging account, loopback-only Gateway binding, `NoNewPrivileges=yes`, filesystem write paths limited to the staging state/config roots, and no shell wrapper. Order the agent after the Gateway and make health/readiness explicit. Install, enable, or start neither unit as part of this handoff.
- Planned shutdown/rollback: stop the agent first, then the Gateway; verify both process groups and all known writers are gone; preserve a private snapshot of configuration and durable stores for diagnosis. Roll back by stopping/disabling only the staging units and restoring the prior staging config snapshot. Do not remove WAL, trust/grant history, execution ledger, or abandoned locks as part of rollback. Reconcile locks only through the existing supervised procedure after independently proving writer quiescence.
