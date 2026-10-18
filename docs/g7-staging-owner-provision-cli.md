# G7 staging Owner provisioning client

This client performs the one-time first-device provisioning sequence against the isolated G7 staging Gateway. It does not mount routes in G6 and does not read or modify trust, Owner WAL, machine-binding, or grant files directly.

The client only accepts the synthetic staging origin `https://g7-staging.test`, connects to `127.0.0.1`, validates TLS against the configured CA, and accepts the synthetic Owner issuer `https://g7-owner-staging.cloudflareaccess.com`. It refuses non-loopback connections, production Owner identities, mismatched or undersized signing keys, unsafe files, and an allowed root outside a path explicitly named for G7 staging. It refuses Owner signing keys under the planned Gateway or agent release, configuration, and state directories and the G6 checkout.

## Provisioning contract

The test device first creates its durable Ed25519 identity, submits `/pairing/start`, and proves possession through `/pairing/prove`. The device must show the request ID, comparison code, and public-key fingerprint to the operator through a trusted out-of-band display. The Owner pending endpoint deliberately omits the comparison code. The operator compares all three values before supplying them to this client.

The client then performs, once and in order:

1. Read `/healthz` and require an empty trust, binding, and policy state.
2. Fetch the Owner pending list to obtain the session CSRF token; require the exact request ID, matching fingerprint, and verified device proof.
3. Mint an Owner JWT in memory using the local Owner RSA private key and submit the I2 approval with the exact staging Origin and CSRF token.
4. Bind the approved device to the configured synthetic machine Client-ID through the authenticated staging API.
5. Create one `read_file` grant scoped to the configured approved root, with fixed limits of 65,536 bytes, 1,000 characters, and offset 100,000.

The Gateway persists the I2 decision and verifies its receipt before accepting the machine binding. The client does not persist the Owner JWT, comparison code, CSRF token, or private key and never prints them. The Owner signing key remains on the client host and must not be copied into the Gateway configuration directory.

This is a bootstrap client: it refuses to operate unless all three revisions are zero. It does not create a pairing request, perform device proof, provision the agent's private key or machine service secret, revoke an existing device, or retry a mutation.

## Client configuration

Create a private configuration file owned by the non-root operator account with mode `0600`. Keep the Owner key in a separate file owned by that account with mode `0600`. The CA file must be owned by the same account and must not be writable by group or others. Do not put any of these files in the repository.

The JSON schema is strict; unknown fields are rejected:

```json
{
  "version": 1,
  "origin": "https://g7-staging.test",
  "connectAddress": "127.0.0.1",
  "connectPort": 18443,
  "tlsServerName": "g7-staging.test",
  "caPath": "/etc/vpsc-g7-staging-owner/staging-ca.crt",
  "stageControlToken": "<64 lowercase hex characters from the synthetic staging setup>",
  "owner": {
    "issuer": "https://g7-owner-staging.cloudflareaccess.com",
    "audience": "<64 lowercase hex characters configured for this synthetic Owner>",
    "email": "g7-staging-owner@example.test",
    "subject": "synthetic-owner-staging-1",
    "kid": "g7-staging-owner-1",
    "publicJwk": {
      "kty": "RSA",
      "alg": "RS256",
      "kid": "g7-staging-owner-1",
      "n": "<RSA public modulus>",
      "e": "AQAB"
    },
    "privateKeyPath": "/etc/vpsc-g7-staging-owner/owner-signing.key"
  },
  "machineClientId": "g7-staging-agent.synthetic",
  "allowedRoot": "/var/lib/vpsc-g7-staging-agent/approved-root"
}
```

The public JWK must match both the private key and the Gateway's synthetic Owner JWKS. The stage control token is a synthetic staging credential and must be protected like a secret. Do not reuse any G6 credential or identity. The client validates that the scope path is normalized and staging-named; the agent validates the actual directory and its ancestors before it serves file operations, so the Owner client does not need access to the agent's private state directory.

## Run

Run as the non-root staging operator after confirming the device display out of band. Supply a single JSON object on standard input; do not put the comparison code in command arguments or shell history.

```sh
/opt/vps-commander/bin/node scripts/g7-staging-owner-provision.mjs \
  --config /etc/vpsc-g7-staging-owner/client.json
```

Standard input must contain exactly these fields:

```json
{"requestId":"<UUID>","code":"<10-character device comparison code>","fingerprint":"<64 lowercase hex characters>"}
```

On success, stdout contains a non-secret summary with the device ID, fingerprint, Client-ID, revisions, grant ID, tool, and scope. It also returns the exact validated I2-backed machine-binding receipt and a bounded grant record so the separately controlled agent identity preparation can persist the approved binding using the existing identity-store API. The Owner client never writes agent identity files or Gateway stores. The code and Owner JWT are not included.

The returned binding includes event IDs, Owner identity digest, and trust revisions. Treat the record as integrity-sensitive provisioning data: transfer it only through the approved local staging procedure and require the agent to match its own Ed25519 fingerprint. It is not a signing key or a new authorization capability by itself.

## Failure handling

The client never retries. If approval, binding, or grant returns a server error, times out, loses its TLS connection, or returns an invalid response, treat the result as ambiguous. Do not rerun the command and do not edit any store file. Preserve the existing locks and history; follow the staging recovery runbook to inspect audit, trust, binding, and grant evidence before an operator authorizes any recovery.

A pending request with an invalid proof, wrong request ID, or fingerprint mismatch is rejected before mutation. A Gateway that already has any trust, binding, or policy revision is also rejected before a write. These conditions require operator review and an explicit new decision, not a retry.

## Local test

```sh
TMPDIR=/var/tmp /opt/vps-commander/bin/node --test \
  gateway/test/staging-owner-provision-cli.test.mjs
```

The test starts a disposable TLS server on loopback, verifies the Owner JWT signature and claims, checks Origin/CSRF and the stage control header, and confirms that socket loss or HTTP 503 during approval causes no retry and no subsequent binding or grant request.
