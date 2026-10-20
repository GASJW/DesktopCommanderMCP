# I8F — Isolated Auth0 Owner bootstrap and activation

**Status: offline implementation candidate; not approved for live activation.**
No live Gateway, agent, Auth0 tenant, OAuth token, tunnel, or persistent store
was read or changed by this work. The I7 Cloudflare Access path remains
unchanged.

## Decision

| Option | Decision | Reason |
| --- | --- | --- |
| Transfer the synthetic Owner across I7 binding, grant, trust, and audit stores | Rejected | Existing records are immutable and their stores have no cross-store transaction or recovery protocol. Rewriting IDs/digests would invalidate history. |
| Bootstrap the real Owner in a new isolated realm | Selected | New Owner and least-privilege state are append-only under a separate storage root; I7 remains untouched. |

The isolated realm must not mount or import I7 audit, binding, grant, ledger,
policy, or trust state. Existing I7 stays independently usable until a
separately approved cutover.

## Identity and administrative authority

The Owner identity is the exact `(Auth0 issuer, Auth0 subject)` pair. The
verifier in `gateway/owner/auth0-owner-auth.mjs` accepts signed RS256 access
tokens only and checks the configured issuer, resource audience, allowlisted
`client_id`/`azp`, `g7.read` or `g7.owner` scope, timestamps, and known public
`kid`. It rejects conflicting client claims and unknown keys. The Owner subject
is non-enumerable on the verified in-memory principal; durable records keep a
domain-separated Owner ID and digest, not the raw subject or access token.

The chosen bootstrap authority is an offline Ed25519 approval key pinned by
public key in the new realm. Bootstrap requires both a verified Auth0 `g7.read`
token and a short-lived signed approval bound to the exact Owner digest, realm,
operation, event ID, expected revision, and expiry. `g7.read` alone cannot
bootstrap or administer. The private approval key is not created or stored by
this repository change.

Owner revocation requires `g7.owner` plus a separate signed approval. The
current Auth0 tenant has not been configured with that scope or an authorized
client. No Auth0 changes are included here. Grant and pairing changes also
remain unavailable until their own durable stores consume approvals and record
each action. The existing ChatGPT bridge only uses `g7.read` for `read_file`.

## Implemented offline APIs

- `createAuth0OwnerVerifier(config)` validates Auth0 access tokens and brands
  verified principals. Only those principals are accepted by Owner identity
  helpers; unverified `{issuer, subject}` objects cannot become Auth0 Owners.
- `createDurableOwnerAuthority(...)` is bound to one realm and one private,
  nonroot Linux directory owned by its service account with mode `0700`. It
  reuses the existing durable Owner audit WAL and process locks, adding exact
  version-1 `g7_owner_authority` intent/outcome records. Every transition is
  hash-chained, revision-bound, and signed. Repeating the exact completed
  bootstrap event is idempotent; conflicting IDs or revisions fail closed.
- `createChatGptReadOnlyBridge({ oauth, ownerAuthority, ... })` resolves the
  authenticated Owner from the active authority rather than mapping an Auth0
  subject to the synthetic Owner. The surface remains `read_file` only and
  uses the existing device, grant, session, and response-fence checks. The
  active Owner is rechecked before dispatch and before result delivery, so
  revocation suppresses late results.
- `createIsolatedG7Realm(...)` validates loopback-only `127.0.0.1`, distinct
  normalized store paths, symlink/reparse rejection, non-overlap with protected
  I7 paths, and a distinct Ed25519 control key fingerprint. Its activation
  barrier requires an active, recovered Owner and healthy audit, binding, grant,
  ledger, policy, and trust inspectors with no pending work. It rechecks after
  listener startup and closes the listener if Owner/store readiness changed.

The realm composer is deliberately inert: the caller must supply read-only
store inspectors and a loopback starter. The starter must use the paths passed
to it and return a closeable listener. No server or runtime is started by this
module.

## Recovery and activation

The Owner WAL is authoritative for the Owner revision. A crash after lock
creation leaves the realm empty but unavailable. A crash after intent leaves a
pending transition; a crash after outcome leaves the committed Owner behind a
stale writer lock. In all cases token verification and activation fail closed.

Recovery requires all of the following:

1. An operator confirms there are no active writers.
2. A new Ed25519 `owner.recover` approval binds the exact WAL sequence/hash,
   pending event ID, and observed writer/reconciliation lock digests.
3. Recovery uses the existing durable reconciliation APIs; it never deletes
   WAL evidence, resets a revision, steals a live lock, or replays an MCP call.
4. A pending bootstrap is completed only from its original valid signed
   approval. The recovery approval is appended to the outcome. A stale lock
   with no pending transition is reconciled without changing Owner state.
5. The listener remains closed until Owner recovery and every store inspector
   passes. Read principals are checked again at dispatch and response delivery.

There is no cross-store transaction for pairing and grants. Their own durable
stores must report healthy and reconciled before activation, but I8F does not
coordinate mutations across those stores. The Owner authority must not be
treated as proof that a device or grant was provisioned.

## Device multi-realm feasibility

The current agent persists one `deviceBinding` in its identity envelope, one
device/client configuration, and one execution ledger. Two workers must not
share the same DPAPI-protected identity directory or ledger. The agent has no
certified multi-realm binding API, and the existing bind operation refuses a
different binding. Therefore the current Linux and Windows identities cannot
be assumed to work simultaneously in I7 and the isolated realm. I8F does not
copy keys, ledgers, or device secrets. A future cutover needs a governed
quiescent worker stop and a separately tested multi-realm binding/cutover
protocol; no device enrollment is included.

## Certification and remaining blockers

Synthetic tests cover valid and invalid Auth0 claims, scope separation, public
key overlap and unknown `kid`, durable bootstrap/revocation, revision and
duplicate handling, concurrent bootstrap, lock/intent/outcome crash recovery,
tamper-evident WAL replay, isolated paths, activation readiness, read-only MCP,
device/grant policy, and Owner revocation during execution or listener startup.
The live I7 stores are not part of these tests.

Before any live Owner review/activation, provide:

- a separately configured and verified `g7.owner` scope/client, or another
  explicitly authorized admin mechanism;
- a real offline approval key and key-custody/rotation procedure;
- a production resource URI and pinned Auth0 JWKS rotation procedure;
- domain-store integration that binds each approved pair/grant change to its
  own durable event ID and Owner approval;
- a supported device enrollment/cutover method for the single-binding agent;
- concrete store inspectors and loopback runtime composition, tested against
  disposable state before deployment.

I8F does not exchange a real token, create a production key, provision devices,
issue grants, start a tunnel/service, change Auth0, or touch I7 state. A new
explicit Owner authorization remains required before those actions.
