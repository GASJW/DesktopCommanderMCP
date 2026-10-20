# I8H — Offline isolated Auth0 Owner provisioning

**Status: offline implementation candidate; not approved for live activation.**
No live Gateway, agent, Auth0 tenant, OAuth token, tunnel, or persistent store
was read or changed. I7 Cloudflare Access and its stores remain independent.

## Decision

| Option | Decision | Reason |
| --- | --- | --- |
| Transfer the synthetic Owner across I7 bindings, grants, trust, and audit | Rejected | Existing records are immutable and the stores have no cross-store transaction. Rewriting IDs or digests would invalidate history. |
| Bootstrap the real Auth0 Owner in a new isolated realm | Selected | New Owner and least-privilege state use separate storage roots. I7 remains untouched. |

The isolated realm must not mount or import I7 audit, binding, grant, ledger,
policy, or trust state. Do not copy device identities, binding receipts, or
grants. I7 remains independently usable unless a separately approved cutover
is completed.

## Identity and administrative authority

The Owner identity is the exact `(Auth0 issuer, Auth0 subject)` pair. The
verifier accepts signed RS256 access tokens only and checks the configured
issuer, resource audience, allowlisted client claim, `g7.read` or `g7.owner`
scope, timestamps, and a known public `kid`. Conflicting client claims and
unknown keys fail closed. Durable Owner records contain a domain-separated
Owner ID and digest, not the raw subject or access token.

Initial Owner bootstrap requires a verified Auth0 `g7.read` token and an
independent, short-lived Ed25519 approval signed by a pinned administrative
key. Every later pairing, binding, grant, or device-revocation operation
requires the active Owner with `g7.owner` **and** a separate signed approval.
The signature binds the exact realm, Owner digest, operation, event ID,
expected revision, target digest, and expiry. `g7.read` by itself cannot
approve devices or change grants. The private administrative key and its
custody procedure are not created or stored by this code.

## Offline provisioning API

`createIsolatedRealmProvisioning(...)` composes only dependencies whose
normalized paths match the validated, dedicated realm configuration. It
rejects store aliases and I7 paths. Use these APIs with synthetic identities
and disposable nonroot Linux state during offline verification:

1. Start an enrollment challenge, then verify fresh Ed25519 device-possession
   proof. Owner approval is bound to the exact realm, device ID, fingerprint,
   event ID, and trust revision before durable trust is changed.
2. Create the machine binding only for that trusted device, matching pairing
   receipt, Owner digest, client/device IDs, fingerprint, and expected binding
   revision. The existing binding audit API records the transition.
3. Issue only a `read_file` grant. Its approval binds the absolute root,
   read limits, device/fingerprint, Owner digest, realm, policy revision,
   and event ID. Grant revocation uses the existing durable grant API. The
   provisioning surface does not expose `write_file`, `run_command`,
   `list_processes`, or `list_directory` issuance.
4. The isolated realm activation barrier stays closed until the Owner is
   active, at least one device has valid possession/approval evidence and a
   matching binding, and that device has an active approved `read_file` grant.
   Trust, binding, grant, audit, and execution-state inspectors must be
   healthy, with no pending work or unresolved writer locks. Read and result
   authorization fences remain in effect.

Each administrative action is a hash-chained approval intent and outcome
linked to the corresponding trust, binding, or grant event. Reusing an event
ID, stale revision, wrong realm/Owner/device/fingerprint, expired signature,
or an escalated tool is rejected. Existing I7 store formats and decision
history are not rewritten.

## Crash recovery

The provisioning approval WAL records intent before the domain mutation and
records its outcome only after the existing domain store reports success. If
the mutation or acknowledgement is uncertain, that provisioner instance is
poisoned and activation remains blocked. There is no automatic retry or
replay of an enrollment or MCP operation.

The WAL stores the Gateway time when the signed approval was verified. New
actions must pass the current expiry check; recovery verifies the recorded
decision at that stored time, so an approval expiring later does not invalidate
an already authorized intent.

Recovery requires all of the following:

1. Stop every writer for the isolated realm and explicitly confirm quiescence.
2. Call the supported reconciliation API. It compares the exact event ID,
   owner/device/fingerprint, signed approval, hash-chain evidence, and
   before/after store revisions. It can append `applied` or `not_applied` only
   when the domain evidence proves that result.
3. If any store state, lock, temporary file, permit, audit entry, or expected
   revision is inconsistent or ambiguous, leave activation blocked for
   operator review. Do not reset stores, edit JSON, rewrite history, steal a
   live lock, or replay a request.
4. Reopen workers only after reconciliation reports a consistent state and
   every store inspector passes.

The protocol is not a cross-store transaction. Deterministic reconciliation
is based on append-only evidence and existing store recovery APIs; an outcome
that cannot be proven stays blocked. Keep the execution ledger and historical
ambiguous records as evidence.

## I7 compatibility and activation boundary

I8H tests use disposable stores and synthetic Auth0/device keys. They exercise
authorized pairing/binding/read-only grant issuance, wrong identities and
realms, privilege separation, revision conflicts, duplicate events,
revocation, device isolation, crash points, recovery, and the activation
barrier. I7-compatible regression fixtures check that existing binding,
grant, audit, and execution-ledger behavior remains valid. No live I7 store
is used.

This candidate does not deploy the bridge, enroll a real device, exchange a
real token, configure Auth0, start the tunnel, or perform multi-realm worker
cutover. Before live activation, separately authorize the exact rollout and
provide a verified real Auth0 Owner, configured admin scope/client, approved
administrative-key custody, dedicated production realm paths, and validated
device enrollment. Do not promote the synthetic Owner or reuse I7 credentials
or grants.
