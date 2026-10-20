# I8E — Real Auth0 Owner bootstrap runbook

**Status: design only.** This runbook does not authorize a live migration or
activation. The current staging runtime still fixes its Owner to the synthetic
Cloudflare Access principal, and the ChatGPT bridge intentionally rejects that
principal. No Auth0 token, live store, service, or tunnel was used or changed.

## Decision

| Design | Safety and cost | Decision |
| --- | --- | --- |
| A. Transfer the current Owner across existing stores | Would have to coordinate immutable machine-binding history, its exact Owner audit join, the hash-chained grant log, Owner authority, and active execution permits. There is no shared transaction/recovery API. Rewriting owner IDs or digests would invalidate existing evidence. | Reject for I8E. |
| B. Bootstrap a real Owner in a new isolated G7 realm | Leaves the I7 state and audit chains byte-for-byte untouched. Reauthorizes devices and grants in a new state root; no old Owner or grant is inherited. Requires a separate runtime/authority implementation before activation. | Select. |

The new realm must have a distinct versioned runtime directory, configuration,
storage root, loopback listener, and service identity. It must not mount any I7
audit, binding, grant, trust, policy, or execution-ledger directory. Keep the
existing I7 deployment running independently until a separately authorized
cutover.

## Identity authority

The canonical Owner is the pair `(Auth0 issuer, Auth0 subject)`. Verify the
signature using the configured public JWKS and enforce the exact issuer,
resource audience, allowed CIMD client claim (`azp` or `client_id`), expiry,
and required scope. Do not identify the Owner by email, tunnel possession, a
client-supplied assertion header, or a mapping to the synthetic staging Owner.
Do not store the raw subject in Git or ordinary logs; persist a domain-separated
Owner ID and digest in the new realm's durable records.

`g7.read` authorizes only the ChatGPT `read_file` path. It is not sufficient to
bootstrap an Owner, pair a device, or mutate grants. The Auth0 tenant currently
has no verified Owner-administration scope or approval endpoint. Before a live
bootstrap, implement a separate, explicitly approved Owner-management authority
(for example, a dedicated `g7.owner` scope and client) and verify it with a
signed token. Do not add that scope or client as part of this offline task.

## Isolated bootstrap protocol

The steps below define the required protocol; the activation journal and
Auth0 Owner-management API are **not implemented yet**.

1. **Prepare, offline.** Create a new empty state root and a versioned runtime
   config. Validate that every store path is unique and outside the I7 roots.
   Keep the listener closed. An existing or non-empty target root is a conflict,
   never an invitation to overwrite or import data.
2. **Prove and approve the Owner.** Verify a signed Auth0 Owner-management
   token against the exact issuer, audience, client and administrative scope.
   Require an explicit approval action and `expectedRevision=0`. Append one
   hash-chained activation intent/outcome to the new realm's Owner authority
   journal. A duplicate event is idempotent; a different Owner or stale
   revision is denied. `g7.read` alone must fail.
3. **Reauthorize devices.** Pair each existing Linux/Windows device into the
   new empty trust store using its existing Ed25519 public identity and a fresh
   proof. Require explicit Owner approval of the exact device ID and
   fingerprint. Do not rotate local identity keys. Add new binding records and
   matching Owner audit events through their supported APIs; never copy or
   rewrite old binding records.
4. **Issue least-privilege grants.** Create a fresh `read_file` grant for each
   approved device and approved root. Do not copy old `ownerDigest` grants or
   inherit write/command permissions. The new policy revision begins from the
   new store's own history; the old grant revision and hash chain remain in I7.
5. **Check the activation barrier.** Before opening a listener, require a
   committed Owner record, no pending Owner/binding/grant intents, exact
   snapshot-to-WAL reconciliation, valid trust and binding receipts, and the
   expected store revisions recorded in the realm activation journal. Any
   mismatch, missing record, lock, or incomplete step leaves the realm offline.
6. **Activate only after separate approval.** The first effective principal in
   the new realm is the verified Auth0 `(iss, sub)` recorded in its Owner
   journal. The synthetic Owner is absent from that realm. The existing I7
   runtime remains independently authorized until its separately approved
   shutdown; this bootstrap does not revoke or rewrite it.

The existing device execution ledgers stay with their agents and are not copied,
cleared, or replayed. The historical ambiguous request
`737c0748-e755-4b85-a1fd-75bc5d0b5787` must never be resubmitted. New MCP calls
must use fresh request IDs; an incomplete or ambiguous result remains
fail-closed.

## Revocation and recovery

Revocation in the new realm must append an Owner-revoked event with
`expectedRevision`, invalidate active Owner sessions and permits, and fence
late MCP results. Disabling an Auth0 user alone is insufficient because an
already issued access token can remain valid until expiry. The old I7 realm is
not changed by a new-realm revocation.

Bootstrap is not a cross-store transaction today. The missing activation
journal must make each phase append-only and revision-bound. On a crash, startup
must keep the listener closed, inspect all intent/outcome records, and either
resume a uniquely provable idempotent provisioning step or require operator
reconciliation. It must never truncate a WAL, reset a revision, auto-steal a
lock, repeat an MCP operation, or treat a partial bootstrap as active. Concurrent
bootstrap attempts must serialize on the expected revision; only one can win.

## Required certification before implementation is deployable

Use synthetic Auth0 keys and entirely disposable state to prove:

- valid signed Owner token and explicit approval; wrong subject, issuer,
  client, audience, scope, signature, expiry, or unknown `kid` denied;
- `expectedRevision` conflict and duplicate transition behavior;
- old I7 binding/grant/audit bytes and revisions remain unchanged;
- same device key is reauthorized only after fresh proof and exact fingerprint
  approval; cross-device access is denied;
- new realm grants authorize only `read_file` under the approved root;
- trust, binding, grant, and Owner audit histories reconcile after every phase;
- injected crash after every intent/store/outcome/activation write leaves the
  listener closed and deterministic recovery without deleting evidence;
- Owner revocation fences new work and late responses;
- concurrent bootstrap and worker activity cannot bypass a revision fence;
- no historical MCP request is replayed and no duplicate remote execution occurs.

Existing I8D JWT, scope, device-isolation, grant-revocation, no-replay, audit,
and Linux crash-recovery tests cover portions of these invariants. They do not
certify the missing Owner-management API or multi-store activation journal.

## Live approval boundary

This task authorizes offline implementation and synthetic tests only. A new
explicit Owner authorization is required before any of the following: changing
Auth0 scopes/client grants, exchanging a real OAuth token, provisioning a
real Owner record, creating live stores or device bindings/grants, starting a
new Gateway/service, switching the tunnel, or stopping the existing I7 service.

**Current readiness:** architecture is ready for Owner review; implementation
and live activation are not ready. The safe next implementation is the isolated
Owner authority/journal and its management verifier, followed by the test matrix
above. No I7 store migration is planned.
