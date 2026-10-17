# G7 I3B / I4C machine identity and cancellation

This document describes the isolated G7 candidate implementation. The machine
ingress and Owner MCP handler remain test-only modules; they are not imported by
the production Gateway. Hosted GitHub Actions are externally disabled, so the
evidence below is local Node 22 testing only and is not a production release
certification.

## Identity contract

The agent keeps its Ed25519 private key in its owner-only identity store. It is
never sent to the Gateway. The Gateway trust snapshot persists only public key
material, device ID, fingerprint, and transition history. Agent sessions,
challenges, and signed-frame sequence counters live only in memory and are
created again after restart. A restarted agent proves possession of the same key
and receives a new session ID.

Machine authentication and Owner authentication are separate:

1. The machine Access JWT identifies the configured M2M Client-ID.
2. The durable machine-binding snapshot joins that Client-ID to the exact
   `deviceId`, public-key fingerprint, Owner principal digest, I2 approval
   receipt, trust revision, and v3 machine-binding audit event.
3. The Gateway verifies the Ed25519 challenge and every signed request frame,
   including its route, body digest, session, and monotonic sequence.
4. The Owner Access JWT independently authorizes an Owner MCP request. It does
   not authenticate the machine.

`machine-bindings-v2.json` is checked against the complete validated v3 machine
binding history in the Owner audit WAL. The two stores are not atomic together.
The protocol is intent → binding snapshot → accepted WAL outcome. A pending
intent blocks lookup and startup. A missing snapshot with any binding history,
or any one-to-one mismatch between WAL and snapshot, fails closed; it is never
recreated empty. Reconciliation does not replay a bind.

Identity envelope v2 is retained as `legacyDeviceBinding`, not presented as a
fully Owner-bound identity. The HTTPS client refuses that partial provenance
until the explicit v3 binding migration writes the Owner digest, binding event,
and binding revision. No hostname-only enrollment exists.

## Dispatch, revocation, and response fences

Before handoff, the Owner MCP handler obtains both the durable tool-grant permit
and a short-lived trust dispatch permit. The trust permit names the device,
authenticated session, and exact current trust revision. It remains held only
until the router's transport handoff resolves. Trust mutation uses the same
cross-process operation gate and returns retryable `TRUST_BUSY` while a live
handoff permit exists. A dead or unverifiable permit blocks operations until
explicit I2 reconciliation; it is never stolen automatically.

After the device result arrives, the HTTP response is emitted inside
`withCurrentSession()`, which takes the same trust operation gate and verifies
the exact session and revision while the synchronous response write runs. If
trust revocation wins first, the response is suppressed and reported as
ambiguous. If the response fence wins first, the response is written before a
later trust mutation can commit. Other verified active dispatch permits may
coexist with this response fence; each holds a read authorization for the same
trust revision and prevents trust mutation. Stale, unknown, malformed, or
foreign permit evidence still blocks the fence. Grant authorization has a
separate gate and permit; no cross-file atomicity is claimed. A final response
must pass both fences.

Cancellation is bound to request ID, owner digest, device ID, and session ID:

| State | Observable result |
| --- | --- |
| Cancel before queueing or while queued | Known no-dispatch cancellation |
| Cancel after transport handoff | Ambiguous unless the authenticated agent confirms it stopped before execution |
| Agent reports completion before cancel | Completed; no rollback |
| Timeout, process death, or transport loss after delivery | Ambiguous; no automatic replay |
| Grant revocation during a running job | Poll fence asks the agent to cancel; any unproved completion stays ambiguous |
| Device trust revocation during a running job | Session and result are fenced immediately. The old session may be unable to receive a later cancellation control, so the remote job can continue until its own timeout/termination. The Owner gets an ambiguous result; no rollback or replay is claimed. |

The last case is an explicit limitation of session revocation and cooperative
cancellation sharing one authenticated channel. This implementation guarantees
that a result from the revoked session cannot become an authorized success; it
does not guarantee immediate remote process termination after device revocation.

## Lock recovery

Trust writer, operation-gate, and dispatch-permit locks are inspected through
`analyzeOwnerPairingRecovery()`. Active or unknown lock owners block recovery.
For dead lock owners, the operator must first establish that the Gateway and
device writers are stopped, then call the existing explicit
`reconcileOwnerPairingRecovery()` with `operatorConfirmedNoActiveWriters: true`.
Reconciliation rechecks the WAL, trust snapshot, lock owner identity, lock
digests, and trust revision while holding the recovery mutex; it removes only
dead lock records and does not alter trust or reapply a decision. A validated
temporary snapshot beside a dead trust-writer lock is removed only by this
explicit reconciliation after its recorded inode/owner/mode/size still match.
An orphan temp file without a dead writer lock, changed evidence, or an
active/unverifiable owner blocks reconciliation and must be preserved for
manual investigation. Never delete lock directories by hand as a normal
recovery step.

The separate `.machine-bindings-writer.lock` is deliberately not auto-cleared
by the I2 trust/WAL reconciler. If its owner process is killed, the binding
store remains unavailable. Recovery is manual and fail-closed:

1. Stop every process that can open the candidate binding store (the test
   Gateway/loopback harness, machine ingress, and any Owner binding handler).
   Record the process list and verify each known writer PID is absent; keep the
   test Gateway stopped so a new writer cannot start during recovery.
2. Use `inspectDurableProcessLock(directory,
   '.machine-bindings-writer.lock')` read-only. Continue only when the lock is
   present, `owner.kind` is exactly `machine-bindings-writer`, its owner
   identity is verified `dead`, and its digest is captured. Active, unknown,
   malformed, or ownerless locks are preserved.
3. With all writers still stopped, call
   `removeDeadDurableProcessLock({directory,
   name:'.machine-bindings-writer.lock',expectedDigest})`. Proceed only if it
   returns `true`; if it throws or returns `false`, stop and preserve all
   evidence. The API removes only the same dead lock record; it does not change
   the binding snapshot or WAL.
4. Reopen the binding store with the real I2 receipt and complete Owner audit
   history readers. Require construction and `revision()` to succeed, then
   resolve every recorded Client-ID and compare its device, fingerprint,
   Owner, I2 receipt, trust revision, and completed binding outcome. Also run
   `analyzeOwnerPairingRecovery()` against the I2 WAL and trust store. A
   pending binding intent, mismatched or missing snapshot, inconsistent I2
   state, or any uncertainty blocks use; preserve evidence for operator
   investigation and do not recreate or edit the snapshot.
5. Restart only the isolated candidate harness after all checks succeed.

The lock-removal API verifies process death and the lock digest, but cannot
prove that an operator has quiesced every possible writer. The process
inventory and prevention of new writers are therefore required operational
evidence, not an automatic guarantee. No live or production binding directory
was used for this recovery procedure.

The Owner audit hash chain is tamper-evident under the private directory and
process permissions. It is not an Owner signature or protection against a
same-UID attacker who can rewrite the whole directory.

## Test scope

All local tests use Node 22 as a non-root user, private temporary directories,
synthetic keys/tokens, and loopback-only ingress. The end-to-end harness performs
a real read through the local Desktop Commander MCP child and checks restart,
grant revocation, trust revocation, ambiguous outcomes, and non-replay behavior.
It does not enroll real devices, use production credentials, change systemd,
configure Cloudflare, enable the production Gateway endpoint, or connect to G6.
