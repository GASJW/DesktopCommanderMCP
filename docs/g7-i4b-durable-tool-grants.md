# G7 I4B: Durable tool grants

## Scope

This change adds a development-candidate policy store and enforces it in the
isolated Gateway-to-agent path. It does not mount the remote MCP handler in the
Gateway server and adds no production grant-management endpoint. Hosted GitHub
Actions remain externally disabled; local Node 22 test results are the
available development evidence.

## Grant identity and policy

Each grant binds the SHA-256 digest of the authenticated Owner issuer and
subject, the approved `deviceId`, the approved agent-key fingerprint, one tool,
and a validated scope and resource limit set. The Owner digest is computed as
`SHA-256("VPSC-I4-OWNER-v1\n" + JSON([issuer, subject]))`. Grant records do not
store Owner JWTs, comparison codes, nonces, private keys, or raw tool arguments.

Supported grants are explicit and bounded:

| Tool | Scope | Limits |
| --- | --- | --- |
| `read_file` | A non-root absolute directory | Maximum bytes, length, offset |
| `list_directory` | A non-root absolute directory | Maximum depth and entries |
| `write_file` | A non-root absolute directory; create-only | Maximum bytes |
| `list_processes` | Agent-owned jobs only | Maximum returned jobs |
| `run_command` | A non-root directory and the fixed `count_lines` profile | Runtime and output limits |

No record means no authorization. A policy grant is never inferred from a
device approval, a tool catalogue entry, a client-supplied revision, or a
previous request.

## Durable format

The policy directory must already exist, be owned by the Gateway process user,
and have mode `0700`. The store uses `tool-grants-v1.json` plus an initialization
marker. The JSON snapshot has schema version 1, a global monotonically
increasing revision, derived active-grant state, and a bounded sequence of
hash-linked `grant`, `revoke`, and `authorize` records. Loading verifies the
schema, snapshot-to-record consistency, record sequence and hash chain,
ownership and file modes, size limits, and absence of interrupted temporary
snapshots.

Mutations use an expected revision and unique event UUID. A writer serializes
the next snapshot to a private temporary file, fsyncs it, atomically renames it,
then fsyncs the directory. A new snapshot is accepted only with its matching
initialization evidence. An unexpected revision, malformed or truncated
snapshot, broken hash chain, unsafe path, leftover temporary file, stale lock,
or unknown process identity fails closed.

## Authorization and dispatch

For every call, the Gateway authenticates the Owner, checks current Owner/device
authorization, reads the current durable trust revision and I2 approval receipt,
and then rechecks them immediately before dispatch. The grant store validates
the exact Owner/device/fingerprint/tool binding, request uniqueness, scope, and
arguments. It writes the authorization decision before returning a short-lived
Ed25519-signed capability. The device router obtains this permit before its
transport handoff and releases the permit immediately after the synchronous
handoff.

The agent is configured with its expected device ID, fingerprint, allowed
filesystem root, and pinned Gateway Ed25519 public key. It verifies the
capability signature, expiry, request/device/fingerprint/tool binding,
arguments digest, scope, and resource limits before invoking the local MCP
operation. A policy revision from the transport is never trusted without the
signed capability and the durable Gateway authorization record.

Before returning a completed result, the Gateway synchronously rechecks the
same active grant, the unchanged durable trust revision and I2 approval
receipt, current trusted-device membership, and the exact live session used
for dispatch. If any evidence changed or is unavailable, the Gateway suppresses
the result and returns an ambiguity error instructing the caller not to replay
the operation. This fence runs immediately before the HTTP response; the trust
store and policy store remain separate files and do not form a cross-file
transaction. A trust revocation committed by another process after the final
session check can race the subsequent network write; this small interprocess
window is not represented as an atomic cross-store guarantee.

## Concurrency and revocation

Policy reads, authorization records, grant changes, and result release use
process-identity locks and revision checks. Competing writers cannot silently
overwrite one another. A policy mutation returns `POLICY_BUSY` while an
authorization permit is active; that response means the revocation was not
committed and must be retried by its caller after the active handoff completes.
The permit protects authorization through transport handoff, not through the
entire remote operation.

Once handed to the transport, an operation may already have reached the
device. Revoking a grant or device does not undo a side effect and does not
cancel a job. A late result is not returned as an authorized success. The
caller must not automatically replay an ambiguous write or command. No
destructive cancellation or rollback contract is provided here.

## Crash and operator recovery

After a clean restart, the store reloads and validates the last durable
snapshot. If a process dies during a policy commit, the next process either
loads the atomically renamed and validated snapshot or fails closed on a
temporary file, stale operation/writer/permit lock, missing initialization
evidence, or inconsistent snapshot. It never steals a lock, completes a
partial mutation, or reapplies a grant automatically.

Recovery is intentionally operator-governed. Stop and prevent every Gateway
writer sharing the policy directory, then call
`clearStaleDurableToolGrantLocks()` with explicit confirmations that no policy
writer or recovery process is active. The function holds a durable recovery
lock that makes new store operations fail closed while it inspects locks. It
removes only process locks whose owner identity is proven dead. Active and
unknown locks remain in place. The function never removes temporary snapshots;
a nonzero `temporaryFileCount` means the store remains unavailable for manual
review. Restart with the same policy directory only after lock cleanup is
complete and no temporary evidence needs review, then verify `revision()` and
`list()` and run the focused policy tests. A stale lock does not itself prove
whether a mutation reached disk; compare the validated snapshot revision and
records with the operator's change event before deciding whether to issue a new
grant mutation. This is an offline library operation, not a production
management endpoint.

## Development certification limits

The local harness uses synthetic Owner and machine credentials, temporary
directories, loopback transport, and generated test keys. It demonstrates
Gateway enforcement and real local file operations in that isolated context;
it does not certify key provisioning, policy onboarding, a live device, or a
production deployment.

Observed with Node 22.23.2 as a non-root user and private `TMPDIR` on
2026-10-17:

- Gateway regression suite: 319 tests, 317 passed, 0 failed, 2 skipped.
- Agent regression suite: 77 tests, 75 passed, 0 failed, 2 skipped.
- Subprocess tests killed a policy writer before atomic rename; the previous
  snapshot remained intact, stale locks were removable only through explicit
  recovery confirmation, and temporary snapshot evidence remained fail-closed.
- A Gateway race test revokes a device after router response acceptance but
  before the HTTP result fence; the result is suppressed as ambiguous.
- I3/I4 HTTPS loopback integration completed Owner approval, signed grant
  authorization, a real read from a disposable file, restart, and revocation.

GitHub Actions are disabled externally, so hosted CI is
`BLOCKED_EXTERNAL_GITHUB_ACTIONS`; production release remains gated on hosted
CI, operational key management, and an explicitly reviewed deployment
procedure.

## Handoff: I3B / I4C

The next isolated engineering slice should establish the following contracts
before any VPS pilot:

1. **Durable machine identity:** bind one device ID to the persistent Ed25519
   public-key fingerprint; protect the private key in owner-only storage; use a
   machine authentication credential distinct from Owner JWTs; reject replayed
   challenges and stale sessions after restart or revocation.
2. **Cooperative cancellation:** bind cancellation to the original request and
   agent job; distinguish cancellation before receipt, while running, after
   completion, and after ambiguous transport loss. Cancellation after receipt
   cannot certify rollback. Do not replay writes or commands after an
   ambiguous outcome.
3. **Isolated VPS pilot:** use a dedicated non-root account, private test
   directories, synthetic identities and keys, and a loopback or explicitly
   approved staging endpoint. Record the exact device ID, policy revision,
   operation result, and revoke/restart outcome. Keep production services,
   G6, real endpoints, and credentials outside the pilot until separately
   approved.

Local acceptance for that slice should include process restart with identity
continuity but no session reuse, signature and replay rejection, cancellation
state tests, revocation during an active job, and a real read from a disposable
file. Any write or command test must demonstrate the no-replay rule after
SIGKILL or transport ambiguity. This handoff is a development specification;
no I3B/I4C pilot or production connection was started in I4B.
