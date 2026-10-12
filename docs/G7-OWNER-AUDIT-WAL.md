# G7 Owner Pairing Decision WAL — isolated storage candidate

**State:** development-only, unmounted and not used by the productive G6 Gateway. This is a stacked delta on Draft PR #21 (`feat/g7-durable-trust-records`). The owner approval HTTP API is separately staged as Draft PR #26 (based on PR #25). This candidate has not been integrated with either HTTP routing or the production device trust database.

## Why it exists

The G6 request journal stores sanitized tool/HTTP metadata, not an authoritative, fail-closed record of owner approval decisions. The PR #26 owner HTTP module requires `auditWrite(event)` to return exactly `true` **only after the write is durable**; otherwise it refuses to authorize a trust mutation. This module implements a POSIX local append-only WAL backend for that contract. It does not authorize any device or root grant itself.

## Interface

`createDurableOwnerAudit({ directory })` returns a frozen object with:

- `auditWrite(event)`: synchronous, returns `true` after complete JSONL record write and POSIX `fsync`. PR #26's `await auditWrite(event)` also works. Unknown or secret-bearing keys are rejected.
- `inspect()`: public metadata `{sequence,pending,bytes}`, with no underlying owner identifiers or codes.
- `close()`: cleanly closes the file and releases the exclusive lock if there has been no ambiguous storage failure. Closing an incomplete intent does not authorize anything; the next startup will refuse to proceed.

The accepted event fields are strictly: `event=g7_owner_pairing`, `version=1`, `at` canonical UTC ISO time, `eventId` UUID v4, `operation=approve|reject`, pseudonymous `ownerId` and `targetId` as 24 hexadecimal digits, `phase=intent|outcome`, plus `outcome=accepted|denied` only for an outcome. The full code, nonce, JWT, email, private key, request contents and headers are never accepted or written.

## Storage rules and failure semantics

- Requires POSIX filesystem and private absolute, normalized directory owned by the executor UID with mode `0700`. Refuses symlinked directory components, missing parents, regular file replacement, hard-linked log files, wrong UID and wrong file mode.
- Creates `.owner-decisions-writer.lock` atomically using `mkdir(0700)` **before opening the log**. Exclusive for the lifetime of the process; another writer or a post-crash stale lock is rejected without automatic lock theft. File `owner-decisions-v1.jsonl` is `0600`, owner-only, `O_NOFOLLOW` and 4 MiB bounded.
- First creation fsyncs file and directory; every append uses explicit positioned writes, checks filename/inode/mode/size, validates the entire prior hash chain via positioned reads, and fsyncs the file before acknowledging. A failed IO step permanently poisons that writer, preserving its lock for manual investigation.
- Each line has `version,seq,previous,event,hash`. The hash is SHA256 over an explicit domain plus canonical JSON of sequence, preceding hash and sanitized event. Startup replays the full bounded stream, rejecting invalid JSON, truncated tails, malformed/duplicate sequence, inconsistent hashes and unmatched outcomes. Any unclosed intent forces **manual reconciliation** before starting another writer. There is **no automatic replay of trust mutations**.
- Permitted event ordering is one outstanding pairing decision at a time. A second intent cannot race a pending outcome. Successful outcome requires matching eventId, owner, target and operation. If outcome writing fails after a trust mutation, callers must **not** interpret 503 as proof of no mutation.
- Read/write validation failures and store tampering stop all subsequent operations. There is no silent rotation, truncation, re-creation or repair. A full WAL (4 MiB) requires operator-led archive/rotation with independent evidence.

## Limitations and gates still RED

1. No production storage path/permissions or systemd service integration; no Cloudflare Access change, no endpoint exposed, no owner API `auditWrite` injection, and no calls to Fhinck or any external system.
2. No deployed crash-recovery/operator reconciliation procedure or separately durable decision state tying an outcome to the actual PR #21 trusted registry revision; those are required before approving live devices.
3. A hash chain in the **same writable file** detects accidental corruption and many tampering cases, but does **not** cryptographically stop a malicious local owner/root actor from recalculating hashes or removing a valid suffix and starting afresh. For higher assurance, anchor sequence/hash in an independent trusted store or ship records to append-only remote logging.
4. POSIX `fsync` and directory `fsync` request durability from the local OS/filesystem; they cannot guarantee integrity against hardware lies, storage controller failure, or Byzantine admins. Tests exercise actual fsync calls but do not emulate power loss.
5. The temporary per-process lock has no automatic stale-lock recovery by design. Multi-host distributed FS/NFS, external file editors with the same account, cross-host synchronization and concurrent cross-service deployment are unsupported.
6. In particular, this WAL is **not** a complete privileged root-command audit and does not satisfy broader admin-forensics requirements. The G6 journal remains metadata-only and the agent privilege model is separate.

## Testing

Focused Node tests cover schema rejection, secret exclusions, permission/symlink refusal, serial intent/outcome, restart, stale/concurrent writer locks, truncated/corrupt tail, hash tampering (including *unchanged file length* during a live writer), and failure poisoning. Validate with:

```bash
node gateway/test/durable-owner-audit.test.mjs
node --test gateway/test/*.test.mjs deploy/test/*.test.mjs
```

The Codex CLI authenticated successfully but its enforced `bwrap` sandbox failed to create the loopback network interface (`RTM_NEWADDR: Operation not permitted`). Codex made **no changes**, and the owner audit candidate was implemented with the Commander in the same isolated worktree; no sandbox bypass was attempted. The existing full-suite baseline had a failure in the unrelated agent CLI doctor test under Node18 on this VPS before the new WAL changes, so any test result must distinguish that pre-existing environment issue.

**Do not merge as a production enablement PR.** The next safe integration is a separate PR for the owner HTTP boundary + durable PR #21 registry, with an explicit end-to-end failure/restart certification and abort/rollback gate.
