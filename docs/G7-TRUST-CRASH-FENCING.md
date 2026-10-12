# G7 durable device trust — crash/revocation fencing certification

This is a **development-only hardening delta** stacked on Draft PR #21 (`feat/g7-durable-trust-records`). It does not import the trust store into the Gateway, change Cloudflare, enable agent ingress, authorize Root/Admin or modify the G6 production unit.

## Reproduced RED before changes

Seven isolated test scenarios: five original failure modes plus a directory reincarnation failure, alongside an extra real-subprocess crash drill. In the unmodified PR #21 candidate:

- A `.trusted-devices-writer.lock` left behind after a crash did not prevent a **freshly restarted server** from loading trusted identities and beginning sessions. The live facade also ignored the lock.
- A trust record revoked by a second process still existed as a **live authenticated session** on a stale first instance; `isLiveSession`, `heartbeat` and signed frame checks needed disk consistency fencing.
- The trust store accepted a symlink in an ancestor path and a hard-linked trust snapshot.
- Replacing a directory after initialization, especially when inode numbers were rapidly reused, could leave the old facade treating the new directory as authoritative.

These are observed defects in a **Draft candidate**, not observed incidents in the G6 production Gateway. They were caught by standalone test cases before any deployment.

## Minimal corrections

1. **Startup lock gate**: refuse opening any trust registry when `.trusted-devices-writer.lock` is present, even if the snapshot JSON parses correctly. A lock is intentionally *not* stolen or removed automatically.
2. **Session freshness gate**: before every registry operation and trust mutation, validate the store directory, absence of lock and the authoritative disk snapshot revision plus trusted-device contents. If any difference or read error is found, poison the instance permanently. Existing sessions cannot continue after an externally observed revoke or writer lock.
3. **Private storage path**: reject symlinks in any ancestor, nonexistent unprovisioned parent paths, unexpected owner/mode (private `0700`) or a replaced directory. The store creates only its final private directory during initial construction, never recreates a missing directory while running.
4. **Trust snapshot path**: require one hard link, correct process UID, regular file, `0600` and existing `O_NOFOLLOW` on read.
5. **Directory reincarnation**: compare POSIX `dev`/`ino` and nanosecond inode birth time (`birthtimeNs`) between initialization and each session operation to detect rapid inode reuse on supported local POSIX filesystems. Refuse startup when the filesystem does not expose a nonzero directory creation timestamp. **Portability gate**: validate the target filesystem before deploy, and reject unsupported filesystems.
6. Update one existing PR #21 test to accept the new fail-closed error message instead of only the raw OS `EEXIST`.

## Certification and limitations

- Focused added tests cover fake and **real subprocess** writer death, stale lock on restart, active-session invalidation after another process revokes, exclusive lock blocking reads, symlinked ancestor, file with extra hard link, replaced directory.
- The first five tests **failed** before the delta and passed after it. The directory-replacement test was added and proved RED before its fix. All seven now pass in Node 18 and Node 22.
- Legacy PR #21 trust tests remain passing, including key restoration, revocation persistence, session reset, corrupt snapshot, stale writer and revision exhaustion.
- On each routed event the synchronous on-disk snapshot must be read/validated, which incurs bounded filesystem IO (snapshot max 128 KiB) and may affect throughput. Do not silently remove this check without a replacement inter-process invalidation mechanism.
- A disk check **cannot atomically fence an operation already in progress** while another process revokes; **strict single-writer/single-router deployment or a shared transactional/lease boundary remains mandatory** before production. Protect the actual device routing against in-flight revocation races using the approved architecture; do not assert complete linearizability from this PR alone.
- Directory inode birthtime is a POSIX/Linux local filesystem assumption. Snapshot JSON still has no independently anchored tamper-proof signature or monotonic counter; a same-UID/root attacker can still forge records. Admin audit WAL from PR #28 does not yet atomically bind its `intent/outcome` to trust snapshot revision. Neither component is live.
- Intent reconciliation, operator-run lock recovery, backup/recovery drills, integrity anchoring and clean deployment rollback remain independent RED gates. No automatic trust repair, replay or lock theft.
- `gateway/server.mjs`, DNS, Cloudflare Access policies, owner API, systemd and the productive G6 checkout are unchanged.

## Test procedure

```sh
node gateway/test/trust-crash-fencing.test.mjs
node gateway/test/durable-trust.test.mjs
node --test gateway/test/*.test.mjs deploy/test/*.test.mjs
```

In this VPS tool environment, the integrated Node18 suite historically reports one unrelated and pre-existing failing `vpsc-agent doctor` child-process test. It should be recorded without suppression and not attributed to trust-fencing changes. GitHub protected CI remains the independent cross-platform gate.

**PR stays Draft** until review of all production admission gates; merge only under the user's protected-PR workflow once a particular dependency is demonstrably safe.
