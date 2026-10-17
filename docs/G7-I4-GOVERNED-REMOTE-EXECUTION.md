# G7 I4 governed remote operations

I4 extends the inert I3 owner MCP candidate with a finite set of bounded operations. This is development code and a test harness; `gateway/server.mjs` still does not import the owner device handler or machine ingress, and the agent CLI still does not start a remote worker.

## Exposed operation contract

| Tool | Contract |
| --- | --- |
| `read_file` | Bounded valid UTF-8 text read from an `O_NOFOLLOW` descriptor opened beneath the fixed root; rejects malformed UTF-8, preserves the MCP text result and line pagination contract. |
| `list_directory` | Iterator-based listing, maximum depth 2 and 200 total entries; output contains relative names and entry types, and never follows symlinks. |
| `write_file` | Text only, at most 64 KiB, `mode: create` only. The destination is created atomically without replacing an existing file; no append or rewrite. |
| `list_processes` | Lists only the agent's last 32 fixed-profile jobs. It never invokes Desktop Commander's host-wide process listing or accepts a PID. |
| `run_command` | Linux-only profile `count_lines`, mapped to `/usr/bin/wc --lines` with the already-open approved file as stdin, `shell:false`, fixed cwd and minimal environment. It accepts no command string or arbitrary arguments. |

The upstream Desktop Commander `read_file` API accepts a pathname and reopens it after validation. The governed executor therefore reads through the pinned file descriptor itself; a concurrent rename or symlink replacement cannot redirect the read. The separate I3 leg of the integrated TLS test still exercises the actual Desktop Commander stdio MCP reader. This executor returns the same MCP text content shape, with bounded strict UTF-8 decoding and line pagination; invalid UTF-8 is recorded as a failed operation instead of being silently replaced.

The Gateway requires two independent callbacks before dispatch: owner-to-device authorization backed by the I2 decision/trust evidence, and owner/device/tool authorization (`authorizeTool`). A missing, false, or failing tool policy denies or fails closed. The test policy is synthetic and does not provision production grants.

## Identity, idempotency and durable execution record

The Gateway creates a fresh random `requestId` for each authorized tool invocation. The JSON-RPC ID is only response correlation; it is not a permanent idempotency key. Router, worker, and executor never retry an ambiguous execution. A caller's later tool invocation is a distinct operation, so create-only writes still cannot overwrite existing files and the other current operations are reads. Any future non-idempotent operation needs a client idempotency contract before it can be added.

The Gateway requires a matching durable I2 owner/device approval receipt and a stable trust revision before and after the owner/tool checks. It sends the approval `eventId`, fingerprint, approval revisions, current trust revision, a digest of the verified owner principal, and a configured tool-policy revision with the operation frame. The Linux agent binds that context to both ledger records. JWTs and owner subjects are not forwarded or written. The Gateway-side tool-policy revision must be changed whenever its policy definition changes; this candidate does not provide a production grant editor or independent policy store.

Before each operation, the agent writes and `fsync`s a version 2 JSONL intent; it `fsync`s the matching outcome before returning the result. Each record includes the device `requestId`, `deviceId`, tool, argument hash, owner digest, approval event/fingerprint/revisions, policy revision, timestamp, outcome status, result hash and optional exit code. File contents, command output, paths, JWTs, service tokens, and private keys are not stored. The ledger is limited to 4 MiB and 20,000 records and does not rotate; new operations are rejected before dispatch if the WAL cannot reserve space for a matching outcome. Earlier I4 ledger schemas fail closed.

The state directory must be an existing directory owned by the agent user with mode `0700`; no ancestor may be a symlink, and every writable ancestor must be root-owned with the sticky bit set. The state directory inode is pinned for the executor lifetime. The ledger is mode `0600`. The approved operation root is also pinned by an open directory descriptor; nested directory traversal and create-only writes are relative to that descriptor and reject symlinks and writable subdirectories. A Linux durable process lock serializes writers. A corrupted or truncated ledger, stale lock, unresolved intent, or ambiguous outcome blocks executor startup. There is no automatic replay, lock theft, WAL repair, or history clearing.

## Timeout, cancellation and recovery

`run_command` is bounded to one command at a time, 10 seconds by default, and 16 KiB combined stdout/stderr. Worker stop signals are passed to the executor; the command process group receives `SIGTERM` and then `SIGKILL`. A test-only timeout fixture uses a real `/usr/bin/sleep` process to verify process-group termination; production stays fixed to `/usr/bin/wc`. HTTP caller cancellation can remove a task while it is still in the Gateway queue. Once the agent has polled a task, cancellation is ambiguous and is never replayed. A timeout, cancellation after launch, or failed outcome write is not reported as success. These ambiguous local outcomes remain in the ledger and block later work until operator review. Result delivery uncertainty after a durable local outcome never retries that request; a later distinct request can proceed after a clean worker restart.

For a disposable development state directory, an operator can inspect it without mutation:

```js
import { analyzeI4ExecutionRecovery } from './packages/vpsc-agent/src/governed-executor.mjs';
const report = analyzeI4ExecutionRecovery({ ledgerDirectory: '/absolute/private/state' });
console.log(report);
```

If the report contains a lock, first stop every agent process known to use that state directory. Inspect its owner PID and boot identity with `inspectDurableProcessLock`, then independently verify that no process with that identity remains. A dead lock can only be removed using the existing `removeDeadDurableProcessLock` function with the observed lock digest. Re-run the analyzer afterwards. If it reports `ambiguous-intent` or `ambiguous-outcome`, preserve the ledger and affected filesystem evidence; this version intentionally has no operator command that declares the effect applied or clears the history. A fresh store must not be used to hide unresolved effects.

The Gateway has no remote cancel frame yet. Revocation fences the Gateway session and rejects late responses, but an operation already delivered to the agent may finish before the agent observes loss of its session. Its result will be rejected by the Gateway; the operation ledger prevents replay. This is a development limitation and does not certify revocation as a rollback mechanism.

## Verification performed

Using Node `v22.23.2`, UID `65534`, and a private short-path `TMPDIR` under `/var/tmp` (the host `/tmp` remains mode `0700`):

- `gateway/test/*.test.mjs deploy/test/*.test.mjs`: 325 tests, 323 passed, 0 failed, 2 skipped (Windows DPAPI and optional host integration).
- `packages/vpsc-agent/test/*.test.mjs`: 74 tests, 73 passed, 0 failed, 1 skipped (Windows DPAPI).
- The agent suite was run with `VPSC_TEST_REAL_MCP_ENTRY` set to the built Desktop Commander `dist/index.js` entry in the isolated I3 worktree; without that variable, the real-process MCP leg uses its test fixture instead.
- Integrated I3/I4 TLS test completed real Owner Only pairing, durable I2 receipt binding, verified TLS/M2M transport, a real Desktop Commander stdio MCP read, then I4 governed `read_file`, directory listing, create-only write, `count_lines`, and agent-job listing over the same authenticated device route. The I4 ledger recorded the real approval `eventId`, fingerprint and trust revisions without content or secrets.
- I4 loopback integration read a 32 KiB disposable file, listed the directory, created a file once, rejected duplicate creation, ran `count_lines`, listed only the agent job, and denied a removed tool grant.
- A real governed-executor subprocess was SIGKILLed after its create-only write and durable intent but before its outcome. The stale lock remained, explicit dead-lock clearance exposed `ambiguous-intent`, and executor startup refused to replay.
- Tool execution records include the durable pairing event, fingerprint, trust revisions, owner digest, and policy revision; the ledger contains no owner JWT, raw owner subject, file contents, or command output.
- Cancellation before agent polling removes the queued tool task. Cancellation after polling returns an ambiguous result, and revocation continues to fence any late agent response.
- Two non-root agent processes raced the same stable request ID; one mutation committed and only one intent/outcome pair was recorded.
- Path substitution tests replace a validated pathname with an in-root symlink between validation and use; both `read_file` and `count_lines` continue against the already-open inode.
- A disconnected owner request paused inside asynchronous tool authorization is not dispatched to the device. Invalid UTF-8 file bytes are rejected and recorded as a failed operation.

GitHub Actions are externally disabled for this repository. Local tests are development evidence only; hosted CI and production release gates remain `BLOCKED_EXTERNAL_GITHUB_ACTIONS` / not certified. No live endpoint, credential, service, or G6 production directory is used by these tests.

## Remaining limits

- The fixed command profile supports Linux only. Other platforms fail closed.
- Per-tool grants are injected by the mounting application; there is not yet a production grant editor or durable tool-scope store.
- The owner route, I2 recovery API, machine ingress, and remote worker remain unmounted in the production Gateway/agent CLI.
- In-flight operation cancellation on Gateway revocation is not guaranteed, and ambiguous local history has no automated reconciliation path.
- The I4 loopback test is HTTP on `127.0.0.1`; the integrated I3/I4 TLS harness is local and uses generated test keys. No real remote device or production endpoint is activated.
- The governed `read_file` path returns bounded UTF-8 MCP text; it does not invoke Desktop Commander's path-based file handler because that handler reopens paths after validation. The I3 leg separately verifies the real Desktop Commander MCP read path, but richer encoding and metadata behavior from that handler is not part of the I4 governed contract.
