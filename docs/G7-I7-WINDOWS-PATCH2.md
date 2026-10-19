# G7 I7 Windows Patch 2

Patch 2 is a certification candidate for PR #40. It has not been deployed to
the active Windows worker or Gateway. Windows worker authorization, TLS,
replay, ledger, identity and revocation behavior are unchanged from Patch 1;
the source timeout adjustment is for the test-only loopback client.

## Regression findings

- **I3:** The RC1 and Patch 1 full suites reproduce the grant-revocation
  spawn timeout. At the failure, Owner authentication and trust revision 1 were
  valid and the device was online, but the queued call returned `CANCELLED` in
  `cancelled_before_delivery`; no command process or durable ledger intent
  existed. The queued route's session differed from the agent's latest
  authenticated session, so the router safely removed work queued on the stale
  session. This is fail-closed session turnover, not a Patch 1 authorization or
  Linux worker regression. The fixture's earlier recovery wait mistakenly
  counted successful polls from before the cancellation, so it could submit a
  second request before the new channel had recovered. Patch 2 waits for three
  successful polls *after* the proven cancellation and requires their session
  to match the router's currently attached session. It permits one *new* Owner
  request with a new ID only when the first is proven cancelled before delivery
  and the ledger is empty. It never retries an ambiguous or delivered operation.
  The Owner test client also closes each local HTTP connection to avoid stale
  keep-alive socket reuse.
- **I4:** RC1 reproduced the Patch 1 HTTP 503 in the full parallel suite. The
  owner read had not reached the agent ledger; the synthetic loopback client's
  poll failed with Node `TimeoutError` code 23 because its fixed 2 second
  request deadline expired. Session teardown was correctly reported as
  `AMBIGUOUS_DISCONNECT`; no result was replayed. The test-only loopback
  deadline is now 15 seconds, and the I4 router test uses its normal 30 second
  default. Diagnostic traces record transport/executor stage names and safe
  error codes without recording payloads or credentials.
- I3 and I4 failures were also reproduced on the I7 RC1 baseline under matching
  full-suite conditions. The observed outcomes are safe, fail-closed behavior;
  Patch 2 corrects the test harness conditions and recovery assertion rather
  than weakening authorization, revocation, TLS, replay protection or recovery.

## Platform-specific test coverage

The seven original Windows failures are platform-bound Gateway/Linux fixtures,
not Windows-agent defects:

- `I3/I4 E2E: Owner approval, durable trust, verified TLS, governed operations,
  restart and revoke` uses Linux durable trust/grant stores and POSIX `fsync`.
- `I4 signed agent loopback routes common governed operations through the owner
  MCP endpoint` requires Linux `/proc` identity and POSIX grant-store modes.
- `staging configuration reader rejects symlinks and writable parent
  directories` requires POSIX symlinks and mode bits.
- `ordinary standalone staging pilot remains available without a test fixture`,
  `standalone Owner cancellation is acknowledged before execution and during a
  live job`, `standalone Gateway grant revocation fences a live job and its
  result`, and `standalone device trust revocation fences a live job and its
  result` require Linux uid/gid isolation, POSIX modes and nonroot execution.

Each now reports an explicit platform reason. Windows equivalents are covered
by NTFS ACL/reparse-point, identity, pairing, executor and cancellation tests;
the Linux-only Gateway and staging behavior remains exercised by the Linux
suite. The 14 other Windows skips were pre-existing optional or Linux-only
cases. No failing Windows behavior is hidden as a skip.

The Windows-native suite exercises DPAPI identity reload and crash recovery,
approved binding persistence, junction and reparse-point escapes, private NTFS
ACL enforcement, locking, capability scope, Gateway-clock validation,
cancellation, revocation and non-replay of ambiguous work.

## Final certification — 2026-10-19

- Windows 11 / Node v24.16.0: **109 tests, 88 passed, 0 failed, 21 skipped**.
  Seven skips are the classified Linux-only cases above; 14 were pre-existing
  optional/platform skips.
- Linux / Node v22.23.2, nonroot `vpsc-g7-staging-agent`: **109 tests, 101
  passed, 0 failed, 8 skipped**. I3, I4, grant/device revocation, cancellation,
  ledger recovery and worker isolation passed. The focused I3 test also passed
  1/1.
- Live state stayed on I7 RC1: Gateway active only on `127.0.0.1:18443`, Linux
  agent active, Windows worker PID 21036 unchanged. G6/Commander and OpenMaus
  services were active and all 15 Docker containers remained present. Patch 1
  and Patch 2 were not deployed; no G6, Docker, Cloudflare or Corporate changes
  were made.
- The read-only Windows ledger contains two successful `read_file` operations
  and no unresolved intent. The available Gateway audit store contains Owner
  decisions but no per-operation record that attributes the previous live
  HTTP 503. That event remains un-attributed and was not replayed.

## Windows worker update and rollback

The observed manual worker command uses:

- Node: `C:\Users\guira\Tools\nodejs\node.exe`
- Worker: `C:\Users\guira\AppData\Local\VPSCommander\g7-i7-windows-pilot\source\packages\vpsc-agent\bin\g7-staging-worker.mjs`
- Config: `C:\Users\guira\AppData\Local\VPSC\G7\agent.json`
- Identity: `C:\Users\guira\AppData\Local\VPSC\G7\identity`
- Ledger: `C:\Users\guira\AppData\Local\VPSC\G7\ledger`
- Approved root: `C:\Users\guira\AppData\Local\VPSC\G7\vpsc-g7-staging-windows\approved-root`
- Staging CA: `C:\Users\guira\AppData\Local\VPSC\G7\staging-ca.pem`

The following is a future, separately approved worker-only rollout procedure;
it was not executed for Patch 2:

1. Extract the selected immutable candidate to a new versioned directory under
   `C:\Users\guira\AppData\Local\VPSCommander\g7-i7-windows-pilot\releases\`.
2. Preserve the current worker files as the rollback version. Keep the existing
   `agent.json`, DPAPI-protected identity, binding, M2M credential, grants,
   ledger, CA and approved root in their current locations.
3. After the owner approves replacement, stop only the recorded G7 Windows
   worker PID and wait for that process to exit. Start the candidate manually,
   unelevated, using the same Node executable and config path:

   ```powershell
   & 'C:\Users\guira\Tools\nodejs\node.exe' '<versioned-release>\packages\vpsc-agent\bin\g7-staging-worker.mjs' --config 'C:\Users\guira\AppData\Local\VPSC\G7\agent.json'
   ```

4. Verify `READY`, `ONLINE`, heartbeat and an authenticated read before
   accepting the worker. Do not configure boot startup.
5. To roll back, stop only the candidate worker and manually start the preserved
   previous worker script with the same config path. Do not restore, reset,
   replace or delete identity, grants, bindings, secrets, ledger or Gateway
   state. If the ledger indicates ambiguous work, keep the worker stopped and
   reconcile that record; never replay it.

Gateway G7, the Linux agent, G6, Docker, Cloudflare and all durable stores remain
outside this worker-only procedure.
