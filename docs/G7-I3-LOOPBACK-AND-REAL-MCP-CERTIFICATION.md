# G7 I3 isolated end-to-end candidate

This document records the local I3 harness. The implementation is an inert development candidate: `gateway/server.mjs` does not import or mount the remote-device MCP handler, the owner pairing API, or the machine ingress. No live Cloudflare credentials, production endpoints, or G6 services are used.

## Exercised path

`packages/vpsc-agent/test/i3-durable-https.integration.test.mjs` runs the following sequence in disposable directories:

1. A separate Node process loads the device's Ed25519 identity and sends only its public key to a loopback pairing ingress. The process signs the returned challenge; the Gateway receives the signature, not private key material.
2. The owner reviews the request through the existing HTTP approval handler using a synthetic, cryptographically verified Owner JWT, same-origin CSRF token, display code, and fingerprint.
3. The trust snapshot and owner decision WAL persist the approved `deviceId`, request, fingerprint, event, and revision. Before each owner MCP call, the route requires a consistent recovery analysis and joins the hashed owner principal, exact intent/outcome, trust transition, revisions, fingerprint, and currently trusted device. A normal active audit writer is accepted only when the analyzer reports an underlying consistent state and no active trust writer; uncertain writer state denies access.
4. The agent establishes an Ed25519-signed session through an HTTPS test edge. The edge uses a short-lived self-signed certificate trusted only by the test client, then forwards to a `127.0.0.1` machine ingress that separately validates a synthetic machine JWT and exact test Client-ID/device-ID binding.
5. The authenticated owner MCP request is routed to the selected device and executed by a built Desktop Commander MCP child. The child reads a disposable file under a fixed allowed root. A reconnect, Gateway store reconstruction, stale-session rejection, and revocation are exercised.

The pairing ingress and HTTPS edge are test harnesses. They are not public Gateway routes or a Cloudflare integration. The machine Client-ID-to-device binding is supplied by an in-memory test map; a durable production binding source has not been designed or enabled.

## Safety behavior

- The owner route advertises and accepts only `read_file`, requires an explicit trusted device, and requires an injected per-device owner authorization policy. The integrated test policy uses the durable approval WAL.
- The local MCP child always has telemetry disabled, receives an inline empty `data:` feature-flag document, and runs with a generated private `HOME` whose Desktop Commander config allows only the canonical approved root. Every feature-flag URL override is rejected because a loopback URL could redirect outside the host. No feature-flag network request is made by this adapter.
- TLS verification failures happen before the test edge receives an HTTP request. Service-token headers are removed at the edge boundary; Owner JWTs are not sent to the machine ingress.
- A transport failure, HTTP 5xx, or malformed response after a request is classified as ambiguous. The agent worker does not replay the task and terminates the session.
- Every successful HTTPS response is checked against the exact route schema. An absent `poll.frame`, malformed heartbeat, or missing result acknowledgement closes the client and is treated as ambiguous.
- The integration harness recreates Gateway stores and listeners in the same test process. Cross-process I2 crash, WAL, trust fencing, and revocation tests remain the evidence for process death behavior.

## Local test commands

Use the project's supported Node 22 runtime, an unprivileged user, and a private temporary directory. The real MCP build can be selected with `VPSC_TEST_REAL_MCP_ENTRY`; the adapter uses an inline static empty feature-flag document and makes no network request.

```sh
node --test gateway/test/*.test.mjs
node --test packages/vpsc-agent/test/*.test.mjs
VPSC_TEST_REAL_MCP_ENTRY=/absolute/path/to/desktop-commander/dist/index.js \
  node --test packages/vpsc-agent/test/i3-durable-https.integration.test.mjs
```

The current environment has GitHub Actions disabled externally. Local test results do not replace hosted checks for a production release.

## Limits

- The route, pairing approval endpoint, machine ingress, and worker are not mounted or started by the production Gateway or agent CLI.
- The test certificate, synthetic JWTs, and service token are disposable test credentials; no live Cloudflare edge or remote device was contacted.
- The Gateway restart is an in-process reconstruction. A process-level I3 restart run is not covered by this one harness.
- The local read adapter checks canonical paths and fixed roots, but there is a filesystem TOCTOU window if another same-user process can mutate the tree between validation and read. The harness uses private disposable directories; this is not a general-purpose filesystem isolation boundary.
- Remote listing, writing, process inspection, and command execution are not implemented by I3. They require a separate I4 policy boundary and tests.
- The existing Desktop Commander full suite still has previously documented Chromium/root and edit-block runner issues; these are outside the focused I3 gates and are not treated as passing.
