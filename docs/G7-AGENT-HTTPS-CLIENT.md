# G7.2h — Outbound HTTPS agent client and Cloudflare Service Token envelope (inert)

## Purpose

Prepare the future Windows/Linux `@gasjw/vpsc-agent` to connect to a **separately protected Cloudflare machine Access origin**, not the previous RDC server, and without sharing the owner's Access session or Gateway token. This does not make the present agent CLI connect or publish npm.

## Source

- `packages/vpsc-agent/src/https-client.mjs` creates an outbound client only when the locally pinned Gateway URL is **HTTPS on the exact configured hostname and default 443**. HTTP, localhost, private/IP hosts, credentials embedded in the URL, paths, query strings, fragments, alternate hosts and custom ports are refused.
- It sends the per-agent `CF-Access-Client-Id` and `CF-Access-Client-Secret` headers **to that pinned HTTPS hostname** and forbids redirects. Cloudflare Access should validate those headers at the edge, then send an **independently signed JWT assertion** to the origin. Our G7.2g origin verifier checks the machine JWT, Client ID binding and Ed25519 request signature. The agent does not generate JWT assertions itself.
- On every authenticated agent request, the payload is bound to `deviceId`, `sessionId`, strict sequence, method, path and SHA256 request digest via Ed25519. Session IDs or service tokens alone never authorize tools.
- Implements `connect`, `heartbeat`, `poll`, `result`, `close`; no implicit retries on transport failure (ambiguous outcome), strict JSON body and response caps, invalid response rejection, bounded timeouts and sanitized error messages that never include token secrets.
- Credentials and private keys are constructor inputs from **future local secure storage**, not generated, persisted, logged, published or sent to other hosts by this module. The existing DPAPI/POSIX Ed25519 signer is provided by a caller.
- The agent process remains a normal, non-root user. `start_process`, writes and root are not granted by this HTTPS client. The separate local adapter from PR #22 enforces read_file-only in the prototype.

## Evidence and test boundary

- `packages/vpsc-agent/test/https-client.test.mjs` includes local protocol tests for host/URL restrictions, credential binding, signed headers, no redirect, malformed response handling, one-shot failure, no secret leakage and a full signed read-only MCP fixture operation via `deviceId`.
- These tests **simulate the Cloudflare edge** by verifying synthetic machine Service Token values and attaching a signed fake Access JWT to the loopback G7 machine ingress. **They do not contact the internet or validate a real Cloudflare Service Auth app.** Tests are imported into Gateway CI through `gateway/test/device-agent-contract.test.mjs`.
- No TLS certificate, Cloudflare Service Token, actual hostname, tunnel, DNS route, npm release, systemd service, autostart, or Windows-to-VPS connection was created in this PR.
- The current `@gasjw/vpsc-agent@0.0.0-dev` remains marked `private:true`, with `connect` disabled in its CLI. Connecting it automatically before enrollment, key handling and audit would be unsafe.

## Gates before dual-host deployment

1. Establish **dedicated Agent Service Auth application/hostname** and strict allowlist of per-device Cloudflare Service Tokens, never "Any Access Service Token" and never broaden the existing Owner Only Access app.
2. Persist Client ID/Secret under Windows user-scoped DPAPI and Linux owner-only files (separately from Ed25519 key); add credential rotation, expiration, disaster recovery and device revocation. Prevent environment, shell command arguments, logs and Git from containing secrets.
3. Implement owner-authenticated device pairing and durable trusted key/deviceId reconciliation, single-writer storage with backup and audit. The server-side durable trust PR #21 remains Draft pending concurrency/recovery review.
4. Wire only a reviewed read-only local MCP executor to agent polling and isolated Gateway routing. Add OS sandboxing/descriptor-based access to resolve the **filesystem TOCTOU** risk of path validation before deploying any remote read_file on writable roots.
5. Add rate limits, heartbeat supervision, session fencing across disconnect, bounded work queue and no blind retry on ambiguous results. Test a real Windows Gui-PC ↔ VPS gui operation after the private secure channel passes all gates.
6. Publish a **pinned version** of the agent for npx only after package integrity/provenance and least-privilege review. No npx process should ever run as root.
7. Dashboard choice of device, Standard/Root/Admin and 10m,30m,60m,Indefinida grants are not activated by this module; privileged helper is still independent and unimplemented.
8. Keep G6 production checkout and RDC recovery intact. At the time of development VPS gui root filesystem was roughly 90% utilized; no additional services were provisioned.

## References

- [Cloudflare Service Tokens](https://developers.cloudflare.com/cloudflare-one/access-controls/service-credentials/service-tokens/)
- [Cloudflare application JWT: `common_name` for service token](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/application-token/)
