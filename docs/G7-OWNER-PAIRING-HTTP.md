# G7 — Owner-only HTTP pairing review API (inert, stacked on PR #25)

This standalone module adds the *server-side control plane* matching the visual owner pairing page staged in PR #25. It is NOT imported into `gateway/server.mjs`, it has NO live listener or Cloudflare/DNS changes, and does NOT activate pairing on the Gui-PC.

## Surface contract

`createOwnerPairingHttp({coordinator,accessVerifier,expectedOrigin,auditWrite,now})` builds a request handler, to be mounted **only after** its deployment gates. It exclusively handles:

- `GET /dashboard/api/g7/pairing/pending`: verify a real owner Cloudflare Access JWT using `accessVerifier.verifyPrincipal` (the existing `createAccessVerifier`, issuer/audience/allowedEmails/JWKS), return a sanitized list of pending devices + a short-lived HMAC-authenticated CSRF token bound to the verified owner's issuer and subject. Never return comparison code, nonce, Access cookie or key.
- `POST /dashboard/api/g7/pairing/approve`: verify exact HTTPS Origin, same-origin fetch metadata (when provided), signed owner JWT, owner-bound CSRF, bounded JSON body, rate cap, write-ahead **durable audit intent**, then call PR #25's `createOwnerPairingReview` with an unforgeable internal owner context. That review demands an Ed25519-verified possession proof, matching owner-entered display code and full public fingerprint. Approval yields an **offline** trusted identity, not an authenticated live connection, root or an OS permission grant.
- `POST /dashboard/api/g7/pairing/reject`: same owner JWT, Origin, CSRF, schema, cap and audit controls, then invalidate the pending pairing. No root grant.

Both mutation routes require a configured `auditWrite` callback that **must durably persist the event and return true**. The handler writes a bounded intent with an ephemeral operation ID and pseudonymous owner/target, **without secrets**, before mutation. It then writes a success/denial outcome. If the initial audit commit fails, no device trust action occurs and the handler becomes unavailable. If the outcome audit fails after a device approval may already have committed, it responds 503 with an **ambiguous outcome** and permanently refuses subsequent actions until manual reconciliation; do not interpret that 503 as proof that no approval happened.

## Hard limits / threat notes

- CSRF token is HMAC authenticated, owner-bound, has a 5-minute lifetime and is invalid after process restart. Reject tokens minted for another owner, malformed tokens and cross-origin/forged browser submits. No CORS headers, no weak code-only approval.
- Rate limit: six owner mutations per 60 seconds in memory, plus PR #25's five-invalid-code cancellation. Rate limiting is not distributed. A production reverse proxy must have independent device/owner/IP abuse mitigation.
- Payload cap 2 KiB, strict expected fields, POST only for mutations, no-store, no content leaks, fail closed on invalid JWT or missing audit.
- Trusted input: the handler is a library instantiated only by trusted Gateway code. Never export a callable ownerGate to clients or pass an unverified request header as a principal. Authentication must use the signed existing `createAccessVerifier` and an explicitly pinned owner-only audience.
- The live `gateway/server.mjs` currently rejects ALL requests with an `Origin` header. When integration is authorized, perform a narrow reviewed route/method exception for this exact API, preserving existing MCP/dashboard guards and never changing Owner Only to permit machine service tokens.
- The injected `auditWrite` is an **interface, not yet a concrete fsync-backed, single-writer production WAL**. Test sinks simulate durable success/failure and cannot themselves satisfy the production gate. Do not deploy this module until a real owner-only durable audit store and reconciliation procedure are certified.
- The PR #21 registry storage remains Draft for lock/crash recovery and revocation durability. Tests currently exercise a temporary in-memory coordinator, not production trusted state.
- The agent `vpsc-agent pair`, own HTTPS machine ingress and Cloudflare Service Auth app are not connected. Installed Gui-PC package remains a local pilot; no npx public release, no auto-start, no admin/root helper.
- There is no rollback through an automatic retry. Always check authoritative registry/audit state after any 503/timeout.
- No deployment, Cloudflare policy edits, external credentials, systemd actions, production main changes or restarts in this PR.

## Tests

End-to-end tests start an ephemeral 127.0.0.1 HTTP listener with an **actual RSA-signed owner JWT** verified by the existing Cloudflare Access verifier using ephemeral test JWKS. They exercise list/approve/reject with the real PR #25 pairing coordinator and Ed25519 proof. Negative cases: anonymous, forged owner, wrong audience/email, machine token, CSRF substitution, expiry and wrong owner session, cross-origin, replay, illegal code, fingerprint mismatch, rate limit, malformed payload, injected fields, oversized content, and fail-before/fail-after audit semantics.

Do not interpret passing unit/loopback tests as live HTTPS or independently durable audit certification.

**PR dependency:** this branch is based on PR #25 head `24703c2979f66e9a376c4b48ef4aeb81db8ba4e7`. Review #25 before merging this dependent PR. Both remain Draft until governance/security gates are satisfied.
