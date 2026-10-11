# G7.2d — Device agent key persistence (owner-scoped, inert)

**Scope:** preserve an Ed25519 signing identity across process restarts so that a future outbound Windows/Linux agent does not silently change its fingerprint. This is NOT durable server-side pairing, not an active agent, and not an approval to connect a device.

## Storage

- `packages/vpsc-agent/src/identity-store.mjs` exposes `loadOrCreateDeviceIdentity()` and reuses the signing helper in `src/pairing.mjs`.
- Identity is Ed25519 PKCS8; the public signing interface reveals only `fingerprint`, `publicKeyPem`, and signature methods, never the key object or private PEM.
- Default POSIX location: `~/.vpsc-device/identity-v1.json`, directory 0700 and file 0600. Refuse unsafe mode, symbolic links, invalid JSON, truncated/mismatched fingerprints and malformed key. Create with `O_CREAT|O_EXCL|O_NOFOLLOW` and fsync before loading. **If creation is interrupted and the file is incomplete, refuse to use it instead of silently regenerating a different identity.** Do not invoke as root.
- Default Windows location: `%LOCALAPPDATA%/VPSCommander/device/identity-v1.json` under the current user's profile. Store only DPAPI **CurrentUser** encrypted PKCS8 ciphertext, with purpose-specific entropy; encryption/decryption is performed locally via noninteractive PowerShell stdin, never via CLI arguments or logs. This is not TPM/non-exportable hardware protection. A Windows administrator or process operating with the same user's security context may access the key; DPAPI does not confer machine identity assurance.
- File includes format/version, fingerprint, protected key material and no Gateway token. The local identity does not include server-side deviceId; future persisted pairing must bind and revoke it separately.
- Only a local package prototype is used for tests. `@gasjw/vpsc-agent@0.0.0-dev` remains private and unpublished; no network transport or remote command can be started by the existing CLI.

## Tests / constraints

- On Linux: persistence across a **separate Node process**, directory/file permissions, symlink rejection, invalid/corrupt identity handling, fingerprint tamper and private key exclusion from public object.
- On Windows (required before certification): DPAPI CurrentUser encrypt/decrypt test in a temporary user-owned directory, process-restart persistence and verifying that another user cannot decrypt, where authorized.
- Do **not** claim Windows validation based solely on Linux skipped tests. Windows test must run on a consenting Gui-PC with adequate disk and trusted checkout. No existing device credentials should be imported.
- Do not allow profile path override through untrusted agent network messages; test directory injection is local-only and cannot be a remote tool parameter.
- Hardening before live rollout: Windows directory ACL audit; key-at-rest process-memory hygiene, backup/recovery, key rotation with two-phase owner approval, server-side revocation/tombstones and authenticated TLS ingress, no rollback to a previously revoked key.
- For Linux root/Admin, use separate per-operation admin helper; ordinary agent must run as user and its npx package cannot be elevated.
- G7.1 through G7.2c stacked review order #15 → #17 → #18 → #19 → this PR. G7.3 admin-duration contract #16 remains inert and independent.
- No code imported into deployed Gateway, no production changes, new DNS, Cloudflare Access modifications, systemd units, npm release, Windows install or root access.

## Operational notes

At preparation time VPS gui root disk reported 90% utilized; workspace intentionally uses shallow clones and does not install npm dependencies. Preserve existing G6 production and G5.2 PR #10.

**Acceptance:** protected CI GREEN, Linux test suite GREEN, Windows DPAPI simulation GREEN, security review of storage and ownership. No live rollout from this PR alone.
