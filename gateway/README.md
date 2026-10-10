# VPS Commander — gateway MCP HTTP (G2)

**Status (2026-10-10):** executor local active na VPS `gui` em `127.0.0.1:8787`, modo Cloudflare Access ativo; túnel dedicado ainda inativo; DNS não publicado; plugin ChatGPT não conectado.

## Architecture
The gateway relays JSON MCP methods to the existing Desktop Commander stdio process. It does not rely on the proprietary Desktop Commander remote service or quotas. Server still supports arbitrary shell commands subject to the dedicated Linux service user's privileges.

## Runtime
- Node.js 22+, `/opt/vps-commander/bin/node`, non-root `vpscommander`.
- Code `/opt/vps-commander/code`; service `vps-commander.service`.
- Loopback bind only, no public TCP interface.
- Headless mode disables Chrome download at bootstrap.
- Local secrets, never Git/Notion: `/var/lib/vps-commander/.config/vps-commander/gateway.env`.
- JWT Access mode is selected by `VPS_COMMANDER_AUTH_MODE=access`; service config via `/etc/systemd/system/vps-commander.service.d/20-access.conf`.
- Auth variables: `VPS_COMMANDER_ACCESS_ISSUER`, `VPS_COMMANDER_ACCESS_AUD`, `VPS_COMMANDER_ALLOWED_EMAILS`.
- A separate mode `local` supports a long static bearer token **for local tests only**. The live G2 service uses `access` and rejects the legacy bearer.

## Cloudflare Managed OAuth
ChatGPT authenticates with Cloudflare Access. Its opaque OAuth access token is validated at Cloudflare's edge. For approved calls, Access forwards a signed JWT to the origin as `Cf-Access-Jwt-Assertion`.

In `access` mode the gateway independently verifies:
- RSA-SHA256 signature with publicly fetched JWKS from the configured Cloudflare Access organization;
- issuer, exact audience, expiration, issue time and optional not-before;
- presence of a nonempty subject and an explicitly allowed owner email.

All failures deny access with 401. The origin does **not** accept an arbitrary string in `Cf-Access-Jwt-Assertion` and does not trust the opaque ChatGPT OAuth bearer by itself.

The Cloudflare managed tunnel ingress is configured to independently require Access JWT verification with the same audience. No tunnel route is published until bootstrap and tests.

## Tests and observations
```bash
node --check gateway/server.mjs
node --check gateway/access-auth.mjs
node --test gateway/test/*.test.mjs
```

5/5 tests passed in the real Ubuntu VPS against the mock fixture, including signing/claims, invalid signatures, invalid identities and HTTP bypass cases. The genuine Desktop Commander toolset was tested before transition to JWT Access mode, exposing 26 tools and successfully executing `start_process`, `read_file`, `write_file`. Post-transition 401 tests for missing/fake JWT and old bearer passed.

**Not yet certified:** OAuth login with real Cloudflare-signed user assertion, live ChatGPT tools/list over the public tunnel, and multi-tool use under the persistent JWT mode.

## Transport limitations
V0 forwards stateless MCP JSON POST and HTTP response; no SSE push, resumability or multi-user session isolation yet. Max 16 upstream calls concurrently, 1 MiB request body, 120-second tool call timeout. Avoid returning huge command results. The upstream blocklist is not a sandbox.

## Deploy and rollback
- G1 local service: `deploy/systemd/vps-commander.service`.
- Access override example: `deploy/systemd/vps-commander-access.conf.example`.
- Cloudflared named tunnel unit: `deploy/systemd/cloudflared-vps-commander.service` (not yet installed).
- Owner-operated direct SSH bootstrap: `deploy/bootstrap-g2-tunnel.sh` (not yet run).
- G2 observed evidence: `docs/G2-LIVE-EVIDENCE-20261010.md`.
- Rollback: `systemctl stop vps-commander.service`, and if installed `systemctl stop cloudflared-vps-commander.service`.

The RDC administrative connector rejected the systemd tunnel bootstrap, so do not claim that stage is deployed. Do not change the existing `cofre` tunnel, Pantheon, Hermes or OpenMausBot deployment.
