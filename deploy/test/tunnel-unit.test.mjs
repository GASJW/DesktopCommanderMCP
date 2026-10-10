import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));
const unit = readFileSync(path.join(here, '..', 'systemd', 'cloudflared-vps-commander.service'), 'utf8');
const bootstrap = readFileSync(path.join(here, '..', 'bootstrap-g2-tunnel.sh'), 'utf8');

test('cloudflared token-file belongs to the tunnel run subcommand', () => {
  assert.match(unit, /^ExecStart=\/usr\/local\/bin\/cloudflared --no-autoupdate tunnel run --token-file \/etc\/cloudflared\/vps-commander-private\/token$/m);
  assert.doesNotMatch(unit, /tunnel --token-file .* run/);
});
test('tunnel starts dedicated, non-root, and checks the active MCP origin', () => {
  assert.match(unit, /^User=vpscommander-tunnel$/m);
  assert.match(unit, /^NoNewPrivileges=true$/m);
  assert.match(unit, /^ProtectSystem=strict$/m);
  assert.match(bootstrap, /systemctl restart "\$UNIT"/);
  assert.match(bootstrap, /ss -ltn/);
});
