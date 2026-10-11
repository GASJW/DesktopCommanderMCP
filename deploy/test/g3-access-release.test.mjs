import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
const deploy=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const script=readFileSync(path.join(deploy,'bootstrap-g3-access.sh'),'utf8');
const gateway=readFileSync(path.join(deploy,'systemd/vps-commander-g3.service'),'utf8');

test('G3.5 requires authenticated Access mode and preserves non-root gateway identity',()=>{
  assert.match(script,/feat\/g3-access-hardening/);
  assert.match(script,/VPS_COMMANDER_AUTH_MODE=access/);
  assert.match(gateway,/^User=vpsc-gateway$/m);
  assert.match(gateway,/^Environment=VPS_COMMANDER_AUTH_MODE=access$/m);
  assert.match(gateway,/^InaccessiblePaths=\/var\/lib\/vps-commander$/m);
  assert.match(script,/G3_5_GATEWAY_DEPLOY=BOOTSTRAP_GREEN/);
});

test('G3.5 recovery uses validated source permissions and falls back ONLY to known G3.4 branch',()=>{
  assert.match(script,/switch feat\/g3-operational-limits/);
  assert.match(script,/rev-parse --verify origin\/feat\/g3-operational-limits/);
  assert.match(script,/ensure_gateway_sources_readable/);
  assert.match(script,/runuser -u vpsc-gateway -- test -r/);
  assert.match(script,/G3_5_ROLLBACK=GREEN_G3_3_RESTORED|G3_5_ROLLBACK=GREEN_G3_4_RESTORED/);
  assert.match(script,/wait_commander_tunnel_ready/);
  assert.match(script,/trap rollback ERR/);
  assert.doesNotMatch(script,/systemctl (restart|kill|stop) "\$WK"/);
  assert.doesNotMatch(script,/systemctl restart cloudflared\.service/);
});
