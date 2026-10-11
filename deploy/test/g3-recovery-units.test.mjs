import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const script=readFileSync(path.join(root,'bootstrap-g3-recovery.sh'),'utf8');
const unit=readFileSync(path.join(root,'systemd/vps-commander-g3.service'),'utf8');
const worker=readFileSync(path.join(root,'systemd/vps-commander-executor.service'),'utf8');

test('G3.3 cutover is gateway-only, preserves isolation and rollback',()=>{
  assert.match(script,/trap rollback ERR/);
  assert.match(script,/systemctl restart vps-commander.service/);
  assert.match(script,/git_safe\[@\].*switch feat\/g3-audit-trail/);
  assert.match(script,/status.*401/);
  assert.match(script,/G3_3_GATEWAY_DEPLOY=BOOTSTRAP_GREEN/);
  assert.doesNotMatch(script,/systemctl (restart|stop|kill) vps-commander-executor.service/);
  assert.doesNotMatch(script,/cloudflared.*token-file/);
  assert.match(unit,/^User=vpsc-gateway$/m);
  assert.match(worker,/^User=vpscommander$/m);
  assert.match(unit,/^Environment=VPS_COMMANDER_AUDIT_ENABLED=1$/m);
});

test('gateway is not deactivated when its independently restarting worker fails',()=>{
  assert.match(unit,/^Restart=on-failure$/m);
  assert.match(worker,/^Restart=on-failure$/m);
  assert.match(unit,/^Wants=vps-commander-executor.service$/m);
  assert.doesNotMatch(unit,/^Requires=vps-commander-executor.service$/m);
  assert.match(unit,/^Environment=VPS_COMMANDER_EXECUTOR_SOCKET=\/run\/vps-commander-ipc\/mcp.sock$/m);
});
