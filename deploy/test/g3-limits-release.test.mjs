import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const deploy=readFileSync(path.join(root,'bootstrap-g3-limits.sh'),'utf8');
const unit=readFileSync(path.join(root,'systemd/vps-commander-g3.service'),'utf8');

test('G3.4 deploy is root-only gateway restart and preserves G3.3 isolation',()=>{
  assert.match(deploy,/Requires root SSH/);
  assert.match(deploy,/feat\/g3-operational-limits/);
  assert.match(deploy,/trap rollback ERR/);
  assert.match(deploy,/switch feat\/g3-recovery/);
  assert.match(deploy,/systemctl restart "\$GW"/);
  assert.doesNotMatch(deploy,/systemctl (restart|stop|kill) "\$WK"/);
  assert.match(deploy,/G3_4_GATEWAY_DEPLOY=BOOTSTRAP_GREEN/);
  assert.match(unit,/^User=vpsc-gateway$/m);
  assert.match(unit,/^Environment=VPS_COMMANDER_AUDIT_ENABLED=1$/m);
  assert.match(unit,/^Wants=vps-commander-executor.service$/m);
  assert.doesNotMatch(unit,/^Requires=vps-commander-executor.service$/m);
});

test('G3.4 has retained non-root systemd memory/process ceilings',()=>{
  assert.match(unit,/^MemoryMax=250M$/m);
  assert.match(unit,/^TasksMax=64$/m);
  const worker=readFileSync(path.join(root,'systemd/vps-commander-executor.service'),'utf8');
  assert.match(worker,/^MemoryMax=900M$/m);
  assert.match(worker,/^TasksMax=128$/m);
  assert.match(deploy,/production load tests are forbidden/);
});
