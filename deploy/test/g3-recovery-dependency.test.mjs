import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const unit=readFileSync(path.join(root,'systemd/vps-commander-g3.service'),'utf8');
const fix=readFileSync(path.join(root,'repair-g3-gateway-dependency.sh'),'utf8');

test('gateway is ordered after worker but never hard-requires its continuous uptime',()=>{
  assert.match(unit,/^Wants=vps-commander-executor.service$/m);
  assert.match(unit,/^After=network.target vps-commander-executor.service$/m);
  assert.doesNotMatch(unit,/^Requires=vps-commander-executor.service$/m);
  assert.match(unit,/^Restart=on-failure$/m);
  assert.match(unit,/^Environment=VPS_COMMANDER_AUDIT_ENABLED=1$/m);
});

test('dependency hotfix is a guarded one-line change and NEVER restarts live units',()=>{
  assert.match(fix,/set -Eeuo pipefail/);
  assert.match(fix,/sed 's\/\^Requires=vps-commander-executor.service\$\/Wants=vps-commander-executor.service\/'/);
  assert.match(fix,/trap rollback ERR/);
  assert.match(fix,/systemctl daemon-reload/);
  assert.match(fix,/MainPID vps-commander.service/);
  assert.match(fix,/G3_3_DEPENDENCY_REPAIR=GREEN/);
  assert.doesNotMatch(fix,/systemctl (kill|restart|stop|reset-failed) /);
});
