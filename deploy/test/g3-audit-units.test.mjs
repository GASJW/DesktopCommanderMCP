import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const deploy=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const unit=readFileSync(path.join(deploy,'systemd/vps-commander-g3.service'),'utf8');
const bootstrap=readFileSync(path.join(deploy,'bootstrap-g3-audit.sh'),'utf8');

test('audit is enabled only in authenticated gateway journald unit',()=>{
  assert.match(unit,/^User=vpsc-gateway$/m);
  assert.match(unit,/^Environment=VPS_COMMANDER_AUTH_MODE=access$/m);
  assert.match(unit,/^Environment=VPS_COMMANDER_AUDIT_ENABLED=1$/m);
  assert.match(unit,/^StandardOutput=journal$/m);
  assert.match(unit,/^SyslogIdentifier=vps-commander$/m);
  assert.match(unit,/^InaccessiblePaths=\/var\/lib\/vps-commander$/m);
  assert.doesNotMatch(unit,/EnvironmentFile=/);
});
test('audit bootstrap preserves service identity and supports fail-closed rollback',()=>{
  assert.match(bootstrap,/trap rollback ERR/);
  assert.match(bootstrap,/systemctl show -P User vps-commander.service/);
  assert.match(bootstrap,/journalctl -u vps-commander.service/);
  assert.match(bootstrap,/G3_2_AUDIT_SYSTEMD=BOOTSTRAP_GREEN/);
  assert.match(bootstrap,/install -m 0644 "\$BACKUP\/vps-commander.service" "\$GW_UNIT"/);
});
