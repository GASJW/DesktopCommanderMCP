import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const dir=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const script=readFileSync(path.join(dir,'verify-g3-systemd-recovery.sh'),'utf8');

test('live restart drill requires explicit root SSH approval and targets only executor main PID',()=>{
  assert.match(script,/EUID.*--accept-controlled-executor-restart/);
  assert.match(script,/systemctl kill --kill-whom=main --signal=SIGKILL "\$WORKER"/);
  assert.match(script,/before_gateway=.*MainPID/);
  assert.match(script,/after_gateway=.*MainPID/);
  assert.match(script,/after_worker.*before_worker/);
  assert.match(script,/G3_3_REAL_SYSTEMD_DRILL=GREEN/);
  assert.doesNotMatch(script,/systemctl (stop|kill) .*"\$GATEWAY"/);
  assert.doesNotMatch(script,/kill .*vps-commander.service/);
});

test('drill validates audit transitions before pass and includes automatic recovery on failure',()=>{
  assert.match(script,/trap recover ERR/);
  assert.match(script,/journalctl -u "\$GATEWAY" --since "\$stamp" --no-pager -o cat/);
  assert.match(script,/verify-g3-recovery-events.py/);
  assert.match(script,/systemctl restart "\$WORKER"/);
  assert.match(script,/systemctl restart "\$GATEWAY"/);
  assert.match(script,/systemctl is-active --quiet cloudflared.service/);
});
