import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const gateway=readFileSync(path.join(root,'systemd/vps-commander-g3.service'),'utf8');
const worker=readFileSync(path.join(root,'systemd/vps-commander-executor.service'),'utf8');
const bootstrap=readFileSync(path.join(root,'bootstrap-g3-isolation.sh'),'utf8');

test('gateway and executor use distinct Unix identities and private socket',()=>{
  assert.match(gateway,/^User=vpsc-gateway$/m);
  assert.match(worker,/^User=vpscommander$/m);
  assert.match(gateway,/^Group=vpsc-ipc$/m);
  assert.match(worker,/^Group=vpsc-ipc$/m);
  assert.match(gateway,/^Environment=VPS_COMMANDER_EXECUTOR_SOCKET=\/run\/vps-commander-ipc\/mcp.sock$/m);
  assert.match(worker,/^Environment=VPS_COMMANDER_EXECUTOR_SOCKET=\/run\/vps-commander-ipc\/mcp.sock$/m);
  assert.match(gateway,/^InaccessiblePaths=\/var\/lib\/vps-commander$/m);
  assert.match(gateway,/^ProtectProc=invisible$/m);
  assert.match(worker,/^RuntimeDirectoryMode=0750$/m);
  assert.doesNotMatch(gateway,/^EnvironmentFile=/m);
  assert.match(gateway,/^NoNewPrivileges=true$/m);
  assert.match(worker,/^NoNewPrivileges=true$/m);
});

test('cutover preserves rollback and refuses promotion if isolation fails',()=>{
  assert.match(bootstrap,/BACKUP=\/root\/vps-commander-g3-backup/);
  assert.match(bootstrap,/trap rollback ERR/);
  assert.match(bootstrap,/stat -c '%a %G'/);
  assert.match(bootstrap,/runuser -u vpscommander -- test -r/);
  assert.match(bootstrap,/systemctl restart cloudflared-vps-commander.service/);
  assert.match(bootstrap,/G3_EXECUTOR_ISOLATION=BOOTSTRAP_GREEN/);
});
