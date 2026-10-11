import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const dir=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const source=name=>readFileSync(path.join(dir,name),'utf8');

test('G5.2 encrypt/upload scripts have valid shell syntax',()=>{
  for(const name of ['g5-offsite-encrypt.sh','g5-offsite-upload.sh']) {
    const res=spawnSync('bash',['-n',path.join(dir,name)],{encoding:'utf8'});
    assert.equal(res.status,0,res.stderr);
  }
});

test('G5.2 never creates or reads the production private recovery identity on VPS',()=>{
  const encrypt=source('g5-offsite-encrypt.sh');
  const upload=source('g5-offsite-upload.sh');
  assert.match(encrypt,/age -R "\$RECIPIENTS" -o/);
  assert.match(encrypt,/plaintext_archive_sha256/);
  assert.match(encrypt,/sha256sum/);
  assert.match(encrypt,/umask 077/);
  assert.match(encrypt,/root:700/);
  assert.doesNotMatch(encrypt,/age-keygen|age -d|age --decrypt/);
  assert.doesNotMatch(upload,/age-keygen|age -d|age --decrypt/);
  assert.doesNotMatch(encrypt,/cloudflared\/vps-commander-private/);
  assert.doesNotMatch(upload,/cloudflared\/vps-commander-private/);
});

test('G5.2 upload requires scoped OAuth, never sync/delete/overwrite and verifies remote digest',()=>{
  const upload=source('g5-offsite-upload.sh');
  assert.match(upload,/scope = drive\.file/);
  assert.match(upload,/root_folder_id =/);
  assert.match(upload,/root:600/);
  assert.match(upload,/rclone .*copyto --immutable/);
  assert.match(upload,/rclone .* cat /);
  assert.match(upload,/G5_2_DRIVE_SHA256=PASS/);
  assert.doesNotMatch(upload,/\brclone (sync|delete|purge|moveto)\b/);
  assert.doesNotMatch(upload,/scope = drive\s*$/m);
});

test('G5.2 restore verifier is inspect/extract-only, off-server, and checks path allowlist',()=>{
  const restore=source('g5-restore-verify.py');
  const syntax=spawnSync('python3',['-c','import ast, pathlib, sys; ast.parse(pathlib.Path(sys.argv[1]).read_text())',path.join(dir,'g5-restore-verify.py')],{encoding:'utf8'});
  assert.equal(syntax.status,0,syntax.stderr);
  assert.match(restore,/G5_2_RESTORE_TEST=GREEN/);
  assert.match(restore,/entry\.isfile\(\)/);
  assert.match(restore,/name not in ALLOWED/);
  assert.doesNotMatch(restore,/\bextractall\b/);
  assert.doesNotMatch(restore,/systemctl|sudo |\/etc\/systemd\/system\/vps-commander\.service\s*=/);
});

test('G5.2 Windows private-key generation only prints the public recipient',()=>{
  const keygen=source('g5-keygen-windows.ps1');
  assert.match(keygen,/age-keygen -o \$key/);
  assert.match(keygen,/age-keygen -y \$key/);
  assert.match(keygen,/icacls\.exe/);
  assert.match(keygen,/Test-Path -LiteralPath \$key/);
  assert.doesNotMatch(keygen,/Get-Content.*\$key|type \$key/);
  assert.doesNotMatch(keygen,/cloudflared|Google Drive.*key/);
});
