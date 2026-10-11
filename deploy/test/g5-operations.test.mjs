import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, writeFileSync, chmodSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const read=name=>readFileSync(path.join(root,name),'utf8');
const health=read('g5-health.sh');
const backup=read('g5-backup.sh');
const guard=read('g5-release-guard.sh');

test('G5 scripts are syntactically valid and never print credential values',()=>{
  for(const name of ['g5-health.sh','g5-backup.sh','g5-release-guard.sh']){
    const r=spawnSync('bash',['-n',path.join(root,name)],{encoding:'utf8'});
    assert.equal(r.status,0,name+': '+r.stderr);
  }
  for(const s of [health,backup,guard]){
    assert.doesNotMatch(s,/\b(cat|echo|printf)\b[^\n]*\/etc\/cloudflared\/vps-commander-private\/token/);
    assert.doesNotMatch(s,/\b(gh auth token|set -x|env\s+\||printenv|systemctl cat)\b/);
  }
});

test('G5 health is non-privileged, fail-closed and never modifies a service',()=>{
  assert.match(health,/G5_HEALTH=RED/);
  assert.match(health,/G5_HEALTH=GREEN_WITH_WARNINGS/);
  assert.match(health,/G5_ANONYMOUS_HTTP=401/);
  assert.match(health,/VPS_COMMANDER_AUTH_MODE=access/);
  assert.match(health,/VPS_COMMANDER_AUDIT_ENABLED=1/);
  assert.match(health,/cloudflared\.service/);
  assert.match(health,/non_loopback_mcp_listener/);
  assert.doesNotMatch(health,/\bsystemctl (restart|stop|kill|start|enable|disable|daemon-reload)/);
  assert.doesNotMatch(health,/\b(chmod|chown|git switch|git reset|swapoff)\b/);
});

test('G5 health fails on inactive service and never treats it as GREEN',()=>{
  const dir=mkdtempSync(path.join(tmpdir(),'vpsc-g5-health-'));
  try {
    const systemctl=path.join(dir,'systemctl');
    writeFileSync(systemctl,'#!/bin/sh\nif [ "$1" = is-active ]; then exit 3; fi\nexit 1\n');
    chmodSync(systemctl,0o755);
    const r=spawnSync('bash',[path.join(root,'g5-health.sh')],{
      encoding:'utf8',timeout:5000,
      env:{...process.env,PATH:dir+':/usr/bin:/bin'},
    });
    assert.equal(r.status,1);
    assert.match(r.stdout,/G5_FAIL=inactive_unit_vps-commander/);
    assert.match(r.stdout,/G5_HEALTH=RED/);
    assert.doesNotMatch(r.stdout,/TOKEN|PRIVATE_KEY|EMAIL=/);
  } finally {rmSync(dir,{recursive:true,force:true});}
});

test('G5 backup only archives named Commander units/drop-in and no tunnel token',()=>{
  assert.match(backup,/\[\[ "\$EUID" -eq 0 \]\]/);
  assert.match(backup,/umask 077/);
  assert.match(backup,/mktemp -d -p "\$ROOT"/);
  assert.match(backup,/install -d -o root -g root -m 0700/);
  assert.match(backup,/tar --create --gzip --file/);
  assert.match(backup,/cloudflared_token_included=no/);
  assert.match(backup,/offsite_verified=no/);
  assert.match(backup,/G5_BACKUP_SELF_CHECK=PASS/);
  assert.doesNotMatch(backup,/files\+=\([^\n]*token/);
  assert.doesNotMatch(backup,/cloudflared\.service\s*\)/);
  assert.doesNotMatch(backup,/\b(systemctl restart|git reset|git switch|rsync)\b/);
});

test('G5 release guard checks protected main, exact CI, no deployment or unreviewed checkout',()=>{
  assert.match(guard,/\.protected/);
  assert.match(guard,/gateway-tests/);
  assert.match(guard,/Check for spelling errors/);
  assert.match(guard,/\.app\.slug=="github-actions"/);
  assert.match(guard,/refs\/heads\/main:refs\/remotes\/origin\/main/);
  assert.match(guard,/diff --quiet/);
  assert.match(guard,/G5_RELEASE_GUARD=GREEN_NO_DEPLOY_NEEDED/);
  assert.match(guard,/HOLD_CANDIDATE_BUILD_AND_CUTOVER_REQUIRED/);
  assert.doesNotMatch(guard,/\bgit\s+(-C\s+\S+\s+)?(switch|checkout|reset|clean|push)\b/);
  assert.doesNotMatch(guard,/\bsystemctl (restart|stop|kill|start)\b/);
});
