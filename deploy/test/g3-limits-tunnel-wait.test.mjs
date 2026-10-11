import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const deploy=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../bootstrap-g3-limits.sh');
const script=readFileSync(deploy,'utf8');
const waiter=script.match(/^wait_commander_tunnel_ready\(\) \{[\s\S]*?^\}/m)?.[0];
assert.ok(waiter,'live bootstrap wait function missing');

test('G3.4 waits for a dependent tunnel that is activating, then accepts active',()=>{
  const program=[waiter,
    'count=0',
    'systemctl(){ count=$((count+1)); if ((count < 4)); then return 3; fi; return 0; }',
    'sleep(){ :; }',
    'wait_commander_tunnel_ready 6 0',
    'printf "POLLS=%s" "$count"',
  ].join('\n');
  assert.equal(execFileSync('bash',['-c',program],{encoding:'utf8'}),'POLLS=4');
});

test('G3.4 fails closed if tunnel never becomes active',()=>{
  const program=[waiter,
    'count=0',
    'systemctl(){ count=$((count+1)); return 3; }',
    'sleep(){ :; }',
    'if wait_commander_tunnel_ready 3 0; then exit 23; fi',
    'printf "TIMEOUT_POLLS=%s" "$count"',
  ].join('\n');
  assert.equal(execFileSync('bash',['-c',program],{encoding:'utf8'}),'TIMEOUT_POLLS=3');
});

test('bootstrap waits for tunnel both after restart and during rollback before declaring GREEN',()=>{
  assert.match(script,/if ! wait_commander_tunnel_ready; then\n  echo 'G3_4_GATE=RED_TUNNEL_NOT_READY_AFTER_WAIT'/);
  assert.match(script,/if ! wait_commander_tunnel_ready; then\n    # Single best-effort tunnel restart/);
  assert.match(script,/echo 'G3_4_ROLLBACK=GREEN_G3_3_RESTORED'/);
  assert.match(script,/echo G3_4_TUNNEL_STABILIZATION=PASS/);
  assert.doesNotMatch(script,/systemctl restart cloudflared\.service/);
});
