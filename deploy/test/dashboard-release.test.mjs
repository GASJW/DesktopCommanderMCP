import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const script=readFileSync(path.join(root,'bootstrap-commander-dashboard.sh'),'utf8');
const server=readFileSync(path.join(root,'../gateway/server.mjs'),'utf8');

test('Dashboard deployment script is syntactically valid and checks protected main',()=>{
  const result=spawnSync('bash',['-n',path.join(root,'bootstrap-commander-dashboard.sh')],{encoding:'utf8'});
  assert.equal(result.status,0,result.stderr);
  assert.match(script,/branches\/main --jq \.protected/);
  assert.match(script,/gateway-tests/);
  assert.match(script,/Check for spelling errors/);
  assert.match(script,/gateway\/test\/dashboard\.test\.mjs/);
  assert.match(script,/DASH_DEPLOY=RED_UNEXPECTED_RUNTIME_DELTA/);
  assert.match(script,/DASH_DEPLOY=BOOTSTRAP_GREEN/);
  assert.match(script,/DASH_ROUTE_ANONYMOUS=401/);
  assert.match(script,/refs\/heads\/feat\/g3-access-hardening|refs\/heads\/feat\/g3-access-hardening|refs\/heads\/main|feat\/g3-access-hardening/);
});
test('Dashboard bootstraps gateway only; never touches unrelated apps or cofre',()=>{
  assert.match(script,/systemctl restart "\$UNIT"/);
  assert.doesNotMatch(script,/systemctl (stop|kill|restart) "\$WORKER"/);
  assert.doesNotMatch(script,/systemctl (stop|kill|restart) "\$COFRE"/);
  assert.doesNotMatch(script,/cloudflare.*(PUT|DELETE)|curl.*api\.cloudflare/i);
  assert.match(script,/DASH_WORKER_PID_UNCHANGED=PASS/);
  assert.match(script,/DASH_ROLLBACK=GREEN_G3_5/);
  assert.match(script,/runuser -u vpsc-gateway -- test -r/);
  assert.doesNotMatch(script,/chmod -R|chown -R|sudo\s+-S|git\s+push/);
});
test('Dashboard remains behind verified owner Access, with same MCP path',()=>{
  assert.match(server,/if \(authMode !== 'access'\) return reply\(res, 404/);
  assert.match(server,/serveDashboard\(req,res/);
  assert.match(server,/req.url !== '\/mcp'/);
  assert.match(server,/createAccessVerifier/);
});
