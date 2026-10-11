import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync, sign} from 'node:crypto';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createDashboardMetrics} from '../dashboard/metrics.mjs';
import {startGateway} from '../server.mjs';

const fixture=path.join(path.dirname(fileURLToPath(import.meta.url)),'fixtures/mock-executor.mjs');
const issuer='https://dashboard.cloudflareaccess.com',audience='b'.repeat(64),email='owner@example.test';
const pair=generateKeyPairSync('rsa',{modulusLength:2048});
const jwk={...pair.publicKey.export({format:'jwk'}),kid:'dashboard-key',use:'sig',alg:'RS256'};
function token(claims={}) {
  const t=Math.floor(Date.now()/1000);
  const h=Buffer.from(JSON.stringify({alg:'RS256',kid:jwk.kid})).toString('base64url');
  const p=Buffer.from(JSON.stringify({iss:issuer,aud:audience,sub:'owner-sub',email,iat:t,exp:t+1000,...claims})).toString('base64url');
  return h+'.'+p+'.'+sign('RSA-SHA256',Buffer.from(h+'.'+p),pair.privateKey).toString('base64url');
}
const events=[];
const opts={authMode:'access',accessIssuer:issuer,accessAudience:audience,
  allowedEmails:email,accessKeyProvider:async()=>({keys:[jwk]}),
  executorFile:fixture,port:0,auditEnabled:true,auditSink:line=>events.push(JSON.parse(line))};
test('Dashboard metrics only store safe aggregates and exclude dashboard polling',()=>{
  let tick=Date.UTC(2026,9,11,10,0,0);
  const store=createDashboardMetrics({now:()=>tick});
  store.record({event:'vps_commander_audit',route:'mcp',operation:'tools/call',tool:'start_process',
    identity:'cf_'+'a'.repeat(24),duration_ms:25,outcome:'ok'});
  store.record({event:'vps_commander_audit',route:'mcp',operation:'tools/call',tool:'start_process',
    identity:'cf_'+'a'.repeat(24),duration_ms:70,outcome:'tool_error'});
  store.record({event:'vps_commander_audit',route:'mcp',operation:'tools/call',tool:'../bad',
    identity:'anonymous',duration_ms:0,outcome:'denied'});
  store.record({event:'vps_commander_audit',route:'dashboard',operation:'unknown',outcome:'ok'});
  const data=store.snapshot();
  assert.equal(data.totals.mcp,3);
  assert.equal(data.totals.requests,4);
  assert.equal(data.totals.tools,3);
  assert.equal(data.totals.errors,1);
  assert.equal(data.totals.denied,1);
  assert.equal(data.clients.active_15m,1);
  assert.equal(data.top_tools[0].name,'start_process');
  assert.equal(data.top_tools[0].calls,2);
  assert.equal(data.minutes.at(-1).calls,3);
  assert.equal(data.latency.p95_ms,70);
  assert.doesNotMatch(JSON.stringify(data),/cf_aaaaaaaa|Bearer |email|token|secret|command/);
  tick+=16*60*1000;
  assert.equal(store.snapshot().clients.active_15m,0);
});
test('Dashboard requires real signed owner Access JWT; serves only known routes',async()=>{
  const gw=await startGateway(opts);
  const go=async(route='/dashboard',headers={},method='GET')=>fetch(gw.address+route,{method,
    headers:{'cf-access-jwt-assertion':token(),...headers}});
  try {
    assert.equal((await fetch(gw.address+'/dashboard')).status,401);
    assert.equal((await go('/dashboard',{'cf-access-jwt-assertion':token({email:'intruder@example.test'})})).status,401);
    const home=await go();
    assert.equal(home.status,200);
    assert.match(await home.text(),/COMMANDER/);
    assert.match(home.headers.get('content-security-policy'),/default-src 'none'/);
    assert.match(home.headers.get('cache-control'),/no-store/);
    for(const item of ['/dashboard/app.js','/dashboard/style.css']) {
      const res=await go(item);assert.equal(res.status,200);assert.ok((await res.text()).length>100);
    }
    const metrics=await go('/dashboard/metrics');
    assert.equal(metrics.status,200);
    const data=await metrics.json();
    assert.equal(data.system.device.type,'VPS');
    assert.equal(data.system.device.inventory_count,1);
    assert.equal(typeof data.health.executor_connected,'boolean');
    assert.equal(typeof data.clients.active_15m,'number');
    assert.equal(data.totals.mcp,0);
    assert.equal((await go('/dashboard/metrics',{},'POST')).status,405);
    assert.equal((await go('/dashboard/metrics',{origin:'https://evil.test'})).status,403);
    assert.equal((await go('/dashboard/../../etc/passwd')).status,404);
    assert.equal((await go('/dashboard/metrics?verbose=true')).status,404);
    assert.ok(events.every(e=>!JSON.stringify(e).includes('owner@example.test')));
    const rpc=await fetch(gw.address+'/mcp',{method:'POST',headers:{
      'cf-access-jwt-assertion':token(),'content-type':'application/json'},
      body:JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/list'})});
    assert.equal(rpc.status,200);
    await new Promise(r=>setTimeout(r,15));
    const last=(await (await go('/dashboard/metrics')).json());
    assert.equal(last.totals.mcp,1);
    assert.equal(last.clients.active_15m,1);
    assert.ok(last.top_tools.length===0);
    assert.ok(events.some(e=>e.route==='dashboard'));
  } finally { await gw.close(); }
});
test('Dashboard unavailable in legacy local bearer mode, including valid local bearer',async()=>{
  const gw=await startGateway({authMode:'local',token:'x'.repeat(48),executorFile:fixture,port:0});
  try {
    const res=await fetch(gw.address+'/dashboard',{headers:{authorization:'Bearer '+'x'.repeat(48)}});
    assert.equal(res.status,404);
  } finally { await gw.close(); }
});
