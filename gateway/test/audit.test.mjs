import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { startGateway } from '../server.mjs';
import { verifiedPrincipalId } from '../audit.mjs';

const dir=path.dirname(fileURLToPath(import.meta.url));
const mock=path.join(dir,'fixtures','mock-executor.mjs');
const issuer='https://example.cloudflareaccess.com';
const audience='d'.repeat(64);
const email='owner@example.test';
const pair=generateKeyPairSync('rsa',{modulusLength:2048});
const publicJwk={...pair.publicKey.export({format:'jwk'}),kid:'key1',alg:'RS256',use:'sig'};
const now=()=>Math.floor(Date.now()/1000);
function jwt(sub='owner-sub',subjectEmail=email) {
  const h=Buffer.from(JSON.stringify({alg:'RS256',kid:'key1'})).toString('base64url');
  const p=Buffer.from(JSON.stringify({iss:issuer,aud:[audience],sub,email:subjectEmail,iat:now(),exp:now()+300})).toString('base64url');
  const message=h+'.'+p;
  return message+'.'+sign('RSA-SHA256',Buffer.from(message),pair.privateKey).toString('base64url');
}
const wait=()=>new Promise(resolve=>setImmediate(resolve));
test('validated principal pseudonym is stable and rejects raw email',()=>{
  const ident=verifiedPrincipalId({issuer,subject:'owner-sub'});
  assert.match(ident,/^cf_[0-9a-f]{24}$/);
  assert.equal(ident,verifiedPrincipalId({issuer,subject:'owner-sub'}));
  assert.notEqual(ident,verifiedPrincipalId({issuer,subject:'different'}));
  assert.equal(verifiedPrincipalId(null),'anonymous');
});

test('Access gateway audit records action, verified subject, duration and result without request secrets',async()=>{
  const records=[];
  const app=await startGateway({authMode:'access',accessIssuer:issuer,accessAudience:audience,
    allowedEmails:email,accessKeyProvider:async()=>({keys:[publicJwk]}),
    executorFile:mock,port:0,auditEnabled:true,auditSink:line=>records.push(JSON.parse(line))});
  async function post(body,header) {
    const res=await fetch(app.address+'/mcp',{method:'POST',
      headers:{'content-type':'application/json',...(header?{'cf-access-jwt-assertion':header}:{})},
      body:JSON.stringify(body)});
    await res.text(); await wait(); return res.status;
  }
  const call={jsonrpc:'2.0',id:'sensitive-id',method:'tools/call',
    params:{name:'echo',arguments:{text:'PRIVATE_COMMAND_VALUE SECRET_TOKEN_123'}}};
  try {
    assert.equal(await post(call),401);
    assert.equal(await post(call,jwt('owner-sub','other@example.test')),401);
    assert.equal(await post(call,jwt()),200);
    const ok=records.find(x=>x.operation==='tools/call'&&x.outcome==='ok');
    assert.ok(ok);
    assert.equal(ok.event,'vps_commander_audit');
    assert.equal(ok.version,1);
    assert.equal(ok.tool,'echo');
    assert.equal(ok.identity,verifiedPrincipalId({issuer,subject:'owner-sub'}));
    assert.equal(ok.route,'mcp'); assert.equal(ok.http_method,'POST');
    assert.equal(ok.http_status,200);
    assert.match(ok.started_at,/^\d{4}-\d\d-\d\dT/);
    assert.ok(ok.duration_ms>=0);
    assert.match(ok.request_id,/^[0-9a-f-]{36}$/);
    assert.equal(records.filter(x=>x.outcome==='denied').length,2);
    const serialized=JSON.stringify(records);
    for (const forbidden of ['PRIVATE_COMMAND_VALUE','SECRET_TOKEN_123',
      'sensitive-id','other@example.test','owner@example.test',jwt()])
      assert.equal(serialized.includes(forbidden),false,forbidden.slice(0,15));
  } finally {await app.close();}
});

test('audit uses only allowlisted method/tool identifiers and never includes command paths',async()=>{
  const records=[];
  const secret='CREDENTIAL_WILL_NOT_APPEAR';
  const token='a'.repeat(64);
  const app=await startGateway({authMode:'local',token,executorFile:mock,port:0,auditEnabled:true,
    auditSink:line=>records.push(JSON.parse(line))});
  try {
    const res=await fetch(app.address+'/mcp',{method:'POST',headers:{authorization:'Bearer '+token,
      'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:'ignored',
      method:'tools/call',params:{name:'../'+secret,arguments:{command:secret,path:'/private/very-secret'}}})});
    assert.equal(res.status,400); await res.text(); await wait();
    const event=records.find(x=>x.operation==='tools/call');
    assert.ok(event); assert.equal(event.tool,'unknown');
    assert.equal(event.identity,'local-authenticated');
    assert.equal(JSON.stringify(records).includes(secret),false);
    assert.equal(JSON.stringify(records).includes('/private/'),false);
  } finally {await app.close();}
});
