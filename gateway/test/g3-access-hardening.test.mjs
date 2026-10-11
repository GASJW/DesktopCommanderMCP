import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createAccessVerifier } from '../access-auth.mjs';
import { startGateway } from '../server.mjs';

const root=path.dirname(fileURLToPath(import.meta.url));
const fixture=path.join(root,'fixtures','mock-executor.mjs');
const issuer='https://example.cloudflareaccess.com';
const audience='a'.repeat(64);
const email='owner@example.test';
const keyPair=generateKeyPairSync('rsa',{modulusLength:2048});
const jwk={...keyPair.publicKey.export({format:'jwk'}),kid:'owner-kid',use:'sig',alg:'RS256'};
const now=()=>Math.floor(Date.now()/1000);
function token(claims={},header={}) {
  const h=Buffer.from(JSON.stringify({alg:'RS256',kid:'owner-kid',typ:'JWT',...header})).toString('base64url');
  const p=Buffer.from(JSON.stringify({iss:issuer,aud:audience,sub:'owner-subject',email,iat:now(),exp:now()+3600,...claims})).toString('base64url');
  const message=h+'.'+p;
  return message+'.'+sign('RSA-SHA256',Buffer.from(message),keyPair.privateKey).toString('base64url');
}
const params={issuer,audience,allowedEmails:email,keyProvider:async()=>({keys:[jwk]})};

test('G3.5 Access JWT duration and time consistency fail closed',async()=>{
  const verify=createAccessVerifier(params);
  assert.equal(await verify(token()),true);
  const invalid=[
    {iat:now()-3600*48,exp:now()+3600},
    {iat:now()+200,exp:now()+400},
    {iat:now()+60,exp:now()+10},
    {iat:now()-30,exp:now()-20},
    {iat:now()-60,exp:now()+86400*3},
    {iat:now()-60,exp:now()+100,nbf:now()+200},
    {iat:now()-60,exp:now()+200,nbf:now()+300},
  ];
  for(const claims of invalid)assert.equal(await verify(token(claims)),false,JSON.stringify(Object.keys(claims)));
  assert.equal(await verify(token({email:'other@example.test'})),false);
  assert.equal(await verify(token({sub:''})),false);
  assert.equal(await verify(token({aud:'b'.repeat(64)})),false);
  assert.equal(await verify(token({}, {alg:'none'})),false);
});

test('G3.5 OAuth gateway permits valid tools but refuses arbitrary RPC methods before executor',async()=>{
  const events=[];
  const gw=await startGateway({authMode:'access',accessIssuer:issuer,accessAudience:audience,
    allowedEmails:email,accessKeyProvider:params.keyProvider,
    executorFile:fixture,port:0,auditEnabled:true,auditSink:line=>events.push(JSON.parse(line))});
  const send=async(message,jwt=token())=>{
    const r=await fetch(gw.address+'/mcp',{method:'POST',headers:{'content-type':'application/json',
      ...(jwt?{'cf-access-jwt-assertion':jwt}:{})},body:JSON.stringify(message)});
    return {status:r.status,data:await r.json().catch(()=>null)};
  };
  const rpc=(id,method,params={})=>({jsonrpc:'2.0',id,method,params});
  try {
    assert.equal((await send(rpc(1,'tools/list'))).status,200);
    assert.equal((await send(rpc(2,'tools/call',{name:'echo',arguments:{text:'G3_5_OWNER_VALID'}}))).status,200);
    assert.equal((await send(rpc(3,'tools/list'),token({email:'intruder@example.test'}))).status,401);
    assert.equal((await send(rpc(4,'tools/list'),'' )).status,401);
    for(const method of ['shutdown','roots/list','sampling/createMessage','some/internal/method','logging/setLevel']){
      const out=await send(rpc('opaque-identifier',method,{secret:'SECRET_SHOULD_NOT_APPEAR'}));
      assert.equal(out.status,404,method);
      assert.equal(out.data.error.code,-32601);
    }
    for(const [method,params] of [
      ['tools/call',{name:'../bad-tool',arguments:{}}],
      ['tools/call',{name:'echo',arguments:['unexpected']}],
      ['tools/call',{arguments:{}}],
      ['tools/call',{name:'echo',arguments:null}],
    ]){
      const out=await send(rpc(9,method,params));
      assert.equal(out.status,400);
      assert.equal(out.data.error.code,-32602);
    }
    for(const invalidId of [null,[],{},true,1.5]){
      const out=await send(rpc(invalidId,'tools/list'));
      assert.equal(out.status,400);
    }
    const notice=await fetch(gw.address+'/mcp',{method:'POST',headers:{'content-type':'application/json',
      'cf-access-jwt-assertion':token()},body:JSON.stringify({jsonrpc:'2.0',method:'notifications/initialized'})});
    assert.equal(notice.status,202);
    assert.equal((await send(rpc(18,'notifications/initialized'))).status,400);
    assert.equal((await send({jsonrpc:'2.0',method:'tools/call',params:{name:'echo',arguments:{text:'not-executed'}}})).status,400);
    const serialized=JSON.stringify(events);
    assert.equal(serialized.includes('SECRET_SHOULD_NOT_APPEAR'),false);
    assert.equal(serialized.includes('intruder@example.test'),false);
    assert.equal(serialized.includes('owner@example.test'),false);
    assert.equal(serialized.includes('G3_5_OWNER_VALID'),false);
    assert.ok(events.some(e=>e.outcome==='denied'));
    assert.ok(events.some(e=>e.outcome==='invalid_request'));
  } finally { await gw.close(); }
});
