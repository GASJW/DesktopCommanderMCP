import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { generateKeyPairSync,sign } from 'node:crypto';
import { createAccessVerifier } from '../access-auth.mjs';
import { createOwnerPairingHttp } from '../dashboard/owner-pairing-http.mjs';
import { createDeviceRegistry } from '../devices/registry.mjs';
import { createPairingCoordinator } from '../devices/pairing.mjs';
import { createEphemeralPairingIdentity } from '../../packages/vpsc-agent/src/pairing.mjs';

const ISSUER='https://owner-test.cloudflareaccess.com';
const AUD='a'.repeat(64);
const ORIGIN='https://commander.supercerebro.me';
const OWNER='owner@example.com';
async function setup({auditWrite,now=Date.now}={}){
  const {publicKey,privateKey}=generateKeyPairSync('rsa',{modulusLength:2048});
  const jwk={...publicKey.export({format:'jwk'}),kid:'owner-kid',alg:'RS256'};
  const accessVerifier=createAccessVerifier({
    issuer:ISSUER,audience:AUD,allowedEmails:OWNER,
    keyProvider:async()=>({keys:[jwk]}),
  });
  const registry=createDeviceRegistry({now});
  const coordinator=createPairingCoordinator({registry,now});
  const identity=createEphemeralPairingIdentity();
  const pairing=coordinator.startPairing({
    name:'Gui-PC',platform:'win32',publicKeyPem:identity.publicKeyPem,
  });
  const audits=[];
  const persist=auditWrite??(async entry=>{audits.push(entry);return true;});
  const handle=createOwnerPairingHttp({
    coordinator,accessVerifier,expectedOrigin:ORIGIN,auditWrite:persist,now,
  });
  const server=createServer((req,res)=>{handle(req,res).catch(()=>{
    if(!res.writableEnded){res.statusCode=503;res.end();}
  });});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const url='http://127.0.0.1:'+server.address().port+'/dashboard/api/g7/pairing/';
  const createJwt=(overrides={})=>{
    const n=Math.floor(Date.now()/1000);
    const head=Buffer.from(JSON.stringify({kid:'owner-kid',alg:'RS256'})).toString('base64url');
    const body=Buffer.from(JSON.stringify({
      iss:ISSUER,aud:AUD,email:OWNER,sub:'person-123',iat:n-5,exp:n+3600,...overrides,
    })).toString('base64url');
    return head+'.'+body+'.'+sign('RSA-SHA256',Buffer.from(head+'.'+body),privateKey).toString('base64url');
  };
  const jwt=createJwt();
  const request=async(route,{method='GET',body,origin,csrf,token=jwt,headers={}}={})=>{
    const h={...headers};
    if(token!==null)h['cf-access-jwt-assertion']=token;
    if(origin!==undefined)h.origin=origin;
    if(csrf!==undefined)h['x-vpsc-csrf']=csrf;
    if(body!==undefined)h['content-type']='application/json';
    const res=await fetch(url+route,{method,headers:h,
      ...(body!==undefined?{body:JSON.stringify(body)}:{})});
    return {status:res.status,data:await res.json(),headers:res.headers};
  };
  const pending=()=>request('pending');
  const approvePayload=()=>({requestId:pairing.requestId,code:pairing.displayCode,
    expectedFingerprint:pairing.fingerprint});
  const proof=()=>coordinator.provePossession(pairing.requestId,identity.prove(pairing));
  const makePairing=(name='Gui-PC-2')=>{
    const nextIdentity=createEphemeralPairingIdentity();
    const next=coordinator.startPairing({
      name,platform:'win32',publicKeyPem:nextIdentity.publicKeyPem,
    });
    return {
      pairing:next,
      prove:()=>coordinator.provePossession(next.requestId,nextIdentity.prove(next)),
      approvePayload:()=>({requestId:next.requestId,code:next.displayCode,
        expectedFingerprint:next.fingerprint}),
      rejectPayload:()=>({requestId:next.requestId,
        expectedFingerprint:next.fingerprint}),
    };
  };
  const close=()=>new Promise(resolve=>server.close(resolve));
  return {registry,coordinator,identity,pairing,audits,request,pending,approvePayload,proof,
    makePairing,createJwt,close};
}
test('JWT valid owner sees pending list and session-bound CSRF; no code or secret leaked',async()=>{
  const x=await setup();
  try{
    const r=await x.pending();
    assert.equal(r.status,200);
    assert.equal(r.data.enabled,true);
    assert.ok(r.data.csrf.length>48);
    assert.equal(r.data.pending.length,1);
    assert.equal(r.data.pending[0].fingerprint,x.pairing.fingerprint);
    const body=JSON.stringify(r.data);
    assert.equal(body.includes(x.pairing.displayCode),false);
    assert.equal(body.includes(x.pairing.nonce),false);
    assert.match(r.headers.get('cache-control'),/no-store/);
    assert.equal(x.audits.length,0);
  }finally{await x.close();}
});
test('unauthenticated, forged, wrong audience and machine tokens cannot list pairing',async()=>{
  const x=await setup();
  try{
    for(const args of [
      {token:null},
      {token:'bad-jwt'},
      {token:x.createJwt({aud:'b'.repeat(64)})},
      {token:x.createJwt({email:'intruder@example.com'})},
      {token:x.createJwt({sub:'',type:'app',common_name:'machine.client'})},
    ]){
      const r=await x.request('pending',args);
      assert.equal(r.status,401);
    }
  }finally{await x.close();}
});
test('same-origin CSRF + JWT + device proof + code approve only once',async()=>{
  const x=await setup();
  try{
    const first=await x.pending();assert.equal(first.status,200);
    x.proof();
    const r=await x.request('approve',{method:'POST',origin:ORIGIN,csrf:first.data.csrf,
      body:x.approvePayload()});
    assert.equal(r.status,200);
    assert.equal(r.data.status,'approved_offline');
    assert.equal(x.registry.listDevices().length,1);
    assert.equal(x.registry.listDevices()[0].online,false);
    assert.deepEqual(x.audits.map(a=>a.phase),['intent','outcome']);
    const after=await x.request('approve',{method:'POST',origin:ORIGIN,csrf:first.data.csrf,
      body:x.approvePayload()});
    assert.equal(after.status,403);
    assert.equal(x.registry.listDevices().length,1);
  }finally{await x.close();}
});
test('owner may reject after signed proof; never registers device',async()=>{
  const x=await setup();
  try{
    const csrf=(await x.pending()).data.csrf;
    x.proof();
    const r=await x.request('reject',{method:'POST',origin:ORIGIN,csrf,
      body:{requestId:x.pairing.requestId,expectedFingerprint:x.pairing.fingerprint}});
    assert.equal(r.status,200);
    assert.equal(r.data.rejected,true);
    assert.equal(x.registry.listDevices().length,0);
    assert.equal((await x.pending()).data.pending.length,0);
  }finally{await x.close();}
});
test('cross-origin and cross-site submissions denied before any mutation',async()=>{
  const x=await setup();
  try{
    x.proof();
    const csrf=(await x.pending()).data.csrf;
    for(const args of [
      {origin:'https://evil.example.com',csrf},
      {csrf},
      {origin:ORIGIN},
      {origin:ORIGIN,csrf,headers:{'sec-fetch-site':'cross-site'}},
    ]){
      const r=await x.request('approve',{method:'POST',body:x.approvePayload(),...args});
      assert.equal(r.status,403);
    }
    assert.equal(x.registry.listDevices().length,0);
    assert.equal(x.audits.length,0);
  }finally{await x.close();}
});
test('CSRF cannot be reused by another signed owner subject',async()=>{
  const x=await setup();
  try{
    x.proof();
    const csrf=(await x.pending()).data.csrf;
    const token=x.createJwt({sub:'person-other'});
    const res=await x.request('approve',{method:'POST',origin:ORIGIN,csrf,
      body:x.approvePayload(),token});
    assert.equal(res.status,403);
    assert.equal(x.registry.listDevices().length,0);
  }finally{await x.close();}
});
test('invalid code or fingerprint denied and never logged as plaintext',async()=>{
  const x=await setup();
  try{
    x.proof();
    const csrf=(await x.pending()).data.csrf;
    const r=await x.request('approve',{method:'POST',origin:ORIGIN,csrf,
      body:{...x.approvePayload(),code:'AAAAA-AAAAA'}});
    assert.equal(r.status,403);
    assert.equal(x.registry.listDevices().length,0);
    assert.equal(x.audits.length,2);
    const events=JSON.stringify(x.audits);
    assert.equal(events.includes(x.pairing.displayCode),false);
    assert.equal(events.includes(x.pairing.nonce),false);
    assert.equal(events.includes(x.createJwt()),false);
  }finally{await x.close();}
});
test('audit intent write failure prevents trust mutation and poisons current handler',async()=>{
  const x=await setup({auditWrite:async()=>false});
  try{
    x.proof();
    const csrf=(await x.pending()).data.csrf;
    const r=await x.request('approve',{method:'POST',origin:ORIGIN,csrf,body:x.approvePayload()});
    assert.equal(r.status,503);
    assert.equal(x.registry.listDevices().length,0);
    assert.equal((await x.pending()).status,503);
  }finally{await x.close();}
});
test('failed post-commit audit never promises rejected operation: handler poisoned',async()=>{
  let count=0;
  const x=await setup({auditWrite:async()=>++count===1});
  try{
    x.proof();
    const csrf=(await x.pending()).data.csrf;
    const r=await x.request('approve',{method:'POST',origin:ORIGIN,csrf,body:x.approvePayload()});
    assert.equal(r.status,503);
    assert.match(r.data.error,/reconciliation/);
    assert.equal(x.registry.listDevices().length,1);
    assert.equal((await x.pending()).status,503);
  }finally{await x.close();}
});
test('rate limit bounds repeated owner mutation attempts',async()=>{
  const x=await setup();
  try{
    x.proof();const csrf=(await x.pending()).data.csrf;
    for(let i=0;i<6;i++){
      const r=await x.request('approve',{method:'POST',origin:ORIGIN,csrf,
        body:{...x.approvePayload(),code:'FFFFF-FFFFF'}});
      assert.equal(r.status,403);
    }
    const r=await x.request('approve',{method:'POST',origin:ORIGIN,csrf,body:x.approvePayload()});
    assert.equal(r.status,429);
    assert.equal(x.registry.listDevices().length,0);
  }finally{await x.close();}
});
test('invalid method, non-JSON, extra fields and oversized bodies denied safely',async()=>{
  const x=await setup();
  try{
    const csrf=(await x.pending()).data.csrf;
    assert.equal((await x.request('approve',{method:'GET'})).status,405);
    assert.equal((await x.request('missing')).status,404);
    assert.equal((await x.request('approve',{method:'POST',origin:ORIGIN,csrf})).status,415);
    const invalid=await x.request('approve',{method:'POST',origin:ORIGIN,csrf,
      body:{...x.approvePayload(),injected:'anything'}});
    assert.equal(invalid.status,400);
    const large=await x.request('approve',{method:'POST',origin:ORIGIN,csrf,
      body:{...x.approvePayload(),code:'x'.repeat(5000)}});
    assert.equal(large.status,413);
    assert.equal(x.registry.listDevices().length,0);
  }finally{await x.close();}
});
test('handler requires real verifier interface and mandatory audit sink',()=>{
  assert.throws(()=>createOwnerPairingHttp({}),/verifier/);
});

test('expired CSRF token is denied even with valid signed owner JWT',async()=>{
  let clock=Date.now();
  const x=await setup({now:()=>clock});
  try{
    x.proof();
    const csrf=(await x.pending()).data.csrf;
    clock+=5*60*1000+1;
    const r=await x.request('approve',{method:'POST',origin:ORIGIN,csrf,
      body:x.approvePayload()});
    assert.equal(r.status,403);
    assert.equal(x.registry.listDevices().length,0);
    assert.equal(x.audits.length,0);
  }finally{await x.close();}
});

test('concurrent decisions for the same request serialize without poisoning audit',async()=>{
  let active=0;
  const written=[];
  const x=await setup({auditWrite:async entry=>{
    if(active>0)return false;
    active++;
    try{
      await new Promise(resolve=>setTimeout(resolve,10));
      written.push(entry);
      return true;
    }finally{active--;}
  }});
  try{
    x.proof();
    const csrf=(await x.pending()).data.csrf;
    const args={method:'POST',origin:ORIGIN,csrf,body:x.approvePayload()};
    const results=await Promise.all([
      x.request('approve',args),
      x.request('approve',args),
    ]);
    assert.deepEqual(results.map(r=>r.status).sort(),[200,403]);
    assert.equal(x.registry.listDevices().length,1);
    assert.deepEqual(written.map(entry=>entry.phase),['intent','outcome','intent','outcome']);
    assert.equal((await x.pending()).status,200);
  }finally{await x.close();}
});

test('concurrent decisions for different requests serialize audit while preserving both outcomes',async()=>{
  let active=0;
  const written=[];
  const x=await setup({auditWrite:async entry=>{
    if(active>0)return false;
    active++;
    try{
      await new Promise(resolve=>setTimeout(resolve,10));
      written.push(entry);
      return true;
    }finally{active--;}
  }});
  try{
    const other=x.makePairing();
    x.proof();other.prove();
    const csrf=(await x.pending()).data.csrf;
    const [approved,rejected]=await Promise.all([
      x.request('approve',{method:'POST',origin:ORIGIN,csrf,body:x.approvePayload()}),
      x.request('reject',{method:'POST',origin:ORIGIN,csrf,body:other.rejectPayload()}),
    ]);
    assert.equal(approved.status,200);
    assert.equal(rejected.status,200);
    assert.equal(approved.data.status,'approved_offline');
    assert.equal(rejected.data.rejected,true);
    assert.equal(x.registry.listDevices().length,1);
    assert.deepEqual(written.map(entry=>entry.phase),['intent','outcome','intent','outcome']);
    assert.deepEqual(new Set(written.filter(entry=>entry.phase==='intent')
      .map(entry=>entry.operation)),new Set(['approve','reject']));
    assert.equal((await x.pending()).data.pending.length,0);
  }finally{await x.close();}
});

test('concurrent approval and rejection of one request produce one decision and keep audit usable',async()=>{
  let active=0;
  const written=[];
  const x=await setup({auditWrite:async entry=>{
    if(active>0)return false;
    active++;
    try{
      await new Promise(resolve=>setTimeout(resolve,10));
      written.push(entry);
      return true;
    }finally{active--;}
  }});
  try{
    x.proof();
    const csrf=(await x.pending()).data.csrf;
    const [approved,rejected]=await Promise.all([
      x.request('approve',{method:'POST',origin:ORIGIN,csrf,body:x.approvePayload()}),
      x.request('reject',{method:'POST',origin:ORIGIN,csrf,
        body:{requestId:x.pairing.requestId,expectedFingerprint:x.pairing.fingerprint}}),
    ]);
    assert.deepEqual([approved.status,rejected.status].sort(),[200,403]);
    assert.equal(x.registry.listDevices().length,approved.status===200?1:0);
    assert.deepEqual(written.map(entry=>entry.phase),['intent','outcome','intent','outcome']);
    assert.equal((await x.pending()).status,200);
  }finally{await x.close();}
});
test('CSRF substitution and malformed token are rejected without audit intent',async()=>{
  const x=await setup();
  try{
    x.proof();
    const csrf=(await x.pending()).data.csrf;
    for(const bad of [csrf.slice(0,-1)+'!',csrf.slice(1),csrf.replace(/.$/,'A'),'junk']){
      const r=await x.request('approve',{method:'POST',origin:ORIGIN,csrf:bad,
        body:x.approvePayload()});
      assert.equal(r.status,403);
    }
    assert.equal(x.registry.listDevices().length,0);
    assert.equal(x.audits.length,0);
  }finally{await x.close();}
});
