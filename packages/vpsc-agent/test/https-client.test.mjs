import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync,sign } from 'node:crypto';
import { mkdirSync,mkdtempSync,rmSync,writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHttpsAgentClient } from '../src/https-client.mjs';
import { createEphemeralPairingIdentity } from '../src/pairing.mjs';
import { createLocalReadonlyMcp } from '../src/local-mcp-readonly.mjs';
import { createMachineAccessVerifier } from '../../../gateway/devices/machine-access.mjs';
import { startMachineIngressLoopback } from '../../../gateway/devices/machine-ingress-loopback.mjs';
import { createDeviceRegistry } from '../../../gateway/devices/registry.mjs';
import { createPairingCoordinator } from '../../../gateway/devices/pairing.mjs';
import { createDeviceRouter } from '../../../gateway/devices/router.mjs';

const HOST='devices.example.test';
const BASE_URL='https://'+HOST+'/';
const CLIENT='edge-agent-test.access';
const SECRET='synthetic-test-secret-not-production-0001';
const DEVICE='f1a2b3c4-d5e6-4a9f-8abc-1bb9b99c0001';
const SESSION='f1a2b3c4-d5e6-4a9f-8abc-1bb9b99c0002';
const ISSUER='https://vpsc.cloudflareaccess.com';
const AUD='c'.repeat(64),T=1_800_000_000_000,SEC=Math.floor(T/1000);
const MCP_FIXTURE=fileURLToPath(new URL('./fixtures-readonly-mcp.mjs',import.meta.url));
function jwt(privateKey){
  const a=Buffer.from(JSON.stringify({alg:'RS256',kid:'kid'})).toString('base64url');
  const b=Buffer.from(JSON.stringify({type:'app',sub:'',common_name:CLIENT,
    aud:AUD,iss:ISSUER,iat:SEC-10,exp:SEC+3600})).toString('base64url');
  return a+'.'+b+'.'+sign('RSA-SHA256',Buffer.from(a+'.'+b),privateKey).toString('base64url');
}
async function harness(){
  const registry=createDeviceRegistry(),router=createDeviceRouter({registry,timeoutMs:5000});
  const pairing=createPairingCoordinator({registry});
  const identity=createEphemeralPairingIdentity();
  const request=pairing.startPairing({name:'test-Windows',platform:'win32',
    publicKeyPem:identity.publicKeyPem});
  pairing.provePossession(request.requestId,identity.prove(request));
  const {deviceId}=pairing.approvePairing(request.requestId,identity.fingerprint);
  const {publicKey,privateKey}=generateKeyPairSync('rsa',{modulusLength:2048});
  const jwk={...publicKey.export({format:'jwk'}),kid:'kid',alg:'RS256'};
  const verifyMachineToken=createMachineAccessVerifier({issuer:ISSUER,audience:AUD,
    allowedClientIds:[CLIENT],now:()=>T,keyProvider:async()=>({keys:[jwk]})});
  const ingress=await startMachineIngressLoopback({registry,router,
    verifyMachineToken,machineBindings:new Map([[CLIENT,deviceId]]),
    enableTestIngress:true});
  const assertion=jwt(privateKey);
  const observed=[];
  // Fake Cloudflare EDGE for unit/E2E only: remap a validated HTTPS request to
  // the test-only HTTP loopback ingress after checking a synthetic service token.
  const fakeEdge=async (input,opts)=>{
    const u=new URL(input);
    observed.push({url:input,headers:{...opts.headers},redirect:opts.redirect});
    assert.equal(u.protocol,'https:');
    assert.equal(u.hostname,HOST);
    if(opts.headers['cf-access-client-id']!==CLIENT||
       opts.headers['cf-access-client-secret']!==SECRET){
      return new Response(JSON.stringify({error:'Edge rejects service token'}),
        {status:403,headers:{'content-type':'application/json'}});
    }
    const headers={...opts.headers};
    delete headers['cf-access-client-id'];
    delete headers['cf-access-client-secret'];
    headers['cf-access-jwt-assertion']=assertion;
    return fetch(ingress.url+u.pathname,{
      ...opts,headers,redirect:'error',
    });
  };
  const client=createHttpsAgentClient({gatewayUrl:BASE_URL,expectedHostname:HOST,
    identity,deviceId,clientId:CLIENT,clientSecret:SECRET,fetchFn:fakeEdge});
  const close=async()=>{client.close();router.close();await ingress.close();};
  return {client,router,identity,deviceId,ingress,observed,close};
}
function makeInvalid(overrides={}){
  const identity=createEphemeralPairingIdentity();
  return {gatewayUrl:BASE_URL,expectedHostname:HOST,identity,
    deviceId:'f1a2b3c4-d5e6-4a9f-8abc-1bb9b99c0001',
    clientId:CLIENT,clientSecret:SECRET, ...overrides};
}
test('reject HTTP, credentials in URL, other hosts, IP and untrusted port',()=>{
  for(const gatewayUrl of [
    'http://devices.example.test','https://evil.example.test/',
    'https://user:pass@devices.example.test/',
    'https://devices.example.test:8443/',
    'https://devices.example.test/agent/poll',
    'https://127.0.0.1/','https://devices.example.test/?token=abc',
  ])assert.throws(()=>createHttpsAgentClient(makeInvalid({gatewayUrl})),/Gateway URL/);
});
test('reject weak configuration, missing token, unknown identity and unpinned hostname',()=>{
  for(const override of [
    {expectedHostname:'localhost'},{clientId:'a'},{clientSecret:'short'},
    {clientSecret:'good-secret-with-\r\n-injection'},
    {deviceId:'fake'}, {identity:null}, {timeoutMs:120_000}
  ])assert.throws(()=>createHttpsAgentClient(makeInvalid(override)),e=>e.code==='CONFIG');
});
test('durably approved identity cannot be routed as another device or Client-ID',()=>{
  const raw=createEphemeralPairingIdentity();
  const identity={...raw,deviceBinding:{deviceId:DEVICE,clientId:CLIENT,
    fingerprint:raw.fingerprint,approvalEventId:'f1a2b3c4-d5e6-4a9f-8abc-1bb9b99c0003',
    trustRevisionBefore:0,trustRevisionAfter:1,trustRevision:1}};
  assert.throws(()=>createHttpsAgentClient(makeInvalid({identity,
    deviceId:'f1a2b3c4-d5e6-4a9f-8abc-1bb9b99c0004'})),e=>e.code==='CONFIG');
  assert.throws(()=>createHttpsAgentClient(makeInvalid({identity,clientId:'other-agent.access'})),
    e=>e.code==='CONFIG');
});
test('legacy partial device binding cannot authorize HTTPS transport before v3 migration',()=>{
  const identity=createEphemeralPairingIdentity();
  const legacyDeviceBinding={deviceId:DEVICE,clientId:CLIENT,fingerprint:identity.fingerprint,
    approvalEventId:'f1a2b3c4-d5e6-4a9f-8abc-1bb9b99c0003',trustRevisionBefore:0,
    trustRevisionAfter:1,trustRevision:1};
  assert.throws(()=>createHttpsAgentClient(makeInvalid({identity:{...identity,
    deviceBinding:null,legacyDeviceBinding}})),error=>error.code==='CONFIG');
});
test('HTTPS agent sends Service Token headers to edge and signs device frames',async()=>{
  const x=await harness();
  try{
    await x.client.connect();
    await x.client.heartbeat();
    await x.client.poll();
    const urls=x.observed.map(v=>v.url);
    assert.ok(urls.includes(BASE_URL+'agent/challenge'));
    assert.ok(urls.includes(BASE_URL+'agent/connect'));
    assert.ok(urls.includes(BASE_URL+'agent/heartbeat'));
    assert.ok(urls.includes(BASE_URL+'agent/poll'));
    for(const item of x.observed){
      assert.equal(item.headers['cf-access-client-id'],CLIENT);
      assert.equal(item.headers['cf-access-client-secret'],SECRET);
      assert.equal(item.redirect,'error');
      assert.equal(item.headers['cf-access-jwt-assertion'],undefined);
    }
    const signed=x.observed.find(v=>v.url===BASE_URL+'agent/poll');
    assert.ok(signed.headers['x-vpsc-signature']);
  }finally{await x.close();}
});
test('agent disconnect explicitly invalidates its signed Gateway session',async()=>{
  const x=await harness();
  try{
    await x.client.connect();
    await x.client.heartbeat();
    assert.deepEqual(await x.client.disconnect(),{disconnected:true});
    await assert.rejects(x.client.heartbeat(),error=>error.code==='NOT_CONNECTED');
    assert.ok(x.observed.some(item=>item.url===BASE_URL+'agent/disconnect'));
  }finally{await x.close();}
});
test('two layers authenticate an actual local MCP fixture read and return through router',async()=>{
  const x=await harness();
  const tmp=mkdtempSync(path.join(os.tmpdir(),'vpsc-https-agent-test-'));
  const dir=path.join(tmp,'approved');
  mkdirSync(dir);
  const file=path.join(dir,'hello.txt');
  writeFileSync(file,'end-to-end-device-signed-read\n');
  const executor=createLocalReadonlyMcp({allowedRoot:dir,entrypoint:MCP_FIXTURE,timeoutMs:5000});
  try{
    await x.client.connect();await x.client.heartbeat();await executor.start();
    const pending=x.router.callDevice({deviceId:x.deviceId,name:'read_file',arguments:{path:file}});
    const task=await x.client.poll();
    const value=await executor.handle(task);
    await x.client.result(task.requestId,value);
    assert.match(JSON.stringify(await pending),/end-to-end-device-signed-read/);
  }finally{await executor.close();await x.close();rmSync(tmp,{recursive:true,force:true});}
});
test('HTTPS client closes fail-closed and prevents further messages',async()=>{
  const x=await harness();
  await x.client.connect();
  x.client.close();
  await assert.rejects(x.client.heartbeat(),e=>e.code==='CLOSED');
  x.router.close();await x.ingress.close();
});
test('network error is ambiguous and never retried or exposes service secret',async()=>{
  let calls=0;
  const client=createHttpsAgentClient(makeInvalid({fetchFn:async()=>{
    calls++;throw Error('network interrupted');
  }}));
  await assert.rejects(client.connect(),e=>e.code==='AMBIGUOUS_TRANSPORT'&&
    !e.message.includes(SECRET));
  assert.equal(calls,1);
  client.close();
});
test('edge rejection never triggers JWT shortcut or client credential leakage',async()=>{
  const client=createHttpsAgentClient(makeInvalid({
    fetchFn:async()=>new Response(JSON.stringify({error:'no'}),{
      status:403,headers:{'content-type':'application/json'}
    }),
  }));
  await assert.rejects(client.connect(),e=>e.code==='REJECTED'&&
    !e.message.includes(SECRET));
  client.close();
});
test('redirection, non-JSON and oversized response fail closed',async()=>{
  const redirect=createHttpsAgentClient(makeInvalid({
    fetchFn:async()=>{throw TypeError('fetch redirect rejected');},
  }));
  await assert.rejects(redirect.connect(),e=>e.code==='AMBIGUOUS_TRANSPORT');
  const wrong=createHttpsAgentClient(makeInvalid({
    fetchFn:async()=>new Response('not-json',{status:200,
      headers:{'content-type':'text/plain'}}),
  }));
  await assert.rejects(wrong.connect(),e=>e.code==='AMBIGUOUS_TRANSPORT');
  redirect.close();wrong.close();
});
test('a processed result followed by HTTP 503 is ambiguous and never replayed',async()=>{
  const routes=[];let processed=0;
  const client=createHttpsAgentClient(makeInvalid({fetchFn:async(input,options)=>{
    const route=new URL(input).pathname;routes.push(route);
    if(route==='/agent/challenge')return new Response(JSON.stringify({deviceId:DEVICE,
      expiresInMs:30_000,nonce:'n'.repeat(43)}),{
      status:200,headers:{'content-type':'application/json'},
    });
    if(route==='/agent/connect')return new Response(JSON.stringify({deviceId:DEVICE,sessionId:SESSION}),{
      status:200,headers:{'content-type':'application/json'},
    });
    if(route==='/agent/result'){
      processed++;
      return new Response('{"error":"response lost after acceptance"}',{
        status:503,headers:{'content-type':'application/json'},
      });
    }
    return new Response('{"status":"alive"}',{status:200,
      headers:{'content-type':'application/json'}});
  }}));
  try{
    await client.connect();
    await assert.rejects(client.result('f1a2b3c4-d5e6-4a9f-8abc-1bb9b99c0003',{
      content:[{type:'text',text:'completed'}],
    }),error=>error.code==='AMBIGUOUS_TRANSPORT');
    assert.equal(processed,1);
    assert.equal(routes.filter(route=>route==='/agent/result').length,1);
  }finally{client.close();}
});

test('successful HTTP with malformed route acknowledgement is ambiguous and fences client',async()=>{
  for(const route of ['/agent/heartbeat','/agent/poll','/agent/result']){
    const client=createHttpsAgentClient(makeInvalid({fetchFn:async(input)=>{
      const pathname=new URL(input).pathname;
      const payload=pathname==='/agent/challenge'
        ?{deviceId:DEVICE,expiresInMs:30_000,nonce:'n'.repeat(43)}
        :pathname==='/agent/connect'?{deviceId:DEVICE,sessionId:SESSION}
        :pathname===route?{}:{status:'alive',deviceId:DEVICE};
      return new Response(JSON.stringify(payload),{status:200,
        headers:{'content-type':'application/json'}});
    }}));
    try{
      await client.connect();
      const invoke=route==='/agent/heartbeat'?()=>client.heartbeat():
        route==='/agent/poll'?()=>client.poll():
        ()=>client.result('f1a2b3c4-d5e6-4a9f-8abc-1bb9b99c0003',{content:[]});
      await assert.rejects(invoke(),error=>error.code==='AMBIGUOUS_TRANSPORT');
      await assert.rejects(client.heartbeat(),error=>error.code==='CLOSED');
    }finally{client.close();}
  }
});

test('malformed connect acknowledgement fences a potentially created session',async()=>{
  const client=createHttpsAgentClient(makeInvalid({fetchFn:async(input)=>{
    const pathname=new URL(input).pathname;
    const payload=pathname==='/agent/challenge'
      ?{deviceId:DEVICE,expiresInMs:30_000,nonce:'n'.repeat(43)}
      :{deviceId:DEVICE};
    return new Response(JSON.stringify(payload),{status:200,
      headers:{'content-type':'application/json'}});
  }}));
  await assert.rejects(client.connect(),error=>error.code==='AMBIGUOUS_TRANSPORT');
  await assert.rejects(client.connect(),error=>error.code==='CLOSED');
  client.close();
});
