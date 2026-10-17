import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync,randomUUID,sign } from 'node:crypto';
import { mkdtempSync,mkdirSync,writeFileSync,rmSync } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { createMachineAccessVerifier } from '../devices/machine-access.mjs';
import { startMachineIngressLoopback } from '../devices/machine-ingress-loopback.mjs';
import { createDeviceRegistry } from '../devices/registry.mjs';
import { createDeviceRouter } from '../devices/router.mjs';
import { createDurableMachineBindingStore } from '../devices/durable-machine-bindings.mjs';
import { ownerIdentityDigest,ownerPrincipalId } from '../dashboard/owner-identity.mjs';
import { createPairingCoordinator } from '../devices/pairing.mjs';
import { createEphemeralPairingIdentity } from '../../packages/vpsc-agent/src/pairing.mjs';
import { createLoopbackAgentClient } from '../../packages/vpsc-agent/src/loopback-client.mjs';
import { createLocalReadonlyMcp } from '../../packages/vpsc-agent/src/local-mcp-readonly.mjs';

const issuer='https://vpsc.cloudflareaccess.com';
const audience='b'.repeat(64),nowMs=1_800_000_000_000;
const nowSec=Math.floor(nowMs/1000);
const machine='machine1.access',other='machine2.access';
const MCP_FIXTURE=fileURLToPath(new URL('../../packages/vpsc-agent/test/fixtures-readonly-mcp.mjs',import.meta.url));
function makeJwt(privateKey,claims={}){
  const h=Buffer.from(JSON.stringify({alg:'RS256',kid:'kid1'})).toString('base64url');
  const body=Buffer.from(JSON.stringify({type:'app',sub:'',common_name:machine,
    iss:issuer,aud:audience,iat:nowSec-10,exp:nowSec+3600,...claims})).toString('base64url');
  return h+'.'+body+'.'+sign('RSA-SHA256',Buffer.from(h+'.'+body),privateKey).toString('base64url');
}
async function fixture(){
  const {publicKey,privateKey}=generateKeyPairSync('rsa',{modulusLength:2048});
  const jwk={...publicKey.export({format:'jwk'}),kid:'kid1',alg:'RS256'};
  const verifyMachineToken=createMachineAccessVerifier({issuer,audience,allowedClientIds:[machine],
    now:()=>nowMs,keyProvider:async()=>({keys:[jwk]})});
  const registry=createDeviceRegistry();
  const router=createDeviceRouter({registry,timeoutMs:6000});
  const pairing=createPairingCoordinator({registry});
  const identity=createEphemeralPairingIdentity();
  const req=pairing.startPairing({name:'Gui-PC demo',platform:'win32',publicKeyPem:identity.publicKeyPem});
  assert.equal(pairing.provePossession(req.requestId,identity.prove(req)),true);
  const {deviceId}=pairing.approvePairing(req.requestId,identity.fingerprint);
  const bindingDirectory=mkdtempSync(path.join(os.tmpdir(),'vpsc-machine-binding-test-'));
  const owner={issuer:'https://test.cloudflareaccess.com',subject:'m2m-test-owner'};
  const ownerId=ownerPrincipalId(owner),ownerDigest=ownerIdentityDigest(owner);
  const approvalReceipt={ownerId,deviceId,eventId:randomUUID(),fingerprint:identity.fingerprint,
    trustRevisionBefore:0,trustRevisionAfter:1,trustRevision:1};
  const bindingEventId=randomUUID(),intent={event:'g7_owner_machine_binding',version:3,
    eventId:bindingEventId,operation:'bind',ownerId,ownerDigest,clientId:machine,deviceId,
    fingerprint:identity.fingerprint,approvalEventId:approvalReceipt.eventId,
    trustRevisionBefore:0,trustRevisionAfter:1,trustRevision:1,bindingRevisionBefore:0,
    phase:'intent'};
  let decision={state:'NOT_FOUND',eventId:bindingEventId};
  const machineBindingStore=createDurableMachineBindingStore({directory:bindingDirectory,
    verifyApprovalReceipt:binding=>binding.ownerId===ownerId&&binding.deviceId===deviceId&&
      binding.fingerprint===identity.fingerprint?approvalReceipt:null,
    readBindingDecision:binding=>binding.bindingEventId===bindingEventId?decision:
      {state:'NOT_FOUND',eventId:binding.bindingEventId},
    readBindingHistory:()=>({completed:decision.state==='COMPLETE'?[decision]:[],
      pending:decision.state==='PENDING'?[decision]:[]})});
  decision={state:'PENDING',eventId:bindingEventId,intent,outcome:null};
  machineBindingStore.bind({bindingEventId,ownerId,ownerDigest,clientId:machine,deviceId,
    fingerprint:identity.fingerprint,approvalReceipt},{expectedRevision:0});
  decision={state:'COMPLETE',eventId:bindingEventId,intent,
    outcome:{...intent,phase:'outcome',outcome:'accepted',bindingRevisionAfter:1}};
  const ingress=await startMachineIngressLoopback({
    registry,router,verifyMachineToken,machineBindingStore,getTrustRevision:()=>1,enableTestIngress:true,
  });
  const jwt=makeJwt(privateKey);
  const signedFetch=(url,options)=>fetch(url,{...options,
    headers:{...options.headers,'cf-access-jwt-assertion':jwt}});
  const client=createLoopbackAgentClient({url:ingress.url,identity,deviceId,fetchFn:signedFetch});
  return {registry,router,identity,ingress,client,deviceId,privateKey,jwt,machineBindingStore,
    bindingDirectory,verifyMachineToken,close:async()=>{router.close();await ingress.close();machineBindingStore.close();
      rmSync(bindingDirectory,{recursive:true,force:true});}};
}
async function request(url,route,body,headers={}){
  const res=await fetch(url+route,{method:'POST',headers:{
    'content-type':'application/json',...headers,
  },body:JSON.stringify(body)});
  return {status:res.status,json:await res.json()};
}
test('loopback machine ingress denies activation and external listeners by default',async()=>{
  const registry=createDeviceRegistry(),router=createDeviceRouter({registry});
  await assert.rejects(startMachineIngressLoopback({registry,router}),/explicit loopback/);
  await assert.rejects(startMachineIngressLoopback({registry,router,
    enableTestIngress:true,host:'0.0.0.0',port:0,
    verifyMachineToken:async()=>({clientId:machine}),
    machineBindings:new Map([[machine,'f1a2b3c4-d5e6-4a9f-8abc-1bb9b99c0001']])}),/explicit loopback/);
  router.close();
});
test('anonymous agent cannot request pairing challenge, even if deviceId known',async()=>{
  const x=await fixture();
  try{
    const r=await request(x.ingress.url,'/agent/challenge',{deviceId:x.deviceId});
    assert.equal(r.status,401);
  }finally{await x.close();}
});
test('browser owner JWT cookie is not an agent service token',async()=>{
  const x=await fixture();
  try{
    const r=await request(x.ingress.url,'/agent/challenge',{deviceId:x.deviceId},
      {cookie:'CF_Authorization=some-owner-token'});
    assert.equal(r.status,401);
  }finally{await x.close();}
});
test('valid machine assertion alone does not bypass Ed25519 session signature',async()=>{
  const x=await fixture();
  try{
    const r=await request(x.ingress.url,'/agent/heartbeat',{},
      {'cf-access-jwt-assertion':x.jwt,'x-vpsc-device-id':x.deviceId});
    assert.equal(r.status,401);
  }finally{await x.close();}
});
test('machine identity is cryptographically bound to exact authorized device',async()=>{
  const x=await fixture();
  try{
    const wrongId='f1a2b3c4-d5e6-4a9f-8abc-1bb9b99c0009';
    const wrong=await request(x.ingress.url,'/agent/challenge',{deviceId:wrongId},
      {'cf-access-jwt-assertion':x.jwt});
    assert.equal(wrong.status,403);
    const anon=await request(x.ingress.url,'/agent/challenge',{deviceId:x.deviceId},
      {'cf-access-jwt-assertion':makeJwt(x.privateKey,{common_name:other})});
    assert.notEqual(anon.status,200);
  }finally{await x.close();}
});
test('durable Client-ID binding rejects a trusted deviceId with a different public-key fingerprint',async()=>{
  const x=await fixture();
  const replacement=createEphemeralPairingIdentity();
  const original=x.registry.snapshotTrustedDevices()[0];
  const mismatchedRegistry=createDeviceRegistry({initialTrustedDevices:[{...original,
    publicKeyPem:replacement.publicKeyPem,fingerprint:replacement.fingerprint}]});
  const mismatchedRouter=createDeviceRouter({registry:mismatchedRegistry});
  const ingress=await startMachineIngressLoopback({registry:mismatchedRegistry,router:mismatchedRouter,
    verifyMachineToken:x.verifyMachineToken,machineBindingStore:x.machineBindingStore,
    getTrustRevision:()=>1,enableTestIngress:true});
  try{
    const response=await request(ingress.url,'/agent/challenge',{deviceId:x.deviceId},
      {'cf-access-jwt-assertion':x.jwt});
    assert.equal(response.status,403);
  }finally{mismatchedRouter.close();await ingress.close();await x.close();}
});
test('M2M JWT bad issuer, audience and human sub rejected before agent challenge',async()=>{
  const x=await fixture();
  try{
    for(const claims of [{iss:'https://evil.cloudflareaccess.com'},{aud:'c'.repeat(64)},
      {sub:'human-id',email:'owner@example.com'},{exp:nowSec-3600}]){
      const r=await request(x.ingress.url,'/agent/challenge',{deviceId:x.deviceId},
        {'cf-access-jwt-assertion':makeJwt(x.privateKey,claims)});
      assert.equal(r.status,401);
    }
  }finally{await x.close();}
});
test('signed M2M ingress routes a real local MCP read-only operation without RDC transport',async()=>{
  const x=await fixture();
  const dir=mkdtempSync(path.join(os.tmpdir(),'vpsc-machine-ingress-test-'));
  const root=path.join(dir,'approved');
  mkdirSync(root);
  const file=path.join(root,'sample.txt');
  writeFileSync(file,'signed-machine-access-read\n');
  const agent=createLocalReadonlyMcp({allowedRoot:root,entrypoint:MCP_FIXTURE,timeoutMs:5000});
  try{
    await x.client.connect();await x.client.heartbeat();await agent.start();
    const pending=x.router.callDevice({deviceId:x.deviceId,name:'read_file',arguments:{path:file}});
    const frame=await x.client.poll();
    assert.equal(frame.deviceId,x.deviceId);
    const result=await agent.handle(frame);
    await x.client.result(frame.requestId,result);
    assert.match(JSON.stringify(await pending),/signed-machine-access-read/);
  }finally{agent.close();await x.close();rmSync(dir,{recursive:true,force:true});}
});
test('route and Origin restrictions apply before JWT verification',async()=>{
  const x=await fixture();
  try{
    const wrong=await request(x.ingress.url,'/mcp',{}, {'cf-access-jwt-assertion':x.jwt});
    assert.equal(wrong.status,404);
    const browser=await request(x.ingress.url,'/agent/challenge',{deviceId:x.deviceId},
      {origin:'https://hostile.example','cf-access-jwt-assertion':x.jwt});
    assert.equal(browser.status,403);
  }finally{await x.close();}
});
test('revoked Ed25519 trust is not rescued by still-valid machine JWT',async()=>{
  const x=await fixture();
  try{
    await x.client.connect();await x.client.heartbeat();
    x.registry.revokeDevice(x.deviceId);
    await assert.rejects(x.client.poll(),/403/);
  }finally{await x.close();}
});
