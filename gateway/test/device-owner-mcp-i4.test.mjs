import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import path from 'node:path';
import os from 'node:os';
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { createHash, generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import { createAccessVerifier } from '../access-auth.mjs';
import { createDurableToolGrantStore } from '../devices/durable-tool-grants.mjs';
import { createRemoteDeviceMcpHandler } from '../devices/remote-mcp-handler.mjs';
import { verifyToolGrantCapability } from '../devices/tool-grant-capability.mjs';

const ISSUER='https://i4-owner-test.cloudflareaccess.com';
const AUD='e'.repeat(64);
const DEVICE='b7e92caf-f591-44c4-8fb7-6c489ea573f4';
const SESSION='ab000000-0000-4000-8000-000000000001';
const APPROVAL_EVENT='b7e92caf-f591-44c4-8fb7-6c489ea573f5';
const FINGERPRINT='b'.repeat(64);

async function setup(t,{authorizeDevice=()=>true,getTrustRevision=()=>7,grant=true}={}){
  const {publicKey,privateKey}=generateKeyPairSync('rsa',{modulusLength:2048});
  const jwk={...publicKey.export({format:'jwk'}),kid:'i4-owner',alg:'RS256'};
  const accessVerifier=createAccessVerifier({issuer:ISSUER,audience:AUD,
    allowedEmails:'owner@example.com',keyProvider:async()=>({keys:[jwk]})});
  const now=Math.floor(Date.now()/1000);
  const h=Buffer.from(JSON.stringify({alg:'RS256',kid:'i4-owner'})).toString('base64url');
  const p=Buffer.from(JSON.stringify({iss:ISSUER,aud:AUD,email:'owner@example.com',sub:'owner-i4',
    iat:now-1,exp:now+300})).toString('base64url');
  const token=h+'.'+p+'.'+sign('RSA-SHA256',Buffer.from(h+'.'+p),privateKey).toString('base64url');
  const directory=mkdtempSync(path.join(os.tmpdir(),'g7-owner-i4-grant-'));
  const policyDirectory=path.join(directory,'policy');mkdirSync(policyDirectory,{mode:0o700});
  const grantStore=createDurableToolGrantStore({directory:policyDirectory});
  const ownerDigest=createHash('sha256').update('VPSC-I4-OWNER-v1\n')
    .update(JSON.stringify([ISSUER,'owner-i4'])).digest('hex');
  if(grant)grantStore.grant({ownerDigest,deviceId:DEVICE,fingerprint:FINGERPRINT,tool:'read_file',
    scope:{root:'/approved'},constraints:{maxBytes:64*1024,maxLength:1000,maxOffset:100_000}},
  {expectedRevision:0,eventId:randomUUID()});
  const policyKeys=generateKeyPairSync('ed25519');
  const calls=[];
  const router={callDevice:async({beforeDispatch,...frame})=>{
    const permit=await beforeDispatch({deviceId:frame.deviceId,sessionId:SESSION,
      requestId:frame.requestId,name:frame.name,arguments:frame.arguments});
    try{calls.push({...frame,authorization:permit.authorization});}
    finally{permit.release();}
    return {content:[{type:'text',text:'ok'}]};
  }};
  const deviceRegistry={listDevices:()=>[{deviceId:DEVICE}],isLiveSession:()=>true};
  const trustStore={
    acquireDispatchPermit:({expectedRevision})=>{
      if(getTrustRevision()!==expectedRevision)throw Object.assign(Error('stale'),{code:'TRUST_CHANGED'});
      return {trustRevision:expectedRevision,release:()=>true};
    },
    withCurrentSession:({expectedRevision},callback)=>{
      if(getTrustRevision()!==expectedRevision)throw Object.assign(Error('stale'),{code:'TRUST_SESSION_STALE'});
      return callback();
    },
  };
  const handler=createRemoteDeviceMcpHandler({accessVerifier,
    deviceRegistry,trustStore,router,
    authorizeDevice,grantStore,policySigningKey:policyKeys.privateKey,getTrustRevision,
    getDeviceApprovalReceipt:()=>({eventId:APPROVAL_EVENT,deviceId:DEVICE,fingerprint:FINGERPRINT,
      trustRevisionBefore:6,trustRevisionAfter:7,trustRevision:7}),
  });
  const server=createServer(handler);
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  t.after(async()=>{await new Promise(resolve=>server.close(resolve));rmSync(directory,{recursive:true,force:true});});
  const endpoint=`http://127.0.0.1:${server.address().port}/mcp`;
  const call=async payload=>{
    const response=await fetch(endpoint,{method:'POST',headers:{'content-type':'application/json',
      'cf-access-jwt-assertion':token},body:JSON.stringify(payload)});
    return {status:response.status,body:response.status===202?null:await response.json()};
  };
  return {call,calls,grantStore,ownerDigest,policyKeys};
}

test('I4 tool catalogue lists bounded filesystem, create-only write, process and fixed-profile tools',async t=>{
  const x=await setup(t);
  const response=await x.call({jsonrpc:'2.0',id:'catalog-1',method:'tools/list'});
  assert.equal(response.status,200);
  assert.deepEqual(response.body.result.tools.map(tool=>tool.name).sort(),[
    'list_directory','list_processes','read_file','run_command','write_file',
  ]);
  const write=response.body.result.tools.find(tool=>tool.name==='write_file');
  assert.deepEqual(write.inputSchema.properties.mode.enum,['create']);
  const command=response.body.result.tools.find(tool=>tool.name==='run_command');
  assert.deepEqual(command.inputSchema.properties.profile.enum,['count_lines']);
  assert.equal(command.inputSchema.properties.command,undefined);
});

test('same MCP identifier creates distinct durable signed decisions for each tool call',async t=>{
  const x=await setup(t);
  const payload={jsonrpc:'2.0',id:'stable-call-7',method:'tools/call',params:{
    name:'read_file',arguments:{deviceId:DEVICE,path:'/approved/readme.txt'},
  }};
  const first=await x.call(payload),second=await x.call(payload);
  assert.equal(first.status,200);
  assert.equal(second.status,200);
  assert.equal(x.calls.length,2);
  assert.notEqual(x.calls[0].requestId,x.calls[1].requestId);
  for(const frame of x.calls){
    assert.equal(frame.deviceId,DEVICE);
    const claims=verifyToolGrantCapability(frame.authorization,x.policyKeys.publicKey,{deviceId:DEVICE,
      requestId:frame.requestId,fingerprint:FINGERPRINT,tool:'read_file',arguments:frame.arguments,
      allowedRoot:'/approved'});
    assert.equal(claims.ownerDigest,x.ownerDigest);
    assert.equal(claims.approvalEventId,APPROVAL_EVENT);
    assert.equal(claims.approvalTrustRevisionBefore,6);
    assert.equal(claims.approvalTrustRevisionAfter,7);
    assert.equal(claims.scope.root,'/approved');
    assert.equal(claims.policyRevision,1);
  }
});

test('I4 absent durable tool grant and invalid owner-device policy fail before dispatch',async t=>{
  const x=await setup(t,{grant:false});
  const denied=await x.call({jsonrpc:'2.0',id:9,method:'tools/call',params:{
    name:'read_file',arguments:{deviceId:DEVICE,path:'/approved/readme.txt'},
  }});
  assert.equal(denied.status,403);
  assert.equal(x.calls.length,0);
  assert.throws(()=>createRemoteDeviceMcpHandler({
    accessVerifier:{verifyPrincipal:async()=>({issuer:ISSUER,subject:'owner'})},
    deviceRegistry:{listDevices:()=>[{deviceId:DEVICE}],isLiveSession:()=>true},router:{callDevice:async()=>({})},
    authorizeDevice:async()=>true,
  }),/durable tool grant store/);
});

test('trust revision changing during authorization prevents operation dispatch',async t=>{
  let revision=4;
  const x=await setup(t,{getTrustRevision:()=>revision++});
  const response=await x.call({jsonrpc:'2.0',id:'race-revision',method:'tools/call',params:{
    name:'read_file',arguments:{deviceId:DEVICE,path:'/approved/readme.txt'},
  }});
  assert.equal(response.status,503);
  assert.equal(x.calls.length,0);
});
