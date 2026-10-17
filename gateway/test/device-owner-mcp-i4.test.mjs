import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { createAccessVerifier } from '../access-auth.mjs';
import { createRemoteDeviceMcpHandler } from '../devices/remote-mcp-handler.mjs';

const ISSUER='https://i4-owner-test.cloudflareaccess.com';
const AUD='e'.repeat(64);
const DEVICE='b7e92caf-f591-44c4-8fb7-6c489ea573f4';
const APPROVAL_EVENT='b7e92caf-f591-44c4-8fb7-6c489ea573f5';
const FINGERPRINT='b'.repeat(64);

async function setup(t,{authorizeTool=()=>true,getTrustRevision=()=>7,
  authorizationPolicyRevision='i4-test-policy-v1'}={}){
  const {publicKey,privateKey}=generateKeyPairSync('rsa',{modulusLength:2048});
  const jwk={...publicKey.export({format:'jwk'}),kid:'i4-owner',alg:'RS256'};
  const accessVerifier=createAccessVerifier({issuer:ISSUER,audience:AUD,
    allowedEmails:'owner@example.com',keyProvider:async()=>({keys:[jwk]})});
  const now=Math.floor(Date.now()/1000);
  const h=Buffer.from(JSON.stringify({alg:'RS256',kid:'i4-owner'})).toString('base64url');
  const p=Buffer.from(JSON.stringify({iss:ISSUER,aud:AUD,email:'owner@example.com',sub:'owner-i4',
    iat:now-1,exp:now+300})).toString('base64url');
  const token=h+'.'+p+'.'+sign('RSA-SHA256',Buffer.from(h+'.'+p),privateKey).toString('base64url');
  const calls=[];
  const router={callDevice:async frame=>{calls.push(frame);return {content:[{type:'text',text:'ok'}]};}};
  const handler=createRemoteDeviceMcpHandler({accessVerifier,deviceRegistry:{listDevices:()=>[{deviceId:DEVICE}]},
    router,authorizeDevice:async()=>true,authorizeTool,getTrustRevision,
    getDeviceApprovalReceipt:()=>({eventId:APPROVAL_EVENT,deviceId:DEVICE,fingerprint:FINGERPRINT,
      trustRevisionBefore:6,trustRevisionAfter:7,trustRevision:7}),authorizationPolicyRevision});
  const server=createServer(handler);
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  t.after(()=>new Promise(resolve=>server.close(resolve)));
  const endpoint=`http://127.0.0.1:${server.address().port}/mcp`;
  const call=async payload=>{
    const response=await fetch(endpoint,{method:'POST',headers:{'content-type':'application/json',
      'cf-access-jwt-assertion':token},body:JSON.stringify(payload)});
    return {status:response.status,body:response.status===202?null:await response.json()};
  };
  return {call,calls};
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

test('I4 JSON-RPC identifiers are correlation only and each authorized operation receives an audit context',async t=>{
  const seen=[];
  const x=await setup(t,{authorizeTool:async(_owner,deviceId,toolName)=>{
    seen.push([deviceId,toolName]);return toolName==='read_file';
  }});
  const payload={jsonrpc:'2.0',id:'stable-call-7',method:'tools/call',params:{
    name:'read_file',arguments:{deviceId:DEVICE,path:'/approved/readme.txt'},
  }};
  const first=await x.call(payload),second=await x.call(payload);
  assert.equal(first.status,200);
  assert.equal(second.status,200);
  assert.deepEqual(seen,[[DEVICE,'read_file'],[DEVICE,'read_file']]);
  assert.equal(x.calls.length,2);
  assert.notEqual(x.calls[0].requestId,x.calls[1].requestId);
  assert.match(x.calls[0].requestId,/^[0-9a-f-]{36}$/i);
  assert.equal(x.calls[0].deviceId,DEVICE);
  const ownerDigest=createHash('sha256').update('VPSC-I4-OWNER-v1\n')
    .update(JSON.stringify([ISSUER,'owner-i4'])).digest('hex');
  assert.deepEqual(x.calls[0].authorization,{ownerDigest,
    approvalEventId:APPROVAL_EVENT,approvalTrustRevisionBefore:6,approvalTrustRevisionAfter:7,
    fingerprint:FINGERPRINT,trustRevision:7,policyRevision:'i4-test-policy-v1'});
  assert.deepEqual(x.calls[1].authorization,x.calls[0].authorization);
});

test('I4 denied per-tool grant and missing tool policy fail before dispatch',async t=>{
  const x=await setup(t,{authorizeTool:async()=>false});
  const denied=await x.call({jsonrpc:'2.0',id:9,method:'tools/call',params:{
    name:'list_directory',arguments:{deviceId:DEVICE,path:'/approved'},
  }});
  assert.equal(denied.status,403);
  assert.equal(x.calls.length,0);
  assert.throws(()=>createRemoteDeviceMcpHandler({
    accessVerifier:{verifyPrincipal:async()=>({issuer:ISSUER,subject:'owner'})},
    deviceRegistry:{listDevices:()=>[{deviceId:DEVICE}]},router:{callDevice:async()=>({})},
    authorizeDevice:async()=>true,
  }),/tool policy/);
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
