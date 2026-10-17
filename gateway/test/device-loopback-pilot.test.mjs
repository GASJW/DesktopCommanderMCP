import test from 'node:test';
import assert from 'node:assert/strict';
import { createDeviceRegistry } from '../devices/registry.mjs';
import { createPairingCoordinator } from '../devices/pairing.mjs';
import { createDeviceRouter } from '../devices/router.mjs';
import { startLoopbackAgentPilot } from '../devices/loopback-pilot.mjs';
import { createEphemeralPairingIdentity } from '../../packages/vpsc-agent/src/pairing.mjs';
import { createLoopbackAgentClient } from '../../packages/vpsc-agent/src/loopback-client.mjs';
import { signedAgentRequest } from '../../packages/vpsc-agent/src/frame.mjs';
import { request as httpRequest } from 'node:http';

const pause=()=>new Promise(resolve=>setTimeout(resolve,10));
async function setup(options={}){
  const registry=createDeviceRegistry();
  const pairing=createPairingCoordinator({registry});
  const router=createDeviceRouter({registry,timeoutMs:500});
  const pilot=await startLoopbackAgentPilot({registry,router,enableLoopbackPilot:true});
  const identity=createEphemeralPairingIdentity();
  const request=pairing.startPairing({name:'Gui-PC',platform:'win32',
    publicKeyPem:identity.publicKeyPem});
  assert.equal(pairing.provePossession(request.requestId,identity.prove(request)),true);
  const {deviceId}=pairing.approvePairing(request.requestId,identity.fingerprint);
  const client=createLoopbackAgentClient({url:pilot.url,identity,deviceId});
  const close=()=>{router.close();return pilot.close();};
  if(options.connect!==false) {await client.connect();await client.heartbeat();}
  return {registry,pairing,router,pilot,identity,deviceId,client,close};
}
async function rawPost(url,path,body,headers={}){
  const r=await fetch(url+path,{method:'POST',headers:{'content-type':'application/json',...headers},body});
  return {status:r.status,body:await r.json()};
}

test('pilot hard fails unless explicitly loopback and ephemeral',async()=>{
  const registry=createDeviceRegistry();
  const router=createDeviceRouter({registry});
  await assert.rejects(startLoopbackAgentPilot({registry,router}),/loopback-only/);
  await assert.rejects(startLoopbackAgentPilot({
    registry,router,enableLoopbackPilot:true,host:'0.0.0.0'
  }),/loopback-only/);
  await assert.rejects(startLoopbackAgentPilot({
    registry,router,enableLoopbackPilot:true,port:8080
  }),/loopback-only/);
  router.close();
});
test('synthetic signed agent connects outbound over real HTTP loopback and returns mocked result',async()=>{
  const s=await setup();
  try{
    const pending=s.router.callDevice({deviceId:s.deviceId,name:'read_file',arguments:{path:'/mock.txt'}});
    await pause();
    const frame=await s.client.poll();
    assert.equal(frame.deviceId,s.deviceId);
    assert.equal(frame.params.name,'read_file');
    assert.equal(frame.params.arguments.path,'/mock.txt');
    assert.deepEqual(await s.client.result(frame.requestId,{content:'synthetic result'}),{accepted:true});
    assert.deepEqual(await pending,{content:'synthetic result'});
    assert.equal(await s.client.poll(),null);
    assert.equal(s.registry.listDevices()[0].online,true);
  }finally{await s.close();}
});
test('unknown device cannot request a challenge or connect',async()=>{
  const s=await setup();
  try{
    const id='a1088b4b-34d7-4a43-8d1a-63aaed729c0c';
    assert.equal((await rawPost(s.pilot.url,'/agent/challenge',JSON.stringify({deviceId:id}))).status,403);
    assert.equal((await rawPost(s.pilot.url,'/agent/connect',JSON.stringify({deviceId:id,signature:'x'}))).status,403);
  }finally{await s.close();}
});
test('unsigned heartbeat, poll and result denied even with a device id',async()=>{
  const s=await setup();
  try{
    for(const path of ['/agent/heartbeat','/agent/poll','/agent/result']){
      assert.equal((await rawPost(s.pilot.url,path,'{}',{'x-vpsc-device-id':s.deviceId})).status,401);
    }
  }finally{await s.close();}
});
test('replay of same signed request sequence is rejected',async()=>{
  const s=await setup();
  try{
    const connection=await s.client.connect();
    const body='{}',pathname='/agent/heartbeat',sequence=1;
    const frame=signedAgentRequest({pathname,deviceId:s.deviceId,sessionId:connection.sessionId,sequence,bodyText:body});
    const headers={
      'x-vpsc-device-id':s.deviceId,'x-vpsc-session-id':connection.sessionId,
      'x-vpsc-sequence':String(sequence),'x-vpsc-signature':s.identity.signFrame(frame),
    };
    assert.equal((await rawPost(s.pilot.url,pathname,body,headers)).status,200);
    assert.equal((await rawPost(s.pilot.url,pathname,body,headers)).status,401);
  }finally{await s.close();}
});
test('tampering body after signing is rejected before routing',async()=>{
  const s=await setup();
  try{
    const connection=await s.client.connect();
    const body='{}';
    const frame=signedAgentRequest({pathname:'/agent/heartbeat',deviceId:s.deviceId,
      sessionId:connection.sessionId,sequence:1,bodyText:body});
    const headers={'x-vpsc-device-id':s.deviceId,'x-vpsc-session-id':connection.sessionId,
      'x-vpsc-sequence':'1','x-vpsc-signature':s.identity.signFrame(frame)};
    assert.equal((await rawPost(s.pilot.url,'/agent/heartbeat','{"modified":true}',headers)).status,401);
    assert.equal((await rawPost(s.pilot.url,'/agent/heartbeat',body,headers)).status,200);
  }finally{await s.close();}
});
test('signature is bound to path and session and cannot be moved to poll',async()=>{
  const s=await setup();
  try{
    const connection=await s.client.connect();
    const body='{}';
    const frame=signedAgentRequest({pathname:'/agent/heartbeat',deviceId:s.deviceId,
      sessionId:connection.sessionId,sequence:1,bodyText:body});
    const headers={'x-vpsc-device-id':s.deviceId,'x-vpsc-session-id':connection.sessionId,
      'x-vpsc-sequence':'1','x-vpsc-signature':s.identity.signFrame(frame)};
    assert.equal((await rawPost(s.pilot.url,'/agent/poll',body,headers)).status,401);
    assert.equal((await rawPost(s.pilot.url,'/agent/heartbeat',body,headers)).status,200);
  }finally{await s.close();}
});
test('untrusted key cannot sign into a trusted device session',async()=>{
  const s=await setup();
  try{
    const conn=await s.client.connect();
    const impostor=createEphemeralPairingIdentity();
    const body='{}',seq=1;
    const signed=signedAgentRequest({pathname:'/agent/heartbeat',deviceId:s.deviceId,
      sessionId:conn.sessionId,sequence:seq,bodyText:body});
    const headers={'x-vpsc-device-id':s.deviceId,'x-vpsc-session-id':conn.sessionId,
      'x-vpsc-sequence':'1','x-vpsc-signature':impostor.signFrame(signed)};
    assert.equal((await rawPost(s.pilot.url,'/agent/heartbeat',body,headers)).status,401);
    assert.equal((await rawPost(s.pilot.url,'/agent/heartbeat',body,
      {...headers,'x-vpsc-signature':s.identity.signFrame(signed)})).status,200);
  }finally{await s.close();}
});
test('unknown/invalid browser origin is blocked',async()=>{
  const s=await setup();
  try{
    const x=await rawPost(s.pilot.url,'/agent/challenge',JSON.stringify({deviceId:s.deviceId}),
      {origin:'https://evil.example'});
    assert.equal(x.status,403);
    const res=await fetch(s.pilot.url+'/mcp',{method:'POST',headers:{'content-type':'application/json'},body:'{}'});
    assert.equal(res.status,404);
  }finally{await s.close();}
});
test('connection requires heartbeat before poll and cannot receive queued calls until attached',async()=>{
  const s=await setup({connect:false});
  try{
    await s.client.connect();
    await assert.rejects(s.router.callDevice({deviceId:s.deviceId,name:'ping'}),e=>e.code==='OFFLINE');
    await assert.rejects(s.client.poll(),/409/);
    await s.client.heartbeat();
    assert.equal(await s.client.poll(),null);
  }finally{await s.close();}
});
test('reconnecting with fresh challenge invalidates old queued session and pending call',async()=>{
  const s=await setup();
  try{
    const old=assert.rejects(s.router.callDevice({deviceId:s.deviceId,name:'ping'}),
      e=>e.code==='AMBIGUOUS_DISCONNECT');
    await pause();
    const next=await s.client.connect();
    await old;
    await s.client.heartbeat();
    assert.equal(next.deviceId,s.deviceId);
    assert.equal(await s.client.poll(),null);
  }finally{await s.close();}
});
test('revocation immediately blocks signed request from previously connected agent',async()=>{
  const s=await setup();
  try{
    s.registry.revokeDevice(s.deviceId);
    await assert.rejects(s.client.poll(),/401/);
    await assert.rejects(s.router.callDevice({deviceId:s.deviceId,name:'read_file'}),e=>e.code==='OFFLINE');
  }finally{await s.close();}
});
test('oversized malformed and wrong media requests do not pass pilot',async()=>{
  const s=await setup();
  try{
    assert.equal((await rawPost(s.pilot.url,'/agent/challenge','not-json')).status,400);
    assert.equal((await rawPost(s.pilot.url,'/agent/challenge','"string"')).status,400);
    assert.equal((await rawPost(s.pilot.url,'/agent/challenge',JSON.stringify({deviceId:s.deviceId}),
      {'content-type':'text/plain'})).status,415);
    assert.equal((await rawPost(s.pilot.url,'/agent/challenge',JSON.stringify({deviceId:s.deviceId,pad:'x'.repeat(270_000)}))).status,413);
  }finally{await s.close();}
});
test('cross-device session and signed payload cannot access another device',async()=>{
  const s=await setup();
  try{
    const second=createEphemeralPairingIdentity();
    const r=s.pairing.startPairing({name:'gui',platform:'linux',publicKeyPem:second.publicKeyPem});
    s.pairing.provePossession(r.requestId,second.prove(r));
    const {deviceId:otherId}=s.pairing.approvePairing(r.requestId,second.fingerprint);
    const other=createLoopbackAgentClient({url:s.pilot.url,identity:second,deviceId:otherId});
    await other.connect();
    await other.heartbeat();
    const calls=[];
    const one=s.router.callDevice({deviceId:s.deviceId,name:'ping',arguments:{host:'one'}});
    const two=s.router.callDevice({deviceId:otherId,name:'ping',arguments:{host:'two'}});
    await pause();
    const frame1=await s.client.poll();
    const frame2=await other.poll();
    assert.notEqual(frame1.requestId,frame2.requestId);
    assert.equal(frame1.params.arguments.host,'one');
    assert.equal(frame2.params.arguments.host,'two');
    await s.client.result(frame1.requestId,{host:'one'});
    await other.result(frame2.requestId,{host:'two'});
    assert.deepEqual(await one,{host:'one'});
    assert.deepEqual(await two,{host:'two'});
    assert.equal(calls.length,0);
  }finally{await s.close();}
});
test('client is loopback-only and denies external hosts regardless of transport',()=>{
  const identity=createEphemeralPairingIdentity();
  for(const url of ['https://example.com','http://localhost:12345','http://0.0.0.0:12345',
    'http://127.0.0.1:12345/path','http://user:pass@127.0.0.1:1001']) {
    assert.throws(()=>createLoopbackAgentClient({url,identity,deviceId:'any'}),/Loopback pilot/);
  }
});

test('split multibyte UTF-8 is decoded without changing the signed body',async()=>{
  const s=await setup();
  try{
    const conn=await s.client.connect();
    const pathname='/agent/heartbeat';
    const bodyText='{"name":"ação"}';
    const bytes=Buffer.from(bodyText,'utf8');
    const split=bytes.indexOf(0xc3)+1; // Split inside the two-byte ã or ç.
    assert.ok(split>0 && split<bytes.length);
    const signature=s.identity.signFrame(signedAgentRequest({
      pathname,deviceId:s.deviceId,sessionId:conn.sessionId,sequence:1,bodyText,
    }));
    const response=await new Promise((resolve,reject)=>{
      const req=httpRequest(s.pilot.url+pathname,{method:'POST',headers:{
        'content-type':'application/json',
        'x-vpsc-device-id':s.deviceId,
        'x-vpsc-session-id':conn.sessionId,
        'x-vpsc-sequence':'1',
        'x-vpsc-signature':signature,
      }},res=>{
        const parts=[];
        res.on('data',x=>parts.push(x));
        res.on('end',()=>resolve({status:res.statusCode,body:Buffer.concat(parts).toString()}));
      });
      req.on('error',reject);
      req.write(bytes.subarray(0,split));
      req.end(bytes.subarray(split));
    });
    assert.equal(response.status,200);
    assert.deepEqual(JSON.parse(response.body),{status:'alive',deviceId:s.deviceId});
  }finally{await s.close();}
});
test('malformed UTF-8 is denied before signature validation',async()=>{
  const s=await setup();
  try{
    const payload=Buffer.from([0x7b,0x22,0x78,0x22,0x3a,0x22,0xc3,0x28,0x22,0x7d]);
    const response=await new Promise((resolve,reject)=>{
      const req=httpRequest(s.pilot.url+'/agent/heartbeat',{method:'POST',
        headers:{'content-type':'application/json'}},res=>{
        const parts=[];
        res.on('data',x=>parts.push(x));
        res.on('end',()=>resolve({status:res.statusCode,body:Buffer.concat(parts).toString()}));
      });
      req.on('error',reject);
      req.end(payload);
    });
    assert.equal(response.status,400);
    assert.match(response.body,/Invalid UTF-8/);
  }finally{await s.close();}
});
