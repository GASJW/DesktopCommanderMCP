import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { createDeviceRegistry, deviceChallengeMessage } from '../devices/registry.mjs';
import { createDeviceRouter } from '../devices/router.mjs';

function setup(options = {}) {
  let now = 1_800_000_000_000;
  const registry = createDeviceRegistry({ now:() => now, heartbeatTtlMs:5000 });
  const {publicKey,privateKey} = generateKeyPairSync('ed25519');
  const deviceId = registry.trustDevice({name:'Gui-PC',platform:'win32',
    publicKeyPem:publicKey.export({format:'pem',type:'spki'})}).deviceId;
  const signChallenge = () => {
    const {nonce}=registry.beginHandshake(deviceId);
    const signature=sign(null,deviceChallengeMessage(deviceId,nonce),privateKey).toString('base64url');
    const session=registry.completeHandshake(deviceId,signature);
    assert.equal(registry.heartbeat(deviceId,session.sessionId,1),true);
    return session.sessionId;
  };
  const sessionId=signChallenge();
  const router=createDeviceRouter({registry,timeoutMs:250,...options});
  const advance = milliseconds => { now+=milliseconds; };
  const sleep = ms => new Promise(resolve => setTimeout(resolve,ms));
  return {deviceId,sessionId,registry,router,advance,signChallenge,sleep};
}
const errorCode = code => error => error?.code===code;

test('authenticated and live device dispatches to the exact device with an opaque requestId',async()=>{
  const s=setup();
  let frame;
  s.router.attachTransport({deviceId:s.deviceId,sessionId:s.sessionId,send:f=>{ frame=f; }});
  const pending=s.router.callDevice({deviceId:s.deviceId,name:'read_file',arguments:{path:'/safe.txt'}});
  await s.sleep(2);
  assert.equal(frame.deviceId,s.deviceId);
  assert.equal(frame.sessionId,s.sessionId);
  assert.equal(frame.method,'tools/call');
  assert.deepEqual(frame.params,{name:'read_file',arguments:{path:'/safe.txt'}});
  assert.ok(frame.requestId);
  assert.equal(s.router.acceptResponse({deviceId:s.deviceId,sessionId:s.sessionId,
    requestId:frame.requestId,result:{content:'test'}}),true);
  assert.deepEqual(await pending,{content:'test'});
  assert.equal(s.router.acceptResponse({deviceId:s.deviceId,sessionId:s.sessionId,
    requestId:frame.requestId,result:{content:'duplicate'}}),false);
  s.router.close();
});
test('stable request ids are preserved and duplicates cannot be in flight twice',async()=>{
  const s=setup();let sent=0;
  s.router.attachTransport({deviceId:s.deviceId,sessionId:s.sessionId,send:()=>{sent++;}});
  const requestId='d3911c43-4fc9-4cb8-a3d0-1bef1f04748a';
  const pending=s.router.callDevice({deviceId:s.deviceId,name:'write_file',requestId,
    arguments:{path:'/safe/new.txt',mode:'create'}});
  await assert.rejects(s.router.callDevice({deviceId:s.deviceId,name:'write_file',requestId,
    arguments:{path:'/safe/new.txt',mode:'create'}}),errorCode('DUPLICATE_REQUEST'));
  await s.sleep(2);
  assert.equal(sent,1);
  assert.equal(s.router.acceptResponse({deviceId:s.deviceId,sessionId:s.sessionId,requestId,
    result:{created:true}}),true);
  assert.deepEqual(await pending,{created:true});
  await assert.rejects(s.router.callDevice({deviceId:s.deviceId,name:'write_file',
    requestId:'not-a-uuid',arguments:{path:'/safe/new.txt'}}),errorCode('BAD_REQUEST_ID'));
  s.router.close();
});
test('unknown, offline or empty deviceId cannot route to local implicit default',async()=>{
  const s=setup();
  await assert.rejects(s.router.callDevice({name:'read_file'}),errorCode('BAD_DEVICE'));
  await assert.rejects(s.router.callDevice({deviceId:s.deviceId,name:'read_file'}),errorCode('OFFLINE'));
  await assert.rejects(s.router.callDevice({deviceId:s.deviceId,name:'!bad'}),errorCode('BAD_TOOL'));
  await assert.rejects(s.router.callDevice({deviceId:s.deviceId,name:'read_file',arguments:[]}),errorCode('BAD_PAYLOAD'));
  s.router.close();
});
test('unauthorized transport and duplicate same-session attach are blocked',()=>{
  const s=setup();
  assert.throws(()=>s.router.attachTransport({deviceId:s.deviceId,sessionId:'not-a-session',send:()=>{}}),errorCode('UNAUTHORIZED_DEVICE'));
  assert.throws(()=>s.router.attachTransport({deviceId:s.deviceId,sessionId:s.sessionId}),errorCode('UNAUTHORIZED_DEVICE'));
  s.router.attachTransport({deviceId:s.deviceId,sessionId:s.sessionId,send:()=>{}});
  assert.throws(()=>s.router.attachTransport({deviceId:s.deviceId,sessionId:s.sessionId,send:()=>{}}),errorCode('SESSION_IN_USE'));
  s.router.close();
});
test('transport rejects responses from wrong session or requestId',async()=>{
  const s=setup();
  let frame;
  s.router.attachTransport({deviceId:s.deviceId,sessionId:s.sessionId,send:f=>{frame=f;}});
  const pending=s.router.callDevice({deviceId:s.deviceId,name:'ping'});
  await s.sleep(2);
  assert.equal(s.router.acceptResponse({deviceId:s.deviceId,sessionId:'another',
    requestId:frame.requestId,result:{ok:true}}),false);
  assert.equal(s.router.acceptResponse({deviceId:s.deviceId,sessionId:s.sessionId,
    requestId:'not-a-request',result:{ok:true}}),false);
  assert.equal(s.router.acceptResponse({deviceId:s.deviceId,sessionId:s.sessionId,
    requestId:frame.requestId,result:{ok:true}}),true);
  assert.deepEqual(await pending,{ok:true});
  s.router.close();
});
test('transport detach aborts pending request without replay',async()=>{
  const s=setup();
  let sent=0;
  s.router.attachTransport({deviceId:s.deviceId,sessionId:s.sessionId,send:()=>{sent++;}});
  const pending=s.router.callDevice({deviceId:s.deviceId,name:'ping'});
  await s.sleep(2);
  assert.equal(sent,1);
  assert.equal(s.router.detachTransport({deviceId:s.deviceId,sessionId:'bogus'}),false);
  assert.equal(s.router.detachTransport({deviceId:s.deviceId,sessionId:s.sessionId}),true);
  await assert.rejects(pending,errorCode('AMBIGUOUS_DISCONNECT'));
  assert.equal(sent,1);
  s.router.close();
});
test('timeout is ambiguous: never redispatch tool calls',async()=>{
  const s=setup({timeoutMs:105});
  let sent=0;
  s.router.attachTransport({deviceId:s.deviceId,sessionId:s.sessionId,send:()=>{sent++;}});
  await assert.rejects(s.router.callDevice({deviceId:s.deviceId,name:'write_file',arguments:{path:'/tmp/x'}}),errorCode('AMBIGUOUS_TIMEOUT'));
  assert.equal(sent,1);
  s.router.close();
});
test('caller cancellation before dispatch prevents delivery to the device',async()=>{
  const s=setup();let sent=0;
  s.router.attachTransport({deviceId:s.deviceId,sessionId:s.sessionId,send:()=>{sent++;}});
  const controller=new AbortController();
  const pending=s.router.callDevice({deviceId:s.deviceId,name:'write_file',signal:controller.signal});
  controller.abort();
  await assert.rejects(pending,errorCode('CANCELLED'));
  await s.sleep(2);
  assert.equal(sent,0);
  s.router.close();
});
test('pre-dispatch permit is acquired before transport handoff and released immediately after send',async()=>{
  const s=setup();let sent=0,released=0,releasePermit;
  s.router.attachTransport({deviceId:s.deviceId,sessionId:s.sessionId,send:frame=>{
    sent++;assert.equal(frame.authorization?.capability,'signed');
  }});
  const pending=s.router.callDevice({deviceId:s.deviceId,name:'read_file',requestId:
    'a2e4d90e-17f6-481c-846d-60494812f76c',arguments:{path:'/safe.txt'},
    beforeDispatch:async()=>{
      await new Promise(resolve=>{releasePermit=resolve;});
      return {authorization:{capability:'signed'},release:()=>{released++;}};
    }});
  await s.sleep(2);
  assert.equal(sent,0,'transport cannot receive a frame before durable authorization completes');
  releasePermit();
  await s.sleep(2);
  assert.equal(sent,1);
  assert.equal(released,1,'policy gate is released after the synchronous transport handoff');
  const frameRequest='a2e4d90e-17f6-481c-846d-60494812f76c';
  assert.equal(s.router.acceptResponse({deviceId:s.deviceId,sessionId:s.sessionId,
    requestId:frameRequest,result:{ok:true}}),true);
  assert.deepEqual(await pending,{ok:true});
  s.router.close();
});
test('pre-dispatch denial never calls transport and does not retain an authorization permit',async()=>{
  const s=setup();let sent=0,released=0;
  s.router.attachTransport({deviceId:s.deviceId,sessionId:s.sessionId,send:()=>{sent++;}});
  await assert.rejects(s.router.callDevice({deviceId:s.deviceId,name:'read_file',
    beforeDispatch:async()=>{throw Object.assign(Error('grant revoked'),{code:'GRANT_REVOKED'});}}),
  errorCode('GRANT_REVOKED'));
  assert.equal(sent,0);
  assert.equal(released,0);
  s.router.close();
});
test('cancellation removes a queued task but stays ambiguous after agent receipt',async()=>{
  const s=setup();const queue=[];
  s.router.attachTransport({deviceId:s.deviceId,sessionId:s.sessionId,
    send:frame=>queue.push(frame),cancel:requestId=>{
      const index=queue.findIndex(frame=>frame.requestId===requestId);
      if(index<0)return false;
      queue.splice(index,1);return true;
    }});
  const beforePoll=new AbortController();
  const queued=s.router.callDevice({deviceId:s.deviceId,name:'write_file',signal:beforePoll.signal});
  await s.sleep(2);assert.equal(queue.length,1);beforePoll.abort();
  await assert.rejects(queued,errorCode('CANCELLED'));
  assert.equal(queue.length,0);
  const afterPoll=new AbortController();
  const dispatched=s.router.callDevice({deviceId:s.deviceId,name:'write_file',signal:afterPoll.signal});
  await s.sleep(2);const received=queue.shift();assert.ok(received);
  afterPoll.abort();
  await assert.rejects(dispatched,errorCode('AMBIGUOUS_CANCELLED'));
  assert.equal(s.router.acceptResponse({deviceId:s.deviceId,sessionId:s.sessionId,
    requestId:received.requestId,result:{ok:true}}),false);
  s.router.close();
});
test('send transport failure reports ambiguous outcome and does not retry',async()=>{
  const s=setup();
  let sent=0;
  s.router.attachTransport({deviceId:s.deviceId,sessionId:s.sessionId,
    send:async()=>{sent++;throw Error('simulated transport failure');}});
  await assert.rejects(s.router.callDevice({deviceId:s.deviceId,name:'start_process'}),errorCode('AMBIGUOUS_DISPATCH'));
  assert.equal(sent,1);
  s.router.close();
});
test('concurrency is bounded and released when response arrives',async()=>{
  const s=setup({maxPendingPerDevice:1});
  const frames=[];
  s.router.attachTransport({deviceId:s.deviceId,sessionId:s.sessionId,send:f=>{frames.push(f);}});
  const pending=s.router.callDevice({deviceId:s.deviceId,name:'ping'});
  await s.sleep(2);
  await assert.rejects(s.router.callDevice({deviceId:s.deviceId,name:'ping'}),errorCode('BUSY'));
  assert.equal(s.router.acceptResponse({deviceId:s.deviceId,sessionId:s.sessionId,
    requestId:frames[0].requestId,result:{ok:true}}),true);
  await pending;
  const next=s.router.callDevice({deviceId:s.deviceId,name:'ping'});
  await s.sleep(2);
  assert.equal(frames.length,2);
  s.router.acceptResponse({deviceId:s.deviceId,sessionId:s.sessionId,
    requestId:frames[1].requestId,result:{ok:true}});
  await next;
  s.router.close();
});
test('revoked or expired device cannot accept late results',async()=>{
  const s=setup();
  let frame;
  s.router.attachTransport({deviceId:s.deviceId,sessionId:s.sessionId,send:f=>{frame=f;}});
  const pending=s.router.callDevice({deviceId:s.deviceId,name:'ping'});
  await s.sleep(2);
  s.registry.revokeDevice(s.deviceId);
  assert.equal(s.router.acceptResponse({deviceId:s.deviceId,sessionId:s.sessionId,
    requestId:frame.requestId,result:{ok:true}}),false);
  await assert.rejects(pending,errorCode('AMBIGUOUS_TIMEOUT'));
  await assert.rejects(s.router.callDevice({deviceId:s.deviceId,name:'ping'}),errorCode('OFFLINE'));
  s.router.close();
});
test('re-authentication fences old channel and outstanding requests',async()=>{
  const s=setup();
  const frames=[];
  s.router.attachTransport({deviceId:s.deviceId,sessionId:s.sessionId,send:f=>{frames.push(f);}});
  const pending=s.router.callDevice({deviceId:s.deviceId,name:'ping'});
  await s.sleep(2);
  const newSession=s.signChallenge();
  s.router.attachTransport({deviceId:s.deviceId,sessionId:newSession,send:f=>{frames.push(f);}});
  await assert.rejects(pending,errorCode('AMBIGUOUS_DISCONNECT'));
  assert.equal(s.router.acceptResponse({deviceId:s.deviceId,sessionId:s.sessionId,
    requestId:frames[0].requestId,result:{ok:true}}),false);
  s.router.close();
});
test('oversized payload rejected and oversized response terminates without retry',async()=>{
  const s=setup({maxRequestBytes:1024,maxResponseBytes:1024});
  let frame;
  s.router.attachTransport({deviceId:s.deviceId,sessionId:s.sessionId,send:f=>{frame=f;}});
  await assert.rejects(s.router.callDevice({deviceId:s.deviceId,name:'ping',
    arguments:{data:'x'.repeat(5000)}}),errorCode('BAD_PAYLOAD'));
  const pending=s.router.callDevice({deviceId:s.deviceId,name:'read_file'});
  await s.sleep(2);
  assert.equal(s.router.acceptResponse({deviceId:s.deviceId,sessionId:s.sessionId,
    requestId:frame.requestId,result:{data:'x'.repeat(6000)}}),false);
  await assert.rejects(pending,errorCode('BAD_RESPONSE'));
  s.router.close();
});
test('invalid options rejected; close fences future calls and sessions',async()=>{
  const s=setup();
  assert.throws(()=>createDeviceRouter({registry:s.registry,maxPendingPerDevice:0}),/Invalid/);
  const pendingFrames=[];
  s.router.attachTransport({deviceId:s.deviceId,sessionId:s.sessionId,send:f=>pendingFrames.push(f)});
  const pending=s.router.callDevice({deviceId:s.deviceId,name:'ping'});
  await s.sleep(2);
  s.router.close();
  await assert.rejects(pending,errorCode('CLOSED'));
  await assert.rejects(s.router.callDevice({deviceId:s.deviceId,name:'ping'}),errorCode('CLOSED'));
  assert.throws(()=>s.router.attachTransport({deviceId:s.deviceId,sessionId:s.sessionId,send:()=>{}}),errorCode('CLOSED'));
});
