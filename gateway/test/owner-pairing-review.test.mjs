import test from 'node:test';
import assert from 'node:assert/strict';
import { createDeviceRegistry } from '../devices/registry.mjs';
import { createPairingCoordinator } from '../devices/pairing.mjs';
import { createEphemeralPairingIdentity } from '../../packages/vpsc-agent/src/pairing.mjs';
import { createOwnerPairingReview } from '../dashboard/owner-pairing-review.mjs';

function setup(){
  let t=1_800_000_000_000;
  const registry=createDeviceRegistry({now:()=>t});
  const coordinator=createPairingCoordinator({registry,now:()=>t});
  const gate=ctx=>ctx?.identity==='owner'&&ctx?.csrfOk===true&&ctx?.recentLogin===true;
  const review=createOwnerPairingReview({coordinator,ownerGate:gate});
  const identity=createEphemeralPairingIdentity();
  const pending=coordinator.startPairing({name:'Gui-PC',platform:'win32',
    publicKeyPem:identity.publicKeyPem});
  const owner={identity:'owner',csrfOk:true,recentLogin:true};
  const approve=()=>review.approve(owner,{requestId:pending.requestId,
    code:pending.displayCode,expectedFingerprint:pending.fingerprint});
  return {registry,coordinator,review,identity,pending,owner,approve,advance:ms=>{t+=ms;}};
}
test('owner review requires verified trusted owner gate',async()=>{
  const x=setup();
  for(const caller of [null,{}, {identity:'owner'}, {identity:'owner',csrfOk:true},
    {identity:'agent',csrfOk:true,recentLogin:true}]){
    await assert.rejects(x.review.listPending(caller),/denied/);
    await assert.rejects(x.review.approve(caller,{requestId:x.pending.requestId,
      code:x.pending.displayCode,expectedFingerprint:x.pending.fingerprint}),/denied/);
  }
});
test('pending list hides display code, nonce and private key while showing metadata',async()=>{
  const x=setup();
  const p=await x.review.listPending(x.owner);
  assert.equal(p.length,1);
  assert.equal(p[0].name,'Gui-PC');
  assert.equal(p[0].fingerprint,x.pending.fingerprint);
  assert.equal(p[0].proofVerified,false);
  assert.equal(Object.hasOwn(p[0],'displayCode'),false);
  const serialized=JSON.stringify(p);
  assert.equal(serialized.includes(x.pending.displayCode),false);
  assert.equal(serialized.includes(x.pending.nonce),false);
  assert.equal(serialized.includes('PRIVATE KEY'),false);
});
test('code alone does not approve without Ed25519 possession proof',async()=>{
  const x=setup();
  await assert.rejects(x.approve(),/denied/);
  assert.equal(x.registry.listDevices().length,0);
});
test('signed proof and matching owner-typed code/fingerprint approves offline device',async()=>{
  const x=setup();
  assert.equal(x.coordinator.provePossession(x.pending.requestId,x.identity.prove(x.pending)),true);
  const p=await x.review.listPending(x.owner);
  assert.equal(p[0].proofVerified,true);
  const code=x.pending.displayCode.slice(0,4)+'-'+x.pending.displayCode.slice(4);
  const result=await x.review.approve(x.owner,{requestId:x.pending.requestId,
    code:code.toLowerCase(),expectedFingerprint:x.pending.fingerprint});
  assert.equal(result.status,'approved_offline');
  assert.equal(result.fingerprint,x.pending.fingerprint);
  assert.equal(x.registry.listDevices().length,1);
  assert.equal(x.registry.listDevices()[0].online,false);
  assert.equal((await x.review.listPending(x.owner)).length,0);
});
test('wrong owner-typed code cannot authorize even with valid device signature',async()=>{
  const x=setup();
  x.coordinator.provePossession(x.pending.requestId,x.identity.prove(x.pending));
  const entered=x.pending.displayCode==='AAAAAAAAAA'?'BBBBBBBBBB':'AAAAAAAAAA';
  await assert.rejects(x.review.approve(x.owner,{requestId:x.pending.requestId,
    code:entered,expectedFingerprint:x.pending.fingerprint}),/denied/);
  assert.equal(x.registry.listDevices().length,0);
});
test('five bad codes consume pending pairing instead of unlimited guesses',async()=>{
  const x=setup();
  x.coordinator.provePossession(x.pending.requestId,x.identity.prove(x.pending));
  const entered=x.pending.displayCode==='AAAAAAAAAA'?'BBBBBBBBBB':'AAAAAAAAAA';
  for(let i=0;i<5;i++){
    await assert.rejects(x.review.approve(x.owner,{requestId:x.pending.requestId,
      code:entered,expectedFingerprint:x.pending.fingerprint}),/denied/);
  }
  assert.equal((await x.review.listPending(x.owner)).length,0);
  await assert.rejects(x.approve(),/denied/);
});
test('fingerprint mismatch is not silently tolerated',async()=>{
  const x=setup();
  x.coordinator.provePossession(x.pending.requestId,x.identity.prove(x.pending));
  await assert.rejects(x.review.approve(x.owner,{requestId:x.pending.requestId,
    code:x.pending.displayCode,expectedFingerprint:'f'.repeat(64)}),/denied/);
  assert.equal(x.registry.listDevices().length,0);
});
test('rejected request cannot later be used for approval',async()=>{
  const x=setup();
  x.coordinator.provePossession(x.pending.requestId,x.identity.prove(x.pending));
  assert.deepEqual(await x.review.reject(x.owner,{requestId:x.pending.requestId}),{rejected:true});
  await assert.rejects(x.approve(),/denied/);
  assert.equal(x.registry.listDevices().length,0);
});
test('expired request fails closed without retaining device trust',async()=>{
  const x=setup();
  x.coordinator.provePossession(x.pending.requestId,x.identity.prove(x.pending));
  x.advance(120_001);
  await assert.rejects(x.approve(),/denied/);
  assert.equal((await x.review.listPending(x.owner)).length,0);
});
test('bad request ID and malformed code fail closed',async()=>{
  const x=setup();
  x.coordinator.provePossession(x.pending.requestId,x.identity.prove(x.pending));
  for(const requestId of [null,'not-a-uuid']){
    await assert.rejects(x.review.approve(x.owner,{
      requestId,code:x.pending.displayCode,expectedFingerprint:x.pending.fingerprint}),/denied/);
  }
  await assert.rejects(x.review.approve(x.owner,{
    requestId:x.pending.requestId,code:'<script>x</script>',expectedFingerprint:x.pending.fingerprint
  }),/denied/);
});
test('default-deny: missing owner gate cannot instantiate review plane',()=>{
  const x=setup();
  assert.throws(()=>createOwnerPairingReview({coordinator:x.coordinator}),/Owner gate/);
});
