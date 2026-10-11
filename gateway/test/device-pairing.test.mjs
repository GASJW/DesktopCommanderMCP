import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { createDeviceRegistry } from '../devices/registry.mjs';
import { createPairingCoordinator, pairingProofMessage } from '../devices/pairing.mjs';

const createKey = () => {
  const {publicKey,privateKey} = generateKeyPairSync('ed25519');
  return {
    publicKeyPem: publicKey.export({type:'spki',format:'pem'}),
    sign: m => sign(null,m,privateKey).toString('base64url'),
  };
};
function fixture(options = {}) {
  let t = 1_800_000_000_000;
  const registry = createDeviceRegistry({now:()=>t});
  const pairing = createPairingCoordinator({registry,now:()=>t,...options});
  const key = createKey();
  const start = (extra = {}) => pairing.startPairing({
    name:'Gui-PC',platform:'win32',publicKeyPem:key.publicKeyPem,...extra,
  });
  const prove = (request,keyToUse=key) =>
    pairing.provePossession(request.requestId,
      keyToUse.sign(pairingProofMessage(request.requestId,request.nonce,request.fingerprint)));
  const advance = milliseconds => {t+=milliseconds;};
  return {registry,pairing,key,start,prove,advance};
}

test('unproved device is pending and cannot auto-enroll',()=>{
  const {registry,pairing,start}=fixture();
  const req=start();
  assert.match(req.requestId,/^[0-9a-f-]{36}$/);
  assert.match(req.fingerprint,/^[a-f0-9]{64}$/);
  assert.match(req.displayCode,/^[A-F0-9]{10}$/);
  assert.equal(pairing.listPending().length,1);
  assert.equal(pairing.listPending()[0].proofVerified,false);
  assert.equal(registry.listDevices().length,0);
  assert.throws(()=>pairing.approvePairing(req.requestId,req.fingerprint),/requires verified proof/);
});
test('verified proof STILL requires explicit owner approval and expected fingerprint',()=>{
  const {registry,pairing,start,prove}=fixture();
  const req=start();
  assert.equal(prove(req),true);
  assert.equal(registry.listDevices().length,0);
  assert.equal(pairing.listPending()[0].proofVerified,true);
  assert.equal(pairing.listPending()[0].fingerprint,req.fingerprint);
  assert.throws(()=>pairing.approvePairing(req.requestId,'0'.repeat(64)),/matching/);
  assert.equal(registry.listDevices().length,0);
  const trust=pairing.approvePairing(req.requestId,req.fingerprint);
  assert.match(trust.deviceId,/^[0-9a-f-]{36}$/);
  assert.equal(trust.platform,'win32');
  assert.equal(registry.listDevices()[0].online,false);
  assert.equal(pairing.listPending().length,0);
  assert.throws(()=>pairing.approvePairing(req.requestId,req.fingerprint),/requires/);
});
test('invalid proof consumes request and cannot retry, even with correct signature',()=>{
  const {pairing,start,key,prove}=fixture();
  const req=start();
  const evil=createKey();
  assert.equal(prove(req,evil),false);
  assert.equal(prove(req,key),false);
  assert.equal(pairing.listPending().length,0);
});
test('malformed signature consumes request, including unexpected payload',()=>{
  const {pairing,start}=fixture();
  const req=start();
  assert.equal(pairing.provePossession(req.requestId,'bad'),false);
  assert.equal(pairing.provePossession(req.requestId,'bad'),false);
  assert.equal(pairing.listPending().length,0);
});
test('signature cannot be replayed against another pairing request',()=>{
  const {pairing,start,key}=fixture();
  const req=start();
  const sig=key.sign(pairingProofMessage(req.requestId,req.nonce,req.fingerprint));
  assert.equal(pairing.rejectPairing(req.requestId),true);
  const next=start();
  assert.notEqual(next.requestId,req.requestId);
  assert.equal(pairing.provePossession(next.requestId,sig),false);
  assert.equal(pairing.listPending().length,0);
});
test('wrong key and wrong fingerprint prevent proof; key is identity-bound',()=>{
  const {pairing,start,key}=fixture();
  const req=start();
  const invalid=key.sign(pairingProofMessage(req.requestId,req.nonce,'0'.repeat(64)));
  assert.equal(pairing.provePossession(req.requestId,invalid),false);
  assert.equal(pairing.listPending().length,0);
});
test('stale pending proof is discarded at exact TTL boundary',()=>{
  const {pairing,start,advance,prove}=fixture({ttlMs:10_000});
  const req=start();
  advance(9_999);
  assert.equal(pairing.listPending().length,1);
  advance(1);
  assert.equal(prove(req),false);
  assert.equal(pairing.listPending().length,0);
});
test('proof verified before TTL cannot be approved after TTL',()=>{
  const {registry,pairing,start,advance,prove}=fixture({ttlMs:10_000});
  const req=start();
  assert.equal(prove(req),true);
  advance(10_000);
  assert.throws(()=>pairing.approvePairing(req.requestId,req.fingerprint),/requires/);
  assert.equal(registry.listDevices().length,0);
});
test('rejection prevents later proof and approval',()=>{
  const {pairing,start,prove}=fixture();
  const req=start();
  assert.equal(pairing.rejectPairing(req.requestId),true);
  assert.equal(pairing.rejectPairing(req.requestId),false);
  assert.equal(prove(req),false);
  assert.throws(()=>pairing.approvePairing(req.requestId,req.fingerprint),/requires/);
});
test('duplicate pending key cannot start competing pairings',()=>{
  const {pairing,start}=fixture();
  start();
  assert.throws(()=>start(),/already has pending/);
});
test('capacity limits untrusted pending requests',()=>{
  const {pairing,start}=fixture({maxPending:1});
  const req=start();
  assert.throws(()=>start({publicKeyPem:createKey().publicKeyPem}),/capacity/);
  assert.equal(pairing.rejectPairing(req.requestId),true);
  assert.equal(start({publicKeyPem:createKey().publicKeyPem}).requestId.length,36);
});
test('expired pairing frees capacity for new request',()=>{
  const {pairing,start,advance}=fixture({maxPending:1,ttlMs:10_000});
  start();
  advance(10_001);
  assert.equal(start({publicKeyPem:createKey().publicKeyPem}).requestId.length,36);
});
test('unknown request cannot be proved or approved, never creates an identity',()=>{
  const {pairing,registry}=fixture();
  assert.equal(pairing.provePossession('not-found','foo'),false);
  assert.throws(()=>pairing.approvePairing('not-found','0'.repeat(64)),/requires/);
  assert.equal(registry.listDevices().length,0);
});
test('metadata validation rejects invalid host identity or algorithms',()=>{
  const {start}=fixture();
  for (const name of ['', '  ','bad\nhost', 'x'.repeat(65)]) {
    assert.throws(()=>start({name}),/metadata/);
  }
  assert.throws(()=>start({platform:'android'}),/metadata/);
  assert.throws(()=>start({publicKeyPem:'-----invalid-----'}),/key material/);
  const {publicKey}=generateKeyPairSync('rsa',{modulusLength:2048});
  assert.throws(()=>start({publicKeyPem:publicKey.export({type:'spki',format:'pem'})}),/Ed25519/);
});
test('bad coordinator bounds and malformed proof components fail closed',()=>{
  const {registry}=fixture();
  assert.throws(()=>createPairingCoordinator({registry,maxPending:129}),/options/);
  assert.throws(()=>createPairingCoordinator({registry,ttlMs:500}),/options/);
  assert.throws(()=>pairingProofMessage('bogus','foo','bar'),/Invalid pairing/);
});
test('nothing reports agents online without separately authenticated session heartbeats',()=>{
  const {registry,pairing,start,prove}=fixture();
  const req=start();
  prove(req);
  pairing.approvePairing(req.requestId,req.fingerprint);
  assert.equal(registry.listDevices()[0].online,false);
});
test('owner queue provides only public review fields and not private material',()=>{
  const {pairing,start}=fixture();
  start();
  const list=pairing.listPending();
  assert.deepEqual(Object.keys(list[0]).sort(),
    ['createdAt','displayCode','fingerprint','name','platform','proofVerified','requestId']);
  assert.equal(Object.isFrozen(list[0]),true);
});
test('registry rejection does not create success or silently re-register',()=>{
  const registry=createDeviceRegistry({maxDevices:1});
  const first=createKey();
  registry.trustDevice({name:'existing',platform:'linux',publicKeyPem:first.publicKeyPem});
  const key=createKey();
  const pairing=createPairingCoordinator({registry});
  const req=pairing.startPairing({name:'Gui-PC',platform:'win32',publicKeyPem:key.publicKeyPem});
  assert.equal(pairing.provePossession(req.requestId,key.sign(
    pairingProofMessage(req.requestId,req.nonce,req.fingerprint))),true);
  assert.throws(()=>pairing.approvePairing(req.requestId,req.fingerprint),/capacity/);
  assert.equal(registry.listDevices().length,1);
});
