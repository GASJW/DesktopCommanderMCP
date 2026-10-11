import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { createDeviceRegistry, deviceChallengeMessage } from '../devices/registry.mjs';

const makeKey = () => {
  const {publicKey, privateKey} = generateKeyPairSync('ed25519');
  return {
    publicKeyPem: publicKey.export({format:'pem', type:'spki'}),
    sign: message => sign(null, message, privateKey).toString('base64url'),
  };
};
function withDevice(options = {}) {
  let clock = options.clock ?? 1_800_000_000_000;
  const registry = createDeviceRegistry({...options, now: () => clock});
  const key = makeKey();
  const device = registry.trustDevice({name:'Gui-PC',platform:'win32',publicKeyPem:key.publicKeyPem});
  const advance = ms => { clock += ms; };
  const connect = () => {
    const {nonce} = registry.beginHandshake(device.deviceId);
    return registry.completeHandshake(device.deviceId,key.sign(deviceChallengeMessage(device.deviceId,nonce)));
  };
  return {registry,key,device,advance,connect};
}

test('newly trusted device remains offline, with no implied transport', () => {
  const {registry,device} = withDevice();
  const listed=registry.listDevices();
  assert.equal(listed.length,1);
  assert.deepEqual(listed[0],{
    deviceId:device.deviceId,name:'Gui-PC',platform:'win32',online:false,lastSeenAt:null,
  });
  assert.equal(Object.hasOwn(listed[0],'fingerprint'),false);
  assert.equal(Object.hasOwn(listed[0],'sessionId'),false);
});
test('valid signed handshake and sequenced heartbeat establishes observed online', () => {
  const {registry,device,connect,advance}=withDevice();
  const {sessionId}=connect();
  assert.equal(registry.listDevices()[0].online,false);
  assert.equal(registry.heartbeat(device.deviceId,sessionId,1),true);
  advance(10_000);
  assert.equal(registry.heartbeat(device.deviceId,sessionId,2),true);
  assert.equal(registry.listDevices()[0].online,true);
  assert.match(registry.listDevices()[0].lastSeenAt,/Z$/);
});
test('wrong signing key rejected and challenge is one-use', () => {
  const {registry,device}=withDevice();
  const {nonce}=registry.beginHandshake(device.deviceId);
  const imposter=makeKey();
  assert.throws(()=>registry.completeHandshake(device.deviceId,imposter.sign(deviceChallengeMessage(device.deviceId,nonce))),/Invalid signature/);
  assert.throws(()=>registry.completeHandshake(device.deviceId,imposter.sign(deviceChallengeMessage(device.deviceId,nonce))),/No pending challenge/);
  assert.equal(registry.listDevices()[0].online,false);
});
test('challenge bound to exact device and cannot authenticate another device', () => {
  const {registry,device,key}=withDevice();
  const second=makeKey();
  const other=registry.trustDevice({name:'gui',platform:'linux',publicKeyPem:second.publicKeyPem});
  const {nonce}=registry.beginHandshake(device.deviceId);
  registry.beginHandshake(other.deviceId);
  assert.throws(()=>registry.completeHandshake(other.deviceId,key.sign(deviceChallengeMessage(device.deviceId,nonce))),/Invalid signature/);
});
test('challenge expires fail-closed and cannot be replayed', () => {
  const {registry,device,key,advance}=withDevice({challengeTtlMs:1000});
  const {nonce}=registry.beginHandshake(device.deviceId);
  advance(1001);
  const signature=key.sign(deviceChallengeMessage(device.deviceId,nonce));
  assert.throws(()=>registry.completeHandshake(device.deviceId,signature),/expired/);
  assert.throws(()=>registry.completeHandshake(device.deviceId,signature),/No pending/);
});
test('unknown devices cannot enter handshake', () => {
  const {registry}=withDevice();
  assert.throws(()=>registry.beginHandshake('unknown'),/not trusted/);
});
test('handshake requires strict signature serialization', () => {
  const {registry,device}=withDevice();
  registry.beginHandshake(device.deviceId);
  assert.throws(()=>registry.completeHandshake(device.deviceId,'x'),/Invalid signature/);
});
test('replayed or out-of-order heartbeat sequences rejected', () => {
  const {registry,device,connect}=withDevice();
  const {sessionId}=connect();
  assert.equal(registry.heartbeat(device.deviceId,sessionId,1),true);
  assert.equal(registry.heartbeat(device.deviceId,sessionId,1),false);
  assert.equal(registry.heartbeat(device.deviceId,sessionId,0),false);
  assert.equal(registry.heartbeat(device.deviceId,sessionId,-9),false);
  assert.equal(registry.heartbeat(device.deviceId,sessionId,2),true);
});
test('wrong session rejected and does not mark device online', () => {
  const {registry,device,connect}=withDevice();
  connect();
  assert.equal(registry.heartbeat(device.deviceId,'wrong-session',1),false);
  assert.equal(registry.listDevices()[0].online,false);
});
test('heartbeat lease expiry invalidates old session and requires new proof', () => {
  const {registry,device,advance,connect}=withDevice({heartbeatTtlMs:1000});
  const {sessionId}=connect();
  assert.equal(registry.heartbeat(device.deviceId,sessionId,1),true);
  advance(1001);
  assert.equal(registry.listDevices()[0].online,false);
  assert.equal(registry.heartbeat(device.deviceId,sessionId,2),false);
  const newer=connect();
  assert.notEqual(newer.sessionId,sessionId);
  assert.equal(registry.heartbeat(device.deviceId,newer.sessionId,1),true);
});
test('disconnect requires active session, invalidates sequence and presence', () => {
  const {registry,device,connect}=withDevice();
  const {sessionId}=connect();
  assert.equal(registry.heartbeat(device.deviceId,sessionId,1),true);
  assert.equal(registry.disconnect(device.deviceId,'invalid'),false);
  assert.equal(registry.disconnect(device.deviceId,sessionId),true);
  assert.equal(registry.heartbeat(device.deviceId,sessionId,2),false);
  assert.equal(registry.listDevices()[0].online,false);
});
test('revocation removes identity and blocks further handshakes', () => {
  const {registry,device,connect}=withDevice();
  const {sessionId}=connect();
  assert.equal(registry.revokeDevice(device.deviceId),true);
  assert.equal(registry.revokeDevice(device.deviceId),false);
  assert.equal(registry.listDevices().length,0);
  assert.equal(registry.heartbeat(device.deviceId,sessionId,1),false);
  assert.throws(()=>registry.beginHandshake(device.deviceId),/not trusted/);
});
test('duplicate public keys rejected', () => {
  const {registry,key}=withDevice();
  assert.throws(()=>registry.trustDevice({name:'clone',platform:'linux',publicKeyPem:key.publicKeyPem}),/Duplicate/);
});
test('capacity enforced before adding another device', () => {
  const {registry}=withDevice({maxDevices:1});
  assert.throws(()=>registry.trustDevice({name:'other',platform:'linux',publicKeyPem:makeKey().publicKeyPem}),/capacity/);
});
test('invalid metadata, non-ed25519 keys, and name controls rejected', () => {
  const {registry}=withDevice();
  for (const name of ['', ' '.repeat(3),'bad\nname','x'.repeat(65)]) {
    assert.throws(()=>registry.trustDevice({name,platform:'linux',publicKeyPem:makeKey().publicKeyPem}),/metadata/);
  }
  assert.throws(()=>registry.trustDevice({name:'Mac',platform:'ios',publicKeyPem:makeKey().publicKeyPem}),/metadata/);
  assert.throws(()=>registry.trustDevice({name:'mac',platform:'darwin',publicKeyPem:'not a key'}),/public key/);
  const {publicKey}=generateKeyPairSync('rsa',{modulusLength:2048});
  assert.throws(()=>registry.trustDevice({name:'mac',platform:'darwin',publicKeyPem:publicKey.export({type:'spki',format:'pem'})}),/Ed25519/);
});
test('strict options reject invalid clock, lease, and capacity', () => {
  assert.throws(()=>createDeviceRegistry({heartbeatTtlMs:0}),/options/);
  assert.throws(()=>createDeviceRegistry({maxDevices:257}),/options/);
  assert.throws(()=>createDeviceRegistry({now:()=>NaN}).listDevices(),/clock/);
});
test('challenge API never accepts malformed device identifiers or nonce', () => {
  assert.throws(()=>deviceChallengeMessage('gui','x'),/Invalid/);
});
test('registry instance has no filesystem or HTTP side effects', () => {
  const {registry}=withDevice();
  assert.deepEqual(Object.keys(registry).sort(),['beginHandshake','completeHandshake','disconnect','heartbeat','listDevices','revokeDevice','trustDevice'].sort());
});
