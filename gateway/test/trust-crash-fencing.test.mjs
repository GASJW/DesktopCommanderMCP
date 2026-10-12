import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmdirSync, linkSync, lstatSync, rmSync, symlinkSync } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { createDurableDeviceTrustStore } from '../devices/durable-trust.mjs';
import { deviceChallengeMessage } from '../devices/registry.mjs';

function fixture(t) {
  const root = mkdtempSync(path.join(os.tmpdir(), 'vpsc-trust-recovery-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return {root, directory:path.join(root,'records')};
}
function identity() {
  const {publicKey,privateKey}=generateKeyPairSync('ed25519');
  return {
    publicKeyPem:publicKey.export({format:'pem',type:'spki'}),
    proof:challenge=>sign(null,challenge,privateKey).toString('base64url'),
  };
}
function enroll(store, key=identity()) {
  const device=store.trustDevice({name:'Gui-PC',platform:'win32',publicKeyPem:key.publicKeyPem});
  return {device,key};
}
test('CRASH: stale writer lock prevents restart from accepting trusted sessions',t=>{
  const f=fixture(t);
  const active=createDurableDeviceTrustStore({directory:f.directory});
  enroll(active);
  const lock=path.join(f.directory,'.trusted-devices-writer.lock');
  mkdirSync(lock,{mode:0o700}); // emulates process death after taking exclusive lock
  assert.throws(()=>createDurableDeviceTrustStore({directory:f.directory}),
    /lock|reconciliation|unavailable/i);
  // A different running process must also stop routing on ambiguous state.
  assert.throws(()=>active.registry.listDevices(),/lock|unavailable|changed/i);
  rmdirSync(lock); // only an explicit operator reconciliation may clear it
  const reviewed=createDurableDeviceTrustStore({directory:f.directory});
  assert.equal(reviewed.registry.listDevices().length,1);
});
test('REVOCATION: stale authenticated session is fenced after another process revokes it',t=>{
  const f=fixture(t);
  const first=createDurableDeviceTrustStore({directory:f.directory});
  const {device,key}=enroll(first);
  const {nonce}=first.registry.beginHandshake(device.deviceId);
  const proof=key.proof(deviceChallengeMessage(device.deviceId,nonce));
  const {sessionId}=first.registry.completeHandshake(device.deviceId,proof);
  assert.equal(first.registry.heartbeat(device.deviceId,sessionId,1),true);
  assert.equal(first.registry.isLiveSession(device.deviceId,sessionId),true);
  const second=createDurableDeviceTrustStore({directory:f.directory});
  assert.equal(second.revokeDevice(device.deviceId),true);
  assert.equal(second.registry.listDevices().length,0);
  // Prior sessions and queued signed frames MUST NOT pass on the stale facade.
  assert.throws(()=>first.registry.isLiveSession(device.deviceId,sessionId),
    /changed|unavailable|stale/i);
  assert.throws(()=>first.registry.heartbeat(device.deviceId,sessionId,2),
    /changed|unavailable|stale/i);
  assert.throws(()=>first.registry.listDevices(),/changed|unavailable|stale/i);
});
test('WRITER: concurrent lock fences reads and handshakes before mutation is committed',t=>{
  const f=fixture(t);
  const initial=createDurableDeviceTrustStore({directory:f.directory});
  const {device}=enroll(initial);
  const lock=path.join(f.directory,'.trusted-devices-writer.lock');
  mkdirSync(lock,{mode:0o700});
  assert.throws(()=>initial.registry.beginHandshake(device.deviceId),
    /lock|unavailable|changed/i);
  assert.throws(()=>initial.trustDevice({
    name:'another',platform:'linux',publicKeyPem:identity().publicKeyPem,
  }),/lock|unavailable|changed/i);
  rmdirSync(lock);
  assert.throws(()=>initial.registry.listDevices(),/unavailable/i);
});
test('PATH: a symlinked ancestor cannot host authoritative trust data',t=>{
  const f=fixture(t);
  const actual=path.join(f.root,'actual');
  mkdirSync(actual,{mode:0o700});
  const alias=path.join(f.root,'shortcut');
  symlinkSync(actual,alias);
  const pathThroughSymlink=path.join(alias,'trust');
  assert.throws(()=>createDurableDeviceTrustStore({directory:pathThroughSymlink}),
    /Unsafe trust|symlink/i);
});
test('FILE: trust snapshot rejects extra hard links',t=>{
  const f=fixture(t);
  const store=createDurableDeviceTrustStore({directory:f.directory});
  enroll(store);
  const file=path.join(f.directory,'trusted-devices-v1.json');
  const externalLink=path.join(f.root,'linked.json');
  linkSync(file,externalLink);
  assert.equal(lstatSync(file).nlink,2);
  assert.throws(()=>createDurableDeviceTrustStore({directory:f.directory}),
    /Unsafe trust file/);
});

test('REAL SUBPROCESS: a dead writer leaves a persistent lock requiring operator recovery',t=>{
  const f=fixture(t);
  const first=createDurableDeviceTrustStore({directory:f.directory});
  enroll(first);
  const lock=path.join(f.directory,'.trusted-devices-writer.lock');
  const script='const {mkdirSync}=require("node:fs");'+
    'mkdirSync(process.argv[1],{mode:0o700});process.exit(0)';
  execFileSync(process.execPath,['-e',script,lock],{timeout:3000});
  assert.equal(lstatSync(lock).isDirectory(),true);
  assert.throws(()=>createDurableDeviceTrustStore({directory:f.directory}),
    /lock present|reconciliation/);
  assert.throws(()=>first.registry.listDevices(),/lock present|unavailable/);
});

test('DIRECTORY: replacing an initially empty trust directory fences the old facade',t=>{
  const f=fixture(t);
  const first=createDurableDeviceTrustStore({directory:f.directory});
  assert.equal(first.registry.listDevices().length,0);
  rmSync(f.directory,{recursive:true});
  mkdirSync(f.directory,{mode:0o700});
  assert.throws(()=>first.registry.listDevices(),/replaced|unavailable|directory/i);
  assert.throws(()=>first.registry.beginHandshake('missing'),/unavailable/);
});
