import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { createDeviceRegistry } from '../../../gateway/devices/registry.mjs';
import { createPairingCoordinator } from '../../../gateway/devices/pairing.mjs';
import { createEphemeralPairingIdentity } from '../src/pairing.mjs';

const bin = path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../bin/vpsc-agent.mjs');
function scenario() {
  const identity=createEphemeralPairingIdentity();
  const registry=createDeviceRegistry();
  const pairing=createPairingCoordinator({registry});
  const request=pairing.startPairing({
    name:'Gui-PC',platform:'win32',publicKeyPem:identity.publicKeyPem,
  });
  return {identity,registry,pairing,request};
}

test('agent ephemeral key proves possession to actual coordinator; owner must still approve',()=>{
  const {identity,registry,pairing,request}=scenario();
  assert.equal(identity.fingerprint,request.fingerprint);
  const signature=identity.prove(request);
  assert.equal(pairing.provePossession(request.requestId,signature),true);
  assert.equal(registry.listDevices().length,0);
  const reviewed=pairing.listPending();
  assert.equal(reviewed[0].proofVerified,true);
  pairing.approvePairing(request.requestId,identity.fingerprint);
  assert.equal(registry.listDevices().length,1);
  assert.equal(registry.listDevices()[0].online,false);
});
test('agent refuses mismatched public key fingerprint',()=>{
  const {identity,request}=scenario();
  assert.throws(()=>identity.prove({...request,fingerprint:'0'.repeat(64)}),/mismatch/);
});
test('agent refuses invalid requestId and nonce',()=>{
  const {identity,request}=scenario();
  assert.throws(()=>identity.prove({...request,requestId:'other'}),/mismatch/);
  assert.throws(()=>identity.prove({...request,nonce:'bad'}),/mismatch/);
});
test('ephemeral proof cannot be used twice for same pairing request',()=>{
  const {identity,request}=scenario();
  identity.prove(request);
  assert.throws(()=>identity.prove(request),/already used/);
});
test('agent identity object never exposes private key or environment secrets',()=>{
  const {identity}=scenario();
  assert.deepEqual(Object.keys(identity).sort(),['fingerprint','prove','proveDeviceChallenge','publicKeyPem','signFrame']);
  assert.equal(Object.isFrozen(identity),true);
  assert.equal(JSON.stringify(identity).includes('PRIVATE KEY'),false);
});
test('CLI doctor is local-only, claims no remote execution',()=>{
  const output=execFileSync(process.execPath,[bin,'doctor'],{encoding:'utf8'});
  const data=JSON.parse(output);
  assert.equal(data.prototype,true);
  assert.equal(data.remoteExecutionEnabled,false);
  assert.equal(data.supported,true);
});
test('CLI help and version report prototype only',()=>{
  const help=execFileSync(process.execPath,[bin,'--help'],{encoding:'utf8'});
  assert.match(help,/NOT production-ready/);
  assert.match(help,/NOT implemented/);
  assert.equal(execFileSync(process.execPath,[bin,'--version'],{encoding:'utf8'}).trim(),'0.0.0-dev');
});
test('CLI explicitly fails closed if asked to connect or run privileged actions',()=>{
  for (const args of [['connect'],['--gateway','https://example.test'],['root'],[],['pair']]) {
    const outcome=spawnSync(process.execPath,[bin,...args],{encoding:'utf8'});
    assert.equal(outcome.status,2);
    assert.match(outcome.stderr,/not enabled/);
  }
});
