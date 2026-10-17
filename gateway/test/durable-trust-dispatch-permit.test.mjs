import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync,sign } from 'node:crypto';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtempSync,rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createDurableDeviceTrustStore } from '../devices/durable-trust.mjs';
import { deviceChallengeMessage } from '../devices/registry.mjs';
import { createDurableOwnerAudit } from '../dashboard/durable-owner-audit.mjs';
import { analyzeOwnerPairingRecovery,reconcileOwnerPairingRecovery }
  from '../dashboard/owner-pairing-reconciliation.mjs';

const keypair=()=>generateKeyPairSync('ed25519');
function temp(t){
  const root=mkdtempSync(path.join(os.tmpdir(),'g7-trust-dispatch-permit-'));
  t.after(()=>rmSync(root,{recursive:true,force:true}));
  return path.join(root,'trust');
}
function trust(store,publicKey){
  return store.trustDevice({name:'synthetic-permit-device',platform:'linux',
    publicKeyPem:publicKey.export({type:'spki',format:'pem'})});
}
function liveSession(store,deviceId,privateKey){
  const challenge=store.registry.beginHandshake(deviceId);
  const proof=sign(null,deviceChallengeMessage(deviceId,challenge.nonce),privateKey)
    .toString('base64url');
  const session=store.registry.completeHandshake(deviceId,proof);
  assert.equal(store.registry.heartbeat(deviceId,session.sessionId,1),true);
  return session.sessionId;
}

test('trust dispatch permit fences revocation through handoff; response guard fences the exact session',t=>{
  const directory=temp(t),store=createDurableDeviceTrustStore({directory});
  const {publicKey,privateKey}=keypair(),device=trust(store,publicKey);
  const sessionId=liveSession(store,device.deviceId,privateKey);
  const context={deviceId:device.deviceId,sessionId,expectedRevision:1};
  const permit=store.acquireDispatchPermit(context);
  assert.equal(permit.trustRevision,1);
  assert.throws(()=>store.revokeDevice(device.deviceId),error=>error.code==='TRUST_BUSY');
  assert.equal(store.revision(),1,'a retryable revoke conflict leaves the trust facade usable');
  assert.equal(store.withCurrentSession(context,()=>true),true);
  assert.equal(permit.release(),true);
  assert.equal(store.revokeDevice(device.deviceId),true);
  assert.throws(()=>store.withCurrentSession(context,()=>true),error=>
    error.code==='TRUST_SESSION_STALE');
  assert.equal(store.revision(),2);
});

test('a real process dispatch permit blocks another process trust revocation until handoff',async t=>{
  const directory=temp(t),store=createDurableDeviceTrustStore({directory});
  const {publicKey,privateKey}=keypair(),device=trust(store,publicKey);
  const privatePem=privateKey.export({type:'pkcs8',format:'pem'});
  const source=`
    import {createPrivateKey,sign} from 'node:crypto';
    import {createDurableDeviceTrustStore} from './gateway/devices/durable-trust.mjs';
    import {deviceChallengeMessage} from './gateway/devices/registry.mjs';
    const [directory,deviceId,privatePem]=process.argv.slice(1);
    const store=createDurableDeviceTrustStore({directory});
    const key=createPrivateKey(privatePem);
    const challenge=store.registry.beginHandshake(deviceId);
    const proof=sign(null,deviceChallengeMessage(deviceId,challenge.nonce),key).toString('base64url');
    const session=store.registry.completeHandshake(deviceId,proof);
    store.registry.heartbeat(deviceId,session.sessionId,1);
    const permit=store.acquireDispatchPermit({deviceId,sessionId:session.sessionId,expectedRevision:1});
    process.stdout.write('READY\\n');
    process.stdin.once('data',()=>{permit.release();store.close();process.exit(0);});
  `;
  const child=spawn(process.execPath,['--input-type=module','-e',source,directory,
    device.deviceId,privatePem],{cwd:process.cwd(),stdio:['pipe','pipe','pipe']});
  t.after(()=>{if(child.exitCode===null&&child.signalCode===null)child.kill('SIGKILL');});
  let output='';
  child.stdout.setEncoding('utf8');
  const ready=new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>reject(Error('permit child did not become ready: '+output)),5000);
    child.stdout.on('data',chunk=>{
      output+=chunk;
      if(output.includes('READY\n')){clearTimeout(timer);resolve();}
    });
    child.once('error',error=>{clearTimeout(timer);reject(error);});
  });
  await ready;
  assert.throws(()=>store.revokeDevice(device.deviceId),error=>error.code==='TRUST_BUSY');
  assert.equal(store.revision(),1);
  child.stdin.end('release');
  const [code,signal]=await once(child,'exit');
  assert.equal(code,0);assert.equal(signal,null);
  assert.equal(store.revokeDevice(device.deviceId),true);
  assert.equal(store.revision(),2);
});

test('SIGKILL leaves a stale dispatch permit until explicit reconciliation',async t=>{
  const root=mkdtempSync(path.join(os.tmpdir(),'g7-trust-permit-recovery-'));
  t.after(()=>rmSync(root,{recursive:true,force:true}));
  const trustDirectory=path.join(root,'trust'),auditDirectory=path.join(root,'audit');
  const audit=createDurableOwnerAudit({directory:auditDirectory});audit.close();
  const store=createDurableDeviceTrustStore({directory:trustDirectory});
  const {publicKey,privateKey}=keypair(),device=trust(store,publicKey);
  const privatePem=privateKey.export({type:'pkcs8',format:'pem'});
  const source=`
    import {createPrivateKey,sign} from 'node:crypto';
    import {createDurableDeviceTrustStore} from './gateway/devices/durable-trust.mjs';
    import {deviceChallengeMessage} from './gateway/devices/registry.mjs';
    const [directory,deviceId,privatePem]=process.argv.slice(1);
    const store=createDurableDeviceTrustStore({directory});
    const challenge=store.registry.beginHandshake(deviceId);
    const proof=sign(null,deviceChallengeMessage(deviceId,challenge.nonce),createPrivateKey(privatePem))
      .toString('base64url');
    const session=store.registry.completeHandshake(deviceId,proof);
    store.registry.heartbeat(deviceId,session.sessionId,1);
    store.acquireDispatchPermit({deviceId,sessionId:session.sessionId,expectedRevision:1});
    process.stdout.write('READY\\n');
    setInterval(()=>{},1000);
  `;
  const child=spawn(process.execPath,['--input-type=module','-e',source,trustDirectory,
    device.deviceId,privatePem],{cwd:process.cwd(),stdio:['ignore','pipe','pipe']});
  t.after(()=>{if(child.exitCode===null&&child.signalCode===null)child.kill('SIGKILL');});
  let output='';child.stdout.setEncoding('utf8');
  await new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>reject(Error('stale-permit child did not become ready: '+output)),5000);
    child.stdout.on('data',chunk=>{output+=chunk;if(output.includes('READY\n')){clearTimeout(timer);resolve();}});
    child.once('error',error=>{clearTimeout(timer);reject(error);});
  });
  const exited=once(child,'exit');child.kill('SIGKILL');
  const [code,signal]=await exited;assert.equal(code,null);assert.equal(signal,'SIGKILL');
  assert.throws(()=>store.revision(),error=>error.code==='TRUST_RECOVERY_REQUIRED');
  const diagnosis=analyzeOwnerPairingRecovery({auditDirectory,trustDirectory});
  assert.equal(diagnosis.state,'NO_INTENT_LOCK_HELD');
  assert.throws(()=>reconcileOwnerPairingRecovery({auditDirectory,trustDirectory}),/operator confirmation/i);
  assert.equal(reconcileOwnerPairingRecovery({auditDirectory,trustDirectory,
    operatorConfirmedNoActiveWriters:true}).state,'RECONCILED_NO_INTENT');
  store.close();
  const recovered=createDurableDeviceTrustStore({directory:trustDirectory});
  assert.equal(recovered.revision(),1);
  assert.equal(recovered.registry.listDevices().length,1);
  recovered.close();
});
