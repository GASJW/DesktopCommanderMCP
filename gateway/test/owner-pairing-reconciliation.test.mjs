import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import fs from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { appendFileSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { createHash, createPublicKey, generateKeyPairSync, randomUUID } from 'node:crypto';
import { createDurableDeviceTrustStore, inspectDurableDeviceTrust } from '../devices/durable-trust.mjs';
import { createDurableOwnerAudit } from '../dashboard/durable-owner-audit.mjs';
import { analyzeOwnerPairingRecovery, clearStaleOwnerPairingRecoveryLocks,
  reconcileOwnerPairingRecovery } from '../dashboard/owner-pairing-reconciliation.mjs';

const intent=(overrides={})=>({
  event:'g7_owner_pairing',version:2,at:'2026-10-17T12:00:00.000Z',
  eventId:'7844cd69-61f1-4a9c-9664-fce563976a14',operation:'approve',
  ownerId:'a'.repeat(24),requestId:'6093f82c-04f9-4b5a-a523-248e616fbd3f',
  fingerprint:'b'.repeat(64),trustRevisionBefore:0,phase:'intent',...overrides,
});
function fixture(t){
  const root=mkdtempSync(path.join(tmpdir(),'g7-pair-reconcile-'));
  t.after(()=>rmSync(root,{recursive:true,force:true}));
  return {root,auditDirectory:path.join(root,'audit'),trustDirectory:path.join(root,'trust')};
}
function crashChild(f,mode){
  const trustUrl=new URL('../devices/durable-trust.mjs',import.meta.url).href;
  const auditUrl=new URL('../dashboard/durable-owner-audit.mjs',import.meta.url).href;
  const source=`
    import {createHash,createPublicKey,generateKeyPairSync} from 'node:crypto';
    import {readlinkSync,writeSync} from 'node:fs';
    import fs from 'node:fs';
    import {syncBuiltinESMExports} from 'node:module';
    import {createDurableDeviceTrustStore} from ${JSON.stringify(trustUrl)};
    import {createDurableOwnerAudit} from ${JSON.stringify(auditUrl)};
    const [auditDirectory,trustDirectory,mode]=process.argv.slice(1);
    const store=createDurableDeviceTrustStore({directory:trustDirectory});
    const audit=createDurableOwnerAudit({directory:auditDirectory});
    const eventId='7844cd69-61f1-4a9c-9664-fce563976a14';
    const requestId='6093f82c-04f9-4b5a-a523-248e616fbd3f';
    const {publicKey}=generateKeyPairSync('ed25519');
    const publicKeyPem=publicKey.export({type:'spki',format:'pem'});
    const fingerprint=createHash('sha256').update(createPublicKey(publicKeyPem).export({type:'spki',format:'der'})).digest('hex');
    const binding={eventId,requestId,fingerprint};
    if(mode==='before-intent'){
      writeSync(1,JSON.stringify(binding)+'\\n');process.exit(74);
    }
    audit.auditWrite({event:'g7_owner_pairing',version:2,at:'2026-10-17T12:00:00.000Z',
      eventId,operation:mode==='after-reject-intent'?'reject':'approve',
      ownerId:'${'a'.repeat(24)}',requestId,fingerprint,
      trustRevisionBefore:0,phase:'intent'});
    if(mode==='after-reject-intent'){
      writeSync(1,JSON.stringify(binding)+'\\n');process.exit(75);
    }
    if(mode==='after-intent'){
      writeSync(1,JSON.stringify(binding)+'\\n');process.exit(71);
    }
    if(mode==='during-trust-fsync'){
      const original=fs.fsyncSync;
      fs.fsyncSync=(fd)=>{
        let target='';try{target=readlinkSync('/proc/self/fd/'+fd);}catch{}
        if(target.includes('.trust-'))process.kill(process.pid,'SIGKILL');
        return original(fd);
      };
      syncBuiltinESMExports();
      store.trustDevice({name:'Crash GUI',platform:'win32',publicKeyPem},
        {expectedRevision:0,decision:binding});
    }
    if(mode==='after-trust-commit'){
      const device=store.trustDevice({name:'Crash GUI',platform:'win32',publicKeyPem},
        {expectedRevision:0,decision:binding});
      writeSync(1,JSON.stringify({...binding,deviceId:device.deviceId})+'\\n');process.exit(72);
    }
    store.trustDevice({name:'Independent',platform:'linux',publicKeyPem});
    process.exit(73);
  `;
  return spawnSync(process.execPath,['--input-type=module','-e',source,
    f.auditDirectory,f.trustDirectory,mode],{encoding:'utf8',timeout:10000});
}
function approvedBinding(){
  const {publicKey}=generateKeyPairSync('ed25519');
  const publicKeyPem=publicKey.export({type:'spki',format:'pem'});
  const fingerprint=createHash('sha256').update(createPublicKey(publicKeyPem)
    .export({type:'spki',format:'der'})).digest('hex');
  return {publicKeyPem,fingerprint,eventId:randomUUID(),requestId:randomUUID()};
}
async function activeRecoveryChild(f){
  const helperUrl=new URL('../common/durable-process-lock.mjs',import.meta.url).href;
  const source=`
    import {createDurableProcessLock} from ${JSON.stringify(helperUrl)};
    for(const directory of process.argv.slice(1))
      createDurableProcessLock(directory,'.owner-pairing-reconciliation.lock','reconciliation');
    process.stdout.write('ready\\n');
    setInterval(()=>{},1000);
  `;
  const child=spawn(process.execPath,['--input-type=module','-e',source,
    f.auditDirectory,f.trustDirectory],{stdio:['ignore','pipe','pipe']});
  let output='',stderr='';
  await new Promise((resolve,reject)=>{
    const timeout=setTimeout(()=>{
      child.kill('SIGKILL');
      reject(Error('recovery lock child did not start: '+stderr));
    },5000);
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stderr.on('data',chunk=>{stderr+=chunk;});
    child.stdout.on('data',chunk=>{
      output+=chunk;
      if(output.includes('ready\n')){clearTimeout(timeout);resolve();}
    });
    child.once('error',error=>{clearTimeout(timeout);reject(error);});
    child.once('exit',(code,signal)=>{
      if(!output.includes('ready\n')){
        clearTimeout(timeout);
        reject(Error(`recovery lock child exited early: ${code}/${signal}`));
      }
    });
  });
  return child;
}

test('empty durable stores prove no pairing approval was recorded',t=>{
  const f=fixture(t);
  createDurableDeviceTrustStore({directory:f.trustDirectory});
  const audit=createDurableOwnerAudit({directory:f.auditDirectory});audit.close();
  assert.deepEqual(analyzeOwnerPairingRecovery(f),{state:'NO_INTENT'});
});

test('CRASH: process death before first intent leaves only a governed writer lock',t=>{
  const f=fixture(t);
  const child=crashChild(f,'before-intent');
  assert.equal(child.status,74,child.stderr);
  assert.equal(analyzeOwnerPairingRecovery(f).state,'NO_INTENT_LOCK_HELD');
  const result=reconcileOwnerPairingRecovery({...f,operatorConfirmedNoActiveWriters:true});
  assert.equal(result.state,'RECONCILED_NO_INTENT');
  const audit=createDurableOwnerAudit({directory:f.auditDirectory});audit.close();
  assert.equal(analyzeOwnerPairingRecovery(f).state,'NO_INTENT');
});

test('CRASH: kill during trust snapshot fsync never replays authorization',t=>{
  const f=fixture(t);
  const child=crashChild(f,'during-trust-fsync');
  assert.equal(child.signal,'SIGKILL',child.stderr);
  assert.equal(analyzeOwnerPairingRecovery(f).state,'INTENT_NOT_APPLIED');
  const result=reconcileOwnerPairingRecovery({...f,operatorConfirmedNoActiveWriters:true});
  assert.equal(result.state,'RECONCILED_NOT_APPLIED');
  assert.equal(readdirSync(f.trustDirectory).some(name=>name.startsWith('.trust-')),false);
  const store=createDurableDeviceTrustStore({directory:f.trustDirectory});
  assert.equal(store.revision(),0);
  assert.deepEqual(store.registry.listDevices(),[]);
});

test('CRASH: committed trust receipt reconciles missing WAL outcome without reapplying trust',t=>{
  const f=fixture(t);
  const child=crashChild(f,'after-trust-commit');
  assert.equal(child.status,72,child.stderr);
  const binding=JSON.parse(child.stdout);
  const diagnosis=analyzeOwnerPairingRecovery(f);
  assert.equal(diagnosis.state,'COMMITTED_OUTCOME_MISSING');
  assert.equal(diagnosis.eventId,binding.eventId);
  const result=reconcileOwnerPairingRecovery({...f,operatorConfirmedNoActiveWriters:true});
  assert.equal(result.state,'RECONCILED_ACCEPTED');
  const audit=createDurableOwnerAudit({directory:f.auditDirectory});
  assert.equal(audit.inspect().pending,0);
  audit.close();
  const store=createDurableDeviceTrustStore({directory:f.trustDirectory});
  assert.equal(store.revision(),1);
  assert.equal(store.registry.listDevices().length,1);
  const events=readFileSync(path.join(f.auditDirectory,'owner-decisions-v1.jsonl'),'utf8')
    .trimEnd().split('\n').map(JSON.parse).map(record=>record.event);
  assert.deepEqual(events.map(event=>event.phase),['intent','outcome']);
  assert.equal(events[1].deviceId,binding.deviceId);
  assert.equal(events[1].requestId,binding.requestId);
  assert.equal(events[1].fingerprint,binding.fingerprint);
  assert.equal(events[1].trustRevisionAfter,1);
});

test('CRASH: unchanged trust revision reconciles as not_applied and never replays intent',t=>{
  const f=fixture(t);
  const child=crashChild(f,'after-intent');
  assert.equal(child.status,71,child.stderr);
  assert.equal(analyzeOwnerPairingRecovery(f).state,'INTENT_NOT_APPLIED');
  const result=reconcileOwnerPairingRecovery({...f,operatorConfirmedNoActiveWriters:true});
  assert.equal(result.state,'RECONCILED_NOT_APPLIED');
  const store=createDurableDeviceTrustStore({directory:f.trustDirectory});
  assert.equal(store.revision(),0);
  assert.equal(store.registry.listDevices().length,0);
  const audit=createDurableOwnerAudit({directory:f.auditDirectory});
  assert.equal(audit.inspect().pending,0);
  audit.close();
});

test('CRASH: rejected pairing with no durable mutation stays outcome-unknown',t=>{
  const f=fixture(t);
  const child=crashChild(f,'after-reject-intent');
  assert.equal(child.status,75,child.stderr);
  assert.equal(analyzeOwnerPairingRecovery(f).state,'EPHEMERAL_RESULT_UNKNOWN');
  assert.throws(()=>reconcileOwnerPairingRecovery({...f,
    operatorConfirmedNoActiveWriters:true}),/EPHEMERAL_RESULT_UNKNOWN/);
  assert.equal(analyzeOwnerPairingRecovery(f).state,'EPHEMERAL_RESULT_UNKNOWN');
});

test('advanced revision without matching decision receipt remains blocked',t=>{
  const f=fixture(t);
  const child=crashChild(f,'diverged');
  assert.equal(child.status,73,child.stderr);
  assert.equal(analyzeOwnerPairingRecovery(f).state,'REVISION_DIVERGED');
  assert.throws(()=>reconcileOwnerPairingRecovery({...f,
    operatorConfirmedNoActiveWriters:true}),/diverg|contradict/i);
  assert.equal(analyzeOwnerPairingRecovery(f).state,'REVISION_DIVERGED');
});

test('recovery requires explicit operator quiescence confirmation',t=>{
  const f=fixture(t);
  const child=crashChild(f,'after-intent');
  assert.equal(child.status,71,child.stderr);
  assert.throws(()=>reconcileOwnerPairingRecovery(f),/operator confirmation/i);
  assert.equal(analyzeOwnerPairingRecovery(f).state,'INTENT_NOT_APPLIED');
});

test('LIVE WRITER: reconciliation cannot record not_applied before a live approval commits',t=>{
  const f=fixture(t);
  const binding=approvedBinding();
  const decision=intent({eventId:binding.eventId,requestId:binding.requestId,
    fingerprint:binding.fingerprint});
  const store=createDurableDeviceTrustStore({directory:f.trustDirectory});
  const audit=createDurableOwnerAudit({directory:f.auditDirectory});
  audit.auditWrite(decision);

  let recoveryError;
  try{
    reconcileOwnerPairingRecovery({...f,operatorConfirmedNoActiveWriters:true});
  }catch(error){recoveryError=error;}

  const device=store.trustDevice({name:'Live approval',platform:'linux',
    publicKeyPem:binding.publicKeyPem},{expectedRevision:0,decision:{
      eventId:binding.eventId,requestId:binding.requestId,fingerprint:binding.fingerprint}});
  let outcomeError;
  try{
    audit.auditWrite({...decision,phase:'outcome',outcome:'accepted',
      deviceId:device.deviceId,trustRevisionAfter:1});
  }catch(error){outcomeError=error;}
  try{audit.close();}catch{}
  store.close();

  assert.ok(recoveryError,'a live audit writer must prevent reconciliation');
  assert.equal(outcomeError,undefined,'the still-live decision must remain writable');
  assert.equal(analyzeOwnerPairingRecovery(f).state,'CONSISTENT');
});

test('uncertain WAL outcome fsync failure preserves recovery locks',t=>{
  const f=fixture(t);
  const child=crashChild(f,'after-intent');
  assert.equal(child.status,71,child.stderr);
  const original=fs.fsyncSync;
  let injected=false;
  fs.fsyncSync=(fd)=>{
    const target=fs.readlinkSync(`/proc/self/fd/${fd}`);
    const result=original(fd);
    if(!injected&&target===path.join(f.auditDirectory,'owner-decisions-v1.jsonl')){
      injected=true;
      throw Error('injected post-fsync uncertainty');
    }
    return result;
  };
  syncBuiltinESMExports();
  try{
    assert.throws(()=>reconcileOwnerPairingRecovery({...f,
      operatorConfirmedNoActiveWriters:true}),/injected post-fsync uncertainty/);
  }finally{
    fs.fsyncSync=original;
    syncBuiltinESMExports();
  }
  assert.equal(injected,true);
  assert.equal(analyzeOwnerPairingRecovery(f).state,'RECOVERY_LOCK_ACTIVE');
});

test('corrupt trust snapshot classifies as corrupt and is not repaired',t=>{
  const f=fixture(t);
  createDurableDeviceTrustStore({directory:f.trustDirectory});
  const audit=createDurableOwnerAudit({directory:f.auditDirectory});
  audit.auditWrite(intent());audit.close();
  writeFileSync(path.join(f.trustDirectory,'trusted-devices-v1.json'),'{truncated');
  assert.equal(analyzeOwnerPairingRecovery(f).state,'CORRUPT');
  assert.throws(()=>reconcileOwnerPairingRecovery({...f,
    operatorConfirmedNoActiveWriters:true}),/corrupt|invalid/i);
  assert.equal(readFileSync(path.join(f.trustDirectory,'trusted-devices-v1.json'),'utf8'),'{truncated');
});

test('legacy v1 decision history remains explicitly unbound after restart',t=>{
  const f=fixture(t);
  createDurableDeviceTrustStore({directory:f.trustDirectory});
  const audit=createDurableOwnerAudit({directory:f.auditDirectory});
  const eventId=randomUUID();
  const basis={event:'g7_owner_pairing',version:1,at:'2026-10-17T12:00:00.000Z',
    eventId,operation:'approve',ownerId:'a'.repeat(24),targetId:'c'.repeat(24)};
  audit.auditWrite({...basis,phase:'intent'});
  audit.auditWrite({...basis,phase:'outcome',outcome:'accepted'});
  audit.close();
  assert.equal(analyzeOwnerPairingRecovery(f).state,'LEGACY_UNBOUND');
  assert.equal(reconcileOwnerPairingRecovery({...f,operatorConfirmedNoActiveWriters:true}).state,
    'LEGACY_UNBOUND');
});

test('v2 approval receipt without a matching WAL intent is blocked',t=>{
  const f=fixture(t);
  const audit=createDurableOwnerAudit({directory:f.auditDirectory});audit.close();
  const binding=approvedBinding();
  const store=createDurableDeviceTrustStore({directory:f.trustDirectory});
  store.trustDevice({name:'Orphan',platform:'linux',publicKeyPem:binding.publicKeyPem},
    {expectedRevision:0,decision:{eventId:binding.eventId,requestId:binding.requestId,
      fingerprint:binding.fingerprint}});
  assert.equal(analyzeOwnerPairingRecovery(f).state,'TRUST_RECEIPT_WITHOUT_AUDIT');
});

test('denied WAL outcome contradicting a persisted approval receipt is blocked',t=>{
  const f=fixture(t);
  const binding=approvedBinding();
  const decision=intent({eventId:binding.eventId,requestId:binding.requestId,
    fingerprint:binding.fingerprint,trustRevisionBefore:0});
  const audit=createDurableOwnerAudit({directory:f.auditDirectory});
  audit.auditWrite(decision);
  audit.auditWrite({...decision,phase:'outcome',outcome:'denied',deviceId:null,
    trustRevisionAfter:0});
  audit.close();
  const store=createDurableDeviceTrustStore({directory:f.trustDirectory});
  store.trustDevice({name:'Contradiction',platform:'linux',publicKeyPem:binding.publicKeyPem},
    {expectedRevision:0,decision:{eventId:binding.eventId,requestId:binding.requestId,
      fingerprint:binding.fingerprint}});
  assert.equal(analyzeOwnerPairingRecovery(f).state,'OUTCOME_CONTRADICTS_TRUST');
});

test('completed approval remains verifiable after its device is later revoked',t=>{
  const f=fixture(t);
  const binding=approvedBinding();
  const decision=intent({eventId:binding.eventId,requestId:binding.requestId,
    fingerprint:binding.fingerprint,trustRevisionBefore:0});
  const audit=createDurableOwnerAudit({directory:f.auditDirectory});
  audit.auditWrite(decision);
  const store=createDurableDeviceTrustStore({directory:f.trustDirectory});
  const device=store.trustDevice({name:'Revoked later',platform:'linux',
    publicKeyPem:binding.publicKeyPem},{expectedRevision:0,decision:{
      eventId:binding.eventId,requestId:binding.requestId,fingerprint:binding.fingerprint}});
  audit.auditWrite({...decision,phase:'outcome',outcome:'accepted',deviceId:device.deviceId,
    trustRevisionAfter:1});
  assert.equal(store.revokeDevice(device.deviceId),true);
  audit.close();
  const trust=inspectDurableDeviceTrust({directory:f.trustDirectory});
  assert.deepEqual(trust.transitions.map(item=>item.operation),['approve','revoke']);
  assert.deepEqual(trust.devices,[]);
  assert.equal(analyzeOwnerPairingRecovery(f).state,'CONSISTENT');
});

test('truncated WAL is classified as corrupt and is never reconciled',t=>{
  const f=fixture(t);
  createDurableDeviceTrustStore({directory:f.trustDirectory});
  const audit=createDurableOwnerAudit({directory:f.auditDirectory});
  audit.auditWrite(intent());audit.close();
  appendFileSync(path.join(f.auditDirectory,'owner-decisions-v1.jsonl'),'truncated');
  assert.equal(analyzeOwnerPairingRecovery(f).state,'CORRUPT');
  assert.throws(()=>reconcileOwnerPairingRecovery({...f,
    operatorConfirmedNoActiveWriters:true}),/CORRUPT/);
});

test('trust snapshot cannot omit a device that its history says remains trusted',t=>{
  const f=fixture(t);
  const binding=approvedBinding();
  const decision=intent({eventId:binding.eventId,requestId:binding.requestId,
    fingerprint:binding.fingerprint,trustRevisionBefore:0});
  const audit=createDurableOwnerAudit({directory:f.auditDirectory});
  audit.auditWrite(decision);
  const store=createDurableDeviceTrustStore({directory:f.trustDirectory});
  const device=store.trustDevice({name:'Missing',platform:'linux',publicKeyPem:binding.publicKeyPem},
    {expectedRevision:0,decision:{eventId:binding.eventId,requestId:binding.requestId,
      fingerprint:binding.fingerprint}});
  audit.auditWrite({...decision,phase:'outcome',outcome:'accepted',deviceId:device.deviceId,
    trustRevisionAfter:1});audit.close();
  const filename=path.join(f.trustDirectory,'trusted-devices-v1.json');
  const snapshot=JSON.parse(readFileSync(filename,'utf8'));
  snapshot.devices=[];
  writeFileSync(filename,JSON.stringify(snapshot)+'\n');
  assert.equal(analyzeOwnerPairingRecovery(f).state,'CORRUPT');
});

test('abandoned reconciliation lock is reported and only explicitly cleared',t=>{
  const f=fixture(t);
  createDurableDeviceTrustStore({directory:f.trustDirectory});
  const audit=createDurableOwnerAudit({directory:f.auditDirectory});audit.close();
  const helperUrl=new URL('../common/durable-process-lock.mjs',import.meta.url).href;
  const source=`
    import {createDurableProcessLock} from ${JSON.stringify(helperUrl)};
    createDurableProcessLock(process.argv[1],'.owner-pairing-reconciliation.lock','reconciliation');
  `;
  const child=spawnSync(process.execPath,['--input-type=module','-e',source,f.auditDirectory],
    {encoding:'utf8',timeout:10000});
  assert.equal(child.status,0,child.stderr);
  assert.equal(analyzeOwnerPairingRecovery(f).state,'RECOVERY_LOCK_PRESENT');
  assert.throws(()=>reconcileOwnerPairingRecovery({...f,
    operatorConfirmedNoActiveWriters:true}),/RECOVERY_LOCK_PRESENT/);
  assert.deepEqual(clearStaleOwnerPairingRecoveryLocks({...f,
    operatorConfirmedNoActiveRecovery:true}),{cleared:1});
  assert.deepEqual(analyzeOwnerPairingRecovery(f),{state:'NO_INTENT'});
});

test('ownerless acquisition-crash lock remains unverified and is never auto-cleared',t=>{
  const f=fixture(t);
  createDurableDeviceTrustStore({directory:f.trustDirectory});
  const audit=createDurableOwnerAudit({directory:f.auditDirectory});audit.close();
  mkdirSync(path.join(f.auditDirectory,'.owner-pairing-reconciliation.lock'),{mode:0o700});
  assert.equal(analyzeOwnerPairingRecovery(f).state,'RECOVERY_LOCK_UNVERIFIED');
  assert.throws(()=>clearStaleOwnerPairingRecoveryLocks({...f,
    operatorConfirmedNoActiveRecovery:true}),/active or unverified/);
  assert.equal(analyzeOwnerPairingRecovery(f).state,'RECOVERY_LOCK_UNVERIFIED');
});

test('active recovery process blocks writers and can only be cleared after SIGKILL evidence',async t=>{
  const f=fixture(t);
  createDurableDeviceTrustStore({directory:f.trustDirectory});
  const audit=createDurableOwnerAudit({directory:f.auditDirectory});audit.close();
  const child=await activeRecoveryChild(f);
  t.after(()=>{if(child.exitCode===null)child.kill('SIGKILL');});
  assert.equal(analyzeOwnerPairingRecovery(f).state,'RECOVERY_LOCK_ACTIVE');
  assert.throws(()=>createDurableOwnerAudit({directory:f.auditDirectory}),/reconciliation/i);
  assert.throws(()=>createDurableDeviceTrustStore({directory:f.trustDirectory}),/reconciliation/i);
  assert.throws(()=>clearStaleOwnerPairingRecoveryLocks({...f,
    operatorConfirmedNoActiveRecovery:true}),/active or unverified/);
  assert.equal(analyzeOwnerPairingRecovery(f).state,'RECOVERY_LOCK_ACTIVE');
  child.kill('SIGKILL');
  await once(child,'exit');
  assert.equal(analyzeOwnerPairingRecovery(f).state,'RECOVERY_LOCK_PRESENT');
  assert.deepEqual(clearStaleOwnerPairingRecoveryLocks({...f,
    operatorConfirmedNoActiveRecovery:true}),{cleared:2});
  assert.deepEqual(analyzeOwnerPairingRecovery(f),{state:'NO_INTENT'});
});

test('orphan trust temporary file without its writer lock fails closed',t=>{
  const f=fixture(t);
  createDurableDeviceTrustStore({directory:f.trustDirectory});
  const audit=createDurableOwnerAudit({directory:f.auditDirectory});audit.close();
  const temp=path.join(f.trustDirectory,'.trust-0123456789abcdef01234567');
  writeFileSync(temp,'partial',{mode:0o600});
  assert.equal(analyzeOwnerPairingRecovery(f).state,'ORPHAN_TRUST_TEMP');
  assert.throws(()=>reconcileOwnerPairingRecovery({...f,
    operatorConfirmedNoActiveWriters:true}),/ORPHAN_TRUST_TEMP/);
  assert.equal(readFileSync(temp,'utf8'),'partial');
});
