import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createHash, createPublicKey, generateKeyPairSync, randomUUID } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createDurableDeviceTrustStore } from '../devices/durable-trust.mjs';
import { createDurableMachineBindingStore } from '../devices/durable-machine-bindings.mjs';
import { createDurableOwnerAudit, inspectDurableOwnerAudit,
  readDurableOwnerMachineBindingDecision, readDurableOwnerMachineBindingHistory }
  from '../dashboard/durable-owner-audit.mjs';
import { createDurableOwnerDeviceApprovalReader } from '../dashboard/durable-owner-device-authorization.mjs';
import { analyzeOwnerPairingRecovery, reconcileOwnerPairingRecovery } from '../dashboard/owner-pairing-reconciliation.mjs';
import { ownerPrincipalId } from '../dashboard/owner-identity.mjs';

const OWNER=Object.freeze({issuer:'https://pilot.cloudflareaccess.com',
  subject:'synthetic-owner-machine-binding-crash-test'});
const CHILD=new URL('./fixtures-owner-machine-binding-crash.mjs',import.meta.url);
const at='2026-10-17T12:00:00.000Z';

function fixture(t){
  const root=mkdtempSync(path.join(tmpdir(),'g7-owner-machine-binding-crash-'));
  const value={root,auditDirectory:path.join(root,'audit'),
    trustDirectory:path.join(root,'trust'),bindingDirectory:path.join(root,'bindings'),
    clientId:'vpsc-crash-window-test-client',owner:OWNER,deviceId:null};
  t.after(()=>rmSync(root,{recursive:true,force:true}));
  return value;
}

function seedApprovedDevice(f){
  const {publicKey}=generateKeyPairSync('ed25519');
  const publicKeyPem=publicKey.export({type:'spki',format:'pem'});
  const fingerprint=createHash('sha256').update(createPublicKey(publicKeyPem)
    .export({type:'spki',format:'der'})).digest('hex');
  const eventId=randomUUID(),requestId=randomUUID(),ownerId=ownerPrincipalId(OWNER);
  const decision={event:'g7_owner_pairing',version:2,at,eventId,operation:'approve',ownerId,
    requestId,fingerprint,trustRevisionBefore:0,phase:'intent'};
  const audit=createDurableOwnerAudit({directory:f.auditDirectory});
  const trust=createDurableDeviceTrustStore({directory:f.trustDirectory});
  audit.auditWrite(decision);
  const device=trust.trustDevice({name:'Synthetic crash-test device',platform:'linux',publicKeyPem},
    {expectedRevision:0,decision:{eventId,requestId,fingerprint}});
  audit.auditWrite({...decision,phase:'outcome',outcome:'accepted',deviceId:device.deviceId,
    trustRevisionAfter:1});
  audit.close();trust.close();
  f.deviceId=device.deviceId;
  return {fingerprint,ownerId,deviceId:device.deviceId};
}

async function waitForPhase(child,expectedPhase){
  let text='',stderr='';
  return new Promise((resolve,reject)=>{
    const timeout=setTimeout(()=>reject(Error(`child did not reach ${expectedPhase}: ${stderr}`)),10000);
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stderr.on('data',chunk=>{stderr+=chunk;});
    child.stdout.on('data',chunk=>{
      text+=chunk;
      const newline=text.indexOf('\n');
      if(newline<0)return;
      clearTimeout(timeout);
      try{
        const message=JSON.parse(text.slice(0,newline));
        if(message.phase!==expectedPhase)reject(Error(`unexpected child phase: ${message.phase}`));
        else resolve(message);
      }catch(error){reject(error);}
    });
    child.once('error',error=>{clearTimeout(timeout);reject(error);});
    child.once('exit',(code,signal)=>{
      clearTimeout(timeout);
      if(!text.includes('\n'))reject(Error(`child exited before ${expectedPhase}: ${code}/${signal}: ${stderr}`));
    });
  });
}

async function killAtPhase(f,mode,expectedPhase,t){
  const args=[CHILD.pathname,mode,f.auditDirectory,f.trustDirectory,f.bindingDirectory,
    f.deviceId,OWNER.issuer,OWNER.subject];
  const child=spawn(process.execPath,args,{stdio:['ignore','pipe','pipe']});
  t.after(()=>{if(child.exitCode===null&&child.signalCode===null)child.kill('SIGKILL');});
  const phase=await waitForPhase(child,expectedPhase);
  assert.equal(Number.isInteger(phase.pid),true);
  const exited=once(child,'exit');
  assert.equal(child.kill('SIGKILL'),true);
  const [code,signal]=await exited;
  assert.equal(code,null);
  assert.equal(signal,'SIGKILL');
  return phase;
}

function reopenMachineStore(f){
  const readApproval=createDurableOwnerDeviceApprovalReader({
    auditDirectory:f.auditDirectory,trustDirectory:f.trustDirectory});
  const approvalForOwner=(owner,deviceId)=>{
    if(owner.issuer!==OWNER.issuer||owner.subject!==OWNER.subject)return null;
    const receipt=readApproval(owner,deviceId);
    return receipt?Object.freeze({...receipt,ownerId:ownerPrincipalId(owner)}):null;
  };
  return createDurableMachineBindingStore({directory:f.bindingDirectory,
    verifyApprovalReceipt:binding=>approvalForOwner(OWNER,binding.deviceId),
    readBindingDecision:binding=>readDurableOwnerMachineBindingDecision({
      directory:f.auditDirectory,eventId:binding.bindingEventId}),
    readBindingHistory:()=>readDurableOwnerMachineBindingHistory({directory:f.auditDirectory})});
}

function persistedBindingSnapshot(f){
  return JSON.parse(readFileSync(path.join(f.bindingDirectory,'machine-bindings-v2.json'),'utf8'));
}

test('SIGKILL after durable machine-binding intent leaves no snapshot mutation and no I2 repair',async t=>{
  const f=fixture(t);seedApprovedDevice(f);
  await killAtPhase(f,'after-audit-intent','intent-durable',t);

  const decision=readDurableOwnerMachineBindingDecision({directory:f.auditDirectory,
    eventId:inspectDurableOwnerAudit({directory:f.auditDirectory}).pending[0].eventId});
  assert.equal(decision.state,'PENDING');
  assert.equal(analyzeOwnerPairingRecovery(f).state,'MACHINE_BINDING_OUTCOME_UNKNOWN');
  assert.throws(()=>reconcileOwnerPairingRecovery({...f,
    operatorConfirmedNoActiveWriters:true}),/MACHINE_BINDING_OUTCOME_UNKNOWN/);
  const snapshot=persistedBindingSnapshot(f);
  assert.equal(snapshot.revision,0);
  assert.deepEqual(snapshot.bindings,[]);
  assert.throws(()=>reopenMachineStore(f),
    error=>error?.code==='BINDING_OUTCOME_UNKNOWN');
  const wal=inspectDurableOwnerAudit({directory:f.auditDirectory});
  assert.equal(wal.pending.length,1);
  assert.equal(wal.events.filter(event=>event.event==='g7_owner_machine_binding'&&
    event.phase==='outcome').length,0);
});

test('SIGKILL after binding snapshot commit leaves exact outcome unknown and blocks resolution',async t=>{
  const f=fixture(t);seedApprovedDevice(f);
  await killAtPhase(f,'after-snapshot-commit','snapshot-committed',t);

  const wal=inspectDurableOwnerAudit({directory:f.auditDirectory});
  const bindingIntent=wal.pending.find(event=>event.event==='g7_owner_machine_binding');
  assert.ok(bindingIntent);
  assert.equal(readDurableOwnerMachineBindingDecision({directory:f.auditDirectory,
    eventId:bindingIntent.eventId}).state,'PENDING');
  assert.equal(analyzeOwnerPairingRecovery(f).state,'MACHINE_BINDING_OUTCOME_UNKNOWN');
  assert.throws(()=>reconcileOwnerPairingRecovery({...f,
    operatorConfirmedNoActiveWriters:true}),/MACHINE_BINDING_OUTCOME_UNKNOWN/);
  const snapshot=persistedBindingSnapshot(f);
  assert.equal(snapshot.revision,1,'the child committed exactly one binding snapshot');
  assert.equal(snapshot.bindings.length,1);
  assert.equal(snapshot.bindings[0].deviceId,f.deviceId);
  assert.equal(snapshot.bindings[0].bindingEventId,bindingIntent.eventId);
  assert.throws(()=>reopenMachineStore(f),
    error=>error?.code==='BINDING_OUTCOME_UNKNOWN');
  const after=inspectDurableOwnerAudit({directory:f.auditDirectory});
  assert.equal(after.pending.length,1);
  assert.equal(after.events.filter(event=>event.event==='g7_owner_machine_binding'&&
    event.phase==='outcome').length,0);
});
