import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ownerPrincipalId } from '../dashboard/owner-identity.mjs';
import { createDurableOwnerAudit } from '../dashboard/durable-owner-audit.mjs';
import { createDurableOwnerDeviceApprovalByIdReader, createDurableOwnerDeviceApprovalReader, ownerDeviceApprovalIsConsistent,
  ownerDeviceApprovalReceipt } from '../dashboard/durable-owner-device-authorization.mjs';
import { createDurableDeviceTrustStore } from '../devices/durable-trust.mjs';
import { deviceChallengeMessage } from '../devices/registry.mjs';

const OWNER=Object.freeze({issuer:'https://identity.cloudflareaccess.com',subject:'owner-123'});
const DEVICE='f1a2b3c4-d5e6-4a9f-8abc-1bb9b99c0001';
const EVENT='f1a2b3c4-d5e6-4a9f-8abc-1bb9b99c0002';
const REQUEST='f1a2b3c4-d5e6-4a9f-8abc-1bb9b99c0003';
const FINGERPRINT='a'.repeat(64);
function evidence(){
  const ownerId=ownerPrincipalId(OWNER);
  const intent={version:2,phase:'intent',eventId:EVENT,operation:'approve',ownerId,
    requestId:REQUEST,fingerprint:FINGERPRINT,trustRevisionBefore:3};
  const outcome={version:2,phase:'outcome',eventId:EVENT,operation:'approve',ownerId,
    requestId:REQUEST,fingerprint:FINGERPRINT,trustRevisionBefore:3,
    trustRevisionAfter:4,deviceId:DEVICE,outcome:'accepted'};
  const transition={operation:'approve',eventId:EVENT,requestId:REQUEST,
    fingerprint:FINGERPRINT,deviceId:DEVICE,previousRevision:3,revision:4};
  return {owner:OWNER,deviceId:DEVICE,recoveryState:{state:'CONSISTENT'},
    audit:{events:[intent,outcome]},trust:{transitions:[transition],devices:[{
      deviceId:DEVICE,fingerprint:FINGERPRINT,
    }],revision:4}};
}

test('owner-device access requires a consistent exact WAL and trust receipt join',()=>{
  const input=evidence();
  assert.equal(ownerDeviceApprovalIsConsistent(input),true);
  assert.deepEqual(ownerDeviceApprovalReceipt(input),{eventId:EVENT,deviceId:DEVICE,fingerprint:FINGERPRINT,
    trustRevisionBefore:3,trustRevisionAfter:4,trustRevision:4});
  for(const change of [
    x=>{x.recoveryState={state:'REVISION_DIVERGED'};},
    x=>{x.recoveryState={state:'ACTIVE_WRITER',underlyingState:'CONSISTENT',
      auditWriterActive:true,trustWriterActive:true};},
    x=>{x.audit.events[0].requestId='f1a2b3c4-d5e6-4a9f-8abc-1bb9b99c0099';},
    x=>{x.audit.events[1].fingerprint='b'.repeat(64);},
    x=>{x.trust.transitions[0].revision=5;},
    x=>{x.trust.transitions[0].deviceId='00000000-0000-4000-8000-000000000000';},
    x=>{x.trust.devices=[];},
    x=>{x.audit.events.push({...x.audit.events[1]});},
  ]){
    const bad=evidence();change(bad);
    assert.equal(ownerDeviceApprovalIsConsistent(bad),false);
  }
  const activeAudit=evidence();
  activeAudit.recoveryState={state:'ACTIVE_WRITER',underlyingState:'CONSISTENT',
    auditWriterActive:true,trustWriterActive:false};
  assert.equal(ownerDeviceApprovalIsConsistent(activeAudit),true,
    'the ordinary long-lived audit writer is compatible with a consistent read snapshot');
});

test('owner-device access does not transfer an approval to another principal',()=>{
  assert.equal(ownerDeviceApprovalIsConsistent({...evidence(),owner:{
    issuer:OWNER.issuer,subject:'different-owner',
  }}),false);
});

test('real durable approval receipt remains verifiable inside the trust response fence',t=>{
  const root=mkdtempSync(path.join(os.tmpdir(),'g7-owner-response-fence-'));
  t.after(()=>rmSync(root,{recursive:true,force:true}));
  const auditDirectory=path.join(root,'audit'),trustDirectory=path.join(root,'trust');
  mkdirSync(auditDirectory,{mode:0o700});mkdirSync(trustDirectory,{mode:0o700});
  const audit=createDurableOwnerAudit({directory:auditDirectory});
  const trustStore=createDurableDeviceTrustStore({directory:trustDirectory});
  t.after(()=>{try{audit.close();}catch{}try{trustStore.close();}catch{}});
  const {publicKey,privateKey}=generateKeyPairSync('ed25519');
  const fingerprint=createHash('sha256').update(publicKey.export({type:'spki',format:'der'})).digest('hex');
  const eventId=randomUUID(),requestId=randomUUID(),ownerId=ownerPrincipalId(OWNER);
  const at=new Date().toISOString();
  audit.auditWrite({event:'g7_owner_pairing',version:2,at,eventId,operation:'approve',ownerId,
    requestId,fingerprint,trustRevisionBefore:0,phase:'intent'});
  const device=trustStore.trustDevice({name:'response-fence-device',platform:'linux',
    publicKeyPem:publicKey.export({type:'spki',format:'pem'})},
  {expectedRevision:0,decision:{eventId,requestId,fingerprint}});
  audit.auditWrite({event:'g7_owner_pairing',version:2,at:new Date().toISOString(),eventId,
    operation:'approve',ownerId,requestId,fingerprint,trustRevisionBefore:0,phase:'outcome',
    outcome:'accepted',deviceId:device.deviceId,trustRevisionAfter:1});
  const challenge=trustStore.registry.beginHandshake(device.deviceId);
  const proof=sign(null,deviceChallengeMessage(device.deviceId,challenge.nonce),privateKey)
    .toString('base64url');
  const session=trustStore.registry.completeHandshake(device.deviceId,proof);
  assert.equal(trustStore.registry.heartbeat(device.deviceId,session.sessionId,1),true);
  const readApproval=createDurableOwnerDeviceApprovalReader({auditDirectory,trustDirectory});
  const readApprovalById=createDurableOwnerDeviceApprovalByIdReader({auditDirectory,trustDirectory});
  const beforeFence=readApproval(OWNER,device.deviceId);
  assert.ok(beforeFence);
  const dispatchPermit=trustStore.acquireDispatchPermit({deviceId:device.deviceId,
    sessionId:session.sessionId,expectedRevision:1});
  try{
    assert.deepEqual(readApprovalById(ownerId,device.deviceId),{ownerId,...beforeFence},
      'a live dispatch permit must not make the approved machine unbound during heartbeat');
    let escapedProof;
    const duringFence=trustStore.withCurrentSession({deviceId:device.deviceId,
      sessionId:session.sessionId,expectedRevision:1},proof=>{
        escapedProof=proof;
        assert.equal(readApproval(OWNER,device.deviceId),null,
          'an active gate without its unforgeable session proof remains fail-closed');
        return readApproval(OWNER,device.deviceId,proof);
      });
    assert.deepEqual(duringFence,beforeFence,
      'the exact current session proof must remain verifiable while another authorized dispatch holds its permit');
    const expiredProof=trustStore.withCurrentSession({deviceId:device.deviceId,
      sessionId:session.sessionId,expectedRevision:1},()=>
        readApproval(OWNER,device.deviceId,escapedProof));
    assert.equal(expiredProof,null,
      'an expired capability cannot excuse a later operation gate');
  }finally{dispatchPermit.release();}
});
