import test from 'node:test';
import assert from 'node:assert/strict';
import { ownerPrincipalId } from '../dashboard/owner-pairing-http.mjs';
import { ownerDeviceApprovalIsConsistent } from '../dashboard/durable-owner-device-authorization.mjs';

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
    }]}};
}

test('owner-device access requires a consistent exact WAL and trust receipt join',()=>{
  const input=evidence();
  assert.equal(ownerDeviceApprovalIsConsistent(input),true);
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
