import { randomUUID } from 'node:crypto';
import { ownerIdentityDigest, ownerPrincipalId, isOwnerPrincipal } from './owner-identity.mjs';

const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CLIENT=/^[A-Za-z0-9_.-]{8,256}$/;
const fail=(code,message)=>Object.assign(new Error(message),{code});
function validReceipt(value,deviceId){
  return value&&value.deviceId===deviceId&&UUID.test(value.eventId??'')&&
    /^[a-f0-9]{64}$/.test(value.fingerprint??'')&&
    Number.isSafeInteger(value.trustRevisionBefore)&&value.trustRevisionBefore>=0&&
    Number.isSafeInteger(value.trustRevisionAfter)&&
    value.trustRevisionAfter===value.trustRevisionBefore+1&&
    Number.isSafeInteger(value.trustRevision)&&value.trustRevision>=value.trustRevisionAfter;
}

// Internal candidate service only. Any HTTP owner action that calls this must
// first enforce its own origin and CSRF boundary; this module does not expose a
// route or mint a browser capability.
export function createOwnerMachineBindingService({accessVerifier,auditWrite,
  readApprovalReceipt,machineBindingStore,now=()=>new Date(),testHooks}={}){
  if(typeof accessVerifier?.verifyPrincipal!=='function'||typeof auditWrite!=='function'||
     typeof readApprovalReceipt!=='function'||typeof machineBindingStore?.bind!=='function'||
     typeof machineBindingStore?.resolve!=='function'||typeof machineBindingStore?.revision!=='function'||
     typeof now!=='function'||testHooks!==undefined&&(!process.env.NODE_TEST_CONTEXT||
       typeof testHooks?.afterDurableWrite!=='function'))throw new TypeError('Verified Owner, durable audit, I2 receipt, and binding store required');
  let poisoned=false;
  return Object.freeze({machineBindingStore,auditWrite,
    async bind({ownerAssertion,clientId,deviceId,expectedRevision,eventId:requestedEventId}={}){
      if(poisoned)throw fail('BINDING_UNAVAILABLE','Owner machine binding service is unavailable');
      if(typeof ownerAssertion!=='string'||ownerAssertion.length>16*1024||
         typeof clientId!=='string'||!CLIENT.test(clientId)||!UUID.test(deviceId??'')||
         !Number.isSafeInteger(expectedRevision)||expectedRevision<0||
         requestedEventId!==undefined&&!UUID.test(requestedEventId??'')){
        throw fail('INVALID','Invalid Owner machine binding request');
      }
      let owner;
      try{owner=await accessVerifier.verifyPrincipal(ownerAssertion);}catch{}
      if(!isOwnerPrincipal(owner))throw fail('OWNER_AUTH_REQUIRED','Verified Owner JWT required');
      const ownerId=ownerPrincipalId(owner),ownerDigest=ownerIdentityDigest(owner);
      let ownerReceipt;
      try{ownerReceipt=readApprovalReceipt(owner,deviceId);}catch{}
      if(!validReceipt(ownerReceipt,deviceId)||
         ownerReceipt.ownerId!==undefined&&ownerReceipt.ownerId!==ownerId){
        throw fail('APPROVAL_UNAVAILABLE','Current durable I2 approval is required');
      }
      const approvalReceipt=Object.freeze({...ownerReceipt,ownerId});
      const existing=machineBindingStore.resolve(clientId);
      if(existing){
        if(existing.ownerId===ownerId&&existing.ownerDigest===ownerDigest&&
           existing.deviceId===deviceId&&existing.fingerprint===approvalReceipt.fingerprint&&
           existing.approvalEventId===approvalReceipt.eventId){
          return Object.freeze({revision:machineBindingStore.revision(),binding:existing,
            alreadyBound:true});
        }
        throw fail('BINDING_CONFLICT','Client-ID already belongs to another Owner or device');
      }
      if(machineBindingStore.revision()!==expectedRevision){
        throw fail('REVISION_CONFLICT','Machine binding revision conflict');
      }
      const eventId=requestedEventId??randomUUID();
      const at=now().toISOString();
      const intent=Object.freeze({event:'g7_owner_machine_binding',version:3,at,eventId,
        operation:'bind',ownerId,ownerDigest,clientId,deviceId,
        fingerprint:approvalReceipt.fingerprint,approvalEventId:approvalReceipt.eventId,
        trustRevisionBefore:approvalReceipt.trustRevisionBefore,
        trustRevisionAfter:approvalReceipt.trustRevisionAfter,
        trustRevision:approvalReceipt.trustRevision,bindingRevisionBefore:expectedRevision,
        phase:'intent'});
      try{
        if(auditWrite(intent)!==true)throw Error('Machine binding audit intent not committed');
        if(testHooks)testHooks.afterDurableWrite('after-intent');
      }catch{
        poisoned=true;
        throw fail('AUDIT_UNAVAILABLE','Machine binding intent could not be committed');
      }
      let committed;
      try{
        committed=machineBindingStore.bind({bindingEventId:eventId,ownerId,ownerDigest,
          clientId,deviceId,fingerprint:approvalReceipt.fingerprint,approvalReceipt},
          {expectedRevision});
        if(committed.revision!==expectedRevision+1||
           committed.binding.bindingRevision!==expectedRevision+1){
          throw Error('Machine binding commit returned unexpected revision');
        }
        if(testHooks)testHooks.afterDurableWrite('after-store-commit');
      }catch(error){
        poisoned=true;
        throw Object.assign(fail('BINDING_OUTCOME_UNKNOWN',
          `Binding intent is durable; store mutation requires explicit recovery (${error?.code??'STORE_ERROR'})`),{cause:error});
      }
      try{
        if(auditWrite(Object.freeze({...intent,at:now().toISOString(),phase:'outcome',
          outcome:'accepted',bindingRevisionAfter:committed.revision}))!==true){
          throw Error('Machine binding outcome not committed');
        }
      }catch{
        poisoned=true;
        throw fail('BINDING_OUTCOME_UNKNOWN','Binding store committed but audit outcome is missing');
      }
      return committed;
    },
  });
}
