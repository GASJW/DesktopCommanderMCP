import { analyzeOwnerPairingRecovery } from './owner-pairing-reconciliation.mjs';
import { inspectDurableOwnerAudit } from './durable-owner-audit.mjs';
import { inspectDurableDeviceTrust, isCurrentTrustSessionProof } from '../devices/durable-trust.mjs';
import { ownerPrincipalId } from './owner-identity.mjs';

const OWNER_ID=/^[a-f0-9]{24}$/;

function readConsistentDuringKnownTrustWork(recoveryState,{audit,trust,trustDirectory,
  deviceId,trustSessionProof}={}){
  if(!audit||!trust||recoveryState?.state!=='ACTIVE_WRITER'||
     recoveryState.underlyingState!=='CONSISTENT'||recoveryState.trustWriterActive!==true||
     audit?.lockPresent&&audit.lockStatus!=='active'||trust?.lockPresent||
     trust?.temporaryFiles?.length)return recoveryState;
  const onlyDispatchPermits=!trust.operationGatePresent&&
    Array.isArray(trust.dispatchPermits)&&trust.dispatchPermits.length>0&&
    trust.dispatchPermits.every(permit=>permit.status==='active'&&
      permit.kind==='trust-dispatch-permit');
  const dispatchPermitsAreSafe=Array.isArray(trust.dispatchPermits)&&
    trust.dispatchPermits.every(permit=>permit.status==='active'&&
      permit.kind==='trust-dispatch-permit');
  const currentResponseFence=trust.operationGatePresent===true&&
    trust.operationGateStatus==='active'&&dispatchPermitsAreSafe&&
    isCurrentTrustSessionProof(trustSessionProof,{directory:trustDirectory,deviceId,
      expectedRevision:trust.revision,trustRevision:trust.revision});
  if(!onlyDispatchPermits&&!currentResponseFence)return recoveryState;
  // The WAL and snapshot were read and cross-checked above. Normalize only an
  // active handoff permits or the exact synchronous response gate; other trust
  // writers, stale permits, and recovery locks remain fail-closed.
  return {...recoveryState,state:'CONSISTENT',trustWriterActive:false};
}

// Read-only owner/device grant lookup for an explicitly mounted Gateway
// candidate. Any unreadable, inconsistent, incomplete, or unbound evidence
// fails closed.
export function ownerDeviceApprovalReceiptById({ownerId,deviceId,recoveryState,
  audit,trust}={}){
  const verifiedRecovery=recoveryState?.state==='CONSISTENT'||
    recoveryState?.state==='ACTIVE_WRITER'&&recoveryState.underlyingState==='CONSISTENT'&&
      recoveryState.auditWriterActive===true&&recoveryState.trustWriterActive!==true;
  const i2Consistent=recoveryState?.state==='MACHINE_BINDING_OUTCOME_UNKNOWN'&&
    recoveryState.i2State==='CONSISTENT'||recoveryState?.state==='ACTIVE_WRITER'&&
      recoveryState.consistencyState==='CONSISTENT'&&recoveryState.auditWriterActive===true&&
      recoveryState.trustWriterActive!==true;
  if(!OWNER_ID.test(ownerId??'')||typeof deviceId!=='string'||!(verifiedRecovery||i2Consistent)||
     !Array.isArray(audit?.events)||!Array.isArray(trust?.transitions)||
     !Array.isArray(trust?.devices)||!Number.isSafeInteger(trust.revision)||trust.revision<0)return null;
  const outcomes=audit.events.filter(event=>event.version===2&&event.phase==='outcome'&&
    event.operation==='approve'&&event.outcome==='accepted'&&event.ownerId===ownerId&&
    event.deviceId===deviceId);
  if(outcomes.length!==1)return null;
  const outcome=outcomes[0];
  const intents=audit.events.filter(event=>event.version===2&&event.phase==='intent'&&
    event.eventId===outcome.eventId);
  const transitions=trust.transitions.filter(item=>item.operation==='approve'&&
    item.eventId===outcome.eventId);
  if(intents.length!==1||transitions.length!==1)return null;
  const intent=intents[0],transition=transitions[0];
  if(intent.ownerId!==outcome.ownerId||intent.operation!=='approve'||
     intent.requestId!==outcome.requestId||intent.fingerprint!==outcome.fingerprint||
     intent.trustRevisionBefore!==outcome.trustRevisionBefore||
     transition.requestId!==outcome.requestId||
     transition.fingerprint!==outcome.fingerprint||
     transition.deviceId!==outcome.deviceId||
     transition.previousRevision!==outcome.trustRevisionBefore||
     transition.revision!==outcome.trustRevisionAfter||
     outcome.trustRevisionAfter!==outcome.trustRevisionBefore+1||
     trust.revision<outcome.trustRevisionAfter)return null;
  if(!trust.devices.some(device=>device.deviceId===deviceId&&
     device.fingerprint===outcome.fingerprint))return null;
  return Object.freeze({ownerId,eventId:outcome.eventId,deviceId:outcome.deviceId,fingerprint:outcome.fingerprint,
    trustRevisionBefore:outcome.trustRevisionBefore,trustRevisionAfter:outcome.trustRevisionAfter,
    trustRevision:trust.revision});
}

export function ownerDeviceApprovalReceipt({owner,deviceId,recoveryState,audit,trust}={}){
  if(!owner||typeof owner.issuer!=='string'||typeof owner.subject!=='string'||!owner.subject)return null;
  const receipt=ownerDeviceApprovalReceiptById({ownerId:ownerPrincipalId(owner),deviceId,
    recoveryState,audit,trust});
  if(!receipt)return null;
  const {ownerId,...publicReceipt}=receipt;
  return Object.freeze(publicReceipt);
}

export function ownerDeviceApprovalIsConsistent(evidence){
  return ownerDeviceApprovalReceipt(evidence)!==null;
}

export function createDurableOwnerDeviceApprovalReader({auditDirectory,trustDirectory}={}){
  if(typeof auditDirectory!=='string'||typeof trustDirectory!=='string'){
    throw new TypeError('Audit and trust directories are required');
  }
  return function readDeviceApproval(owner,deviceId,trustSessionProof){
    try{
      let recoveryState=analyzeOwnerPairingRecovery({auditDirectory,trustDirectory});
      const audit=inspectDurableOwnerAudit({directory:auditDirectory});
      const trust=inspectDurableDeviceTrust({directory:trustDirectory});
      recoveryState=readConsistentDuringKnownTrustWork(recoveryState,{audit,trust,
        trustDirectory,deviceId,trustSessionProof});
      return ownerDeviceApprovalReceipt({owner,deviceId,recoveryState,audit,trust});
    }catch{return null;}
  };
}

export function createDurableOwnerDeviceApprovalByIdReader({auditDirectory,trustDirectory}={}){
  if(typeof auditDirectory!=='string'||typeof trustDirectory!=='string'){
    throw new TypeError('Audit and trust directories are required');
  }
  return function readDeviceApprovalById(ownerId,deviceId){
    try{
      let recoveryState=analyzeOwnerPairingRecovery({auditDirectory,trustDirectory});
      const audit=inspectDurableOwnerAudit({directory:auditDirectory});
      const trust=inspectDurableDeviceTrust({directory:trustDirectory});
      recoveryState=readConsistentDuringKnownTrustWork(recoveryState,{audit,trust,trustDirectory,deviceId});
      return ownerDeviceApprovalReceiptById({ownerId,deviceId,recoveryState,audit,trust});
    }catch{return null;}
  };
}

export function createDurableOwnerDeviceAuthorizer(options={}){
  const readReceipt=createDurableOwnerDeviceApprovalReader(options);
  return function authorizeDevice(owner,deviceId){return readReceipt(owner,deviceId)!==null;};
}
