import { ownerPrincipalId } from './owner-pairing-http.mjs';
import { analyzeOwnerPairingRecovery } from './owner-pairing-reconciliation.mjs';
import { inspectDurableOwnerAudit } from './durable-owner-audit.mjs';
import { inspectDurableDeviceTrust } from '../devices/durable-trust.mjs';

// Read-only owner/device grant lookup for an explicitly mounted Gateway
// candidate. Any unreadable, inconsistent, incomplete, or unbound evidence
// fails closed.
export function ownerDeviceApprovalReceipt({owner,deviceId,recoveryState,
  audit,trust}={}){
  const verifiedRecovery=recoveryState?.state==='CONSISTENT'||
    recoveryState?.state==='ACTIVE_WRITER'&&recoveryState.underlyingState==='CONSISTENT'&&
      recoveryState.auditWriterActive===true&&recoveryState.trustWriterActive!==true;
  if(!owner||typeof owner.issuer!=='string'||typeof owner.subject!=='string'||
     !owner.subject||typeof deviceId!=='string'||!verifiedRecovery||
     !Array.isArray(audit?.events)||!Array.isArray(trust?.transitions)||
     !Array.isArray(trust?.devices)||!Number.isSafeInteger(trust.revision)||trust.revision<0)return null;
  const ownerId=ownerPrincipalId(owner);
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
  return Object.freeze({eventId:outcome.eventId,deviceId:outcome.deviceId,fingerprint:outcome.fingerprint,
    trustRevisionBefore:outcome.trustRevisionBefore,trustRevisionAfter:outcome.trustRevisionAfter,
    trustRevision:trust.revision});
}

export function ownerDeviceApprovalIsConsistent(evidence){
  return ownerDeviceApprovalReceipt(evidence)!==null;
}

export function createDurableOwnerDeviceApprovalReader({auditDirectory,trustDirectory}={}){
  if(typeof auditDirectory!=='string'||typeof trustDirectory!=='string'){
    throw new TypeError('Audit and trust directories are required');
  }
  return function readDeviceApproval(owner,deviceId){
    try{
      const recoveryState=analyzeOwnerPairingRecovery({auditDirectory,trustDirectory});
      const audit=inspectDurableOwnerAudit({directory:auditDirectory});
      const trust=inspectDurableDeviceTrust({directory:trustDirectory});
      return ownerDeviceApprovalReceipt({owner,deviceId,recoveryState,audit,trust});
    }catch{return null;}
  };
}

export function createDurableOwnerDeviceAuthorizer(options={}){
  const readReceipt=createDurableOwnerDeviceApprovalReader(options);
  return function authorizeDevice(owner,deviceId){return readReceipt(owner,deviceId)!==null;};
}
