import { ownerPrincipalId } from './owner-pairing-http.mjs';
import { analyzeOwnerPairingRecovery } from './owner-pairing-reconciliation.mjs';
import { inspectDurableOwnerAudit } from './durable-owner-audit.mjs';
import { inspectDurableDeviceTrust } from '../devices/durable-trust.mjs';

// Read-only owner/device grant lookup for an explicitly mounted Gateway
// candidate. Any unreadable, inconsistent, incomplete, or unbound evidence
// fails closed.
export function ownerDeviceApprovalIsConsistent({owner,deviceId,recoveryState,
  audit,trust}={}){
  const verifiedRecovery=recoveryState?.state==='CONSISTENT'||
    recoveryState?.state==='ACTIVE_WRITER'&&recoveryState.underlyingState==='CONSISTENT'&&
      recoveryState.auditWriterActive===true&&recoveryState.trustWriterActive!==true;
  if(!owner||typeof owner.issuer!=='string'||typeof owner.subject!=='string'||
     !owner.subject||typeof deviceId!=='string'||!verifiedRecovery||
     !Array.isArray(audit?.events)||!Array.isArray(trust?.transitions)||
     !Array.isArray(trust?.devices))return false;
  const ownerId=ownerPrincipalId(owner);
  const outcomes=audit.events.filter(event=>event.version===2&&event.phase==='outcome'&&
    event.operation==='approve'&&event.outcome==='accepted'&&event.ownerId===ownerId&&
    event.deviceId===deviceId);
  if(outcomes.length!==1)return false;
  const outcome=outcomes[0];
  const intents=audit.events.filter(event=>event.version===2&&event.phase==='intent'&&
    event.eventId===outcome.eventId);
  const transitions=trust.transitions.filter(item=>item.operation==='approve'&&
    item.eventId===outcome.eventId);
  if(intents.length!==1||transitions.length!==1)return false;
  const intent=intents[0],transition=transitions[0];
  if(intent.ownerId!==outcome.ownerId||intent.operation!=='approve'||
     intent.requestId!==outcome.requestId||intent.fingerprint!==outcome.fingerprint||
     intent.trustRevisionBefore!==outcome.trustRevisionBefore||
     transition.requestId!==outcome.requestId||
     transition.fingerprint!==outcome.fingerprint||
     transition.deviceId!==outcome.deviceId||
     transition.previousRevision!==outcome.trustRevisionBefore||
     transition.revision!==outcome.trustRevisionAfter||
     outcome.trustRevisionAfter!==outcome.trustRevisionBefore+1)return false;
  return trust.devices.some(device=>device.deviceId===deviceId&&
    device.fingerprint===outcome.fingerprint);
}

export function createDurableOwnerDeviceAuthorizer({auditDirectory,trustDirectory}={}){
  if(typeof auditDirectory!=='string'||typeof trustDirectory!=='string'){
    throw new TypeError('Audit and trust directories are required');
  }
  return function authorizeDevice(owner,deviceId){
    try{
      const recoveryState=analyzeOwnerPairingRecovery({auditDirectory,trustDirectory});
      const audit=inspectDurableOwnerAudit({directory:auditDirectory});
      const trust=inspectDurableDeviceTrust({directory:trustDirectory});
      return ownerDeviceApprovalIsConsistent({owner,deviceId,recoveryState,audit,trust});
    }catch{return false;}
  };
}
