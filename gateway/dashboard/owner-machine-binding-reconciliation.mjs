import { createDurableProcessLock, inspectDurableProcessLock,
  removeDeadDurableProcessLock, removeOwnedDurableProcessLock } from '../common/durable-process-lock.mjs';
import { inspectDurableOwnerAudit, appendRecoveredOwnerOutcome,
  releaseOwnerAuditLockForReconciliation, readDurableOwnerMachineBindingHistory }
  from './durable-owner-audit.mjs';
import { analyzeOwnerPairingRecovery } from './owner-pairing-reconciliation.mjs';
import { inspectDurableDeviceTrust } from '../devices/durable-trust.mjs';
import { inspectDurableMachineBindingSnapshot } from '../devices/durable-machine-bindings.mjs';

const RECOVERY_LOCK='.owner-pairing-reconciliation.lock';
const fail=(message)=>Object.assign(new Error(message),{code:'BINDING_RECOVERY_BLOCKED'});
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);

function lockAt(directory){return inspectDurableProcessLock(directory,RECOVERY_LOCK);}
function releaseLocks(locks){
  for(const lock of locks.reverse())removeOwnedDurableProcessLock({directory:lock.directory,
    name:RECOVERY_LOCK,owner:lock.owner});
}
function sameBinding(record,intent){
  return record&&record.bindingEventId===intent.eventId&&record.ownerId===intent.ownerId&&
    record.ownerDigest===intent.ownerDigest&&record.clientId===intent.clientId&&
    record.deviceId===intent.deviceId&&record.fingerprint===intent.fingerprint&&
    record.approvalEventId===intent.approvalEventId&&
    record.trustRevisionBefore===intent.trustRevisionBefore&&
    record.trustRevisionAfter===intent.trustRevisionAfter&&
    record.trustRevision===intent.trustRevision&&
    record.bindingRevision===intent.bindingRevisionBefore+1;
}

export function reconcileOwnerMachineBinding({auditDirectory,bindingDirectory,trustDirectory,
  readApprovalReceipt,operatorConfirmedNoActiveWriters}={}){
  if(operatorConfirmedNoActiveWriters!==true||typeof readApprovalReceipt!=='function'){
    throw fail('Explicit quiescence and the durable pairing receipt reader are required');
  }
  const directories=[...new Set([auditDirectory,bindingDirectory,trustDirectory])].sort();
  const initialAudit=inspectDurableOwnerAudit({directory:auditDirectory});
  const initialHistory=readDurableOwnerMachineBindingHistory({directory:auditDirectory});
  if(initialHistory.pending.length===0)return Object.freeze({state:'CONSISTENT'});
  if(initialHistory.pending.length!==1)throw fail('Multiple machine binding intents are unresolved');
  const decision=initialHistory.pending[0],intent=decision.intent;
  if(intent?.phase!=='intent'||intent.version!==3||intent.operation!=='bind'){
    throw fail('Pending machine binding intent has an unsupported schema');
  }
  const pairing=analyzeOwnerPairingRecovery({auditDirectory,trustDirectory});
  if(!(pairing.state==='MACHINE_BINDING_OUTCOME_UNKNOWN'&&pairing.i2State==='CONSISTENT')&&
     !['CONSISTENT','LEGACY_UNBOUND','NO_INTENT'].includes(pairing.state)){
    throw fail(`Device trust recovery is not consistent (${pairing.state})`);
  }
  const initialTrust=inspectDurableDeviceTrust({directory:trustDirectory});
  const initialSnapshot=inspectDurableMachineBindingSnapshot({directory:bindingDirectory});
  if(initialAudit.pending.length!==1||initialAudit.pending[0].event!=='g7_owner_machine_binding'||
     initialAudit.lockPresent&&initialAudit.lockStatus!=='dead'||
     initialSnapshot.lockPresent&&initialSnapshot.lockStatus!=='dead'||
     initialTrust.lockPresent||initialTrust.operationGatePresent||
     initialTrust.dispatchPermits.length||initialTrust.temporaryFiles.length){
    throw fail('A writer, trust transition or temporary snapshot prevents safe binding recovery');
  }
  const receipt=readApprovalReceipt(intent.ownerId,intent.deviceId);
  if(!receipt||receipt.ownerId!==intent.ownerId||receipt.eventId!==intent.approvalEventId||
     receipt.deviceId!==intent.deviceId||receipt.fingerprint!==intent.fingerprint||
     receipt.trustRevisionBefore!==intent.trustRevisionBefore||
     receipt.trustRevisionAfter!==intent.trustRevisionAfter||
     receipt.trustRevision<intent.trustRevisionAfter){
    throw fail('The pairing approval receipt no longer matches the binding intent');
  }
  const candidate=initialSnapshot.bindings.find(value=>value.bindingEventId===intent.eventId);
  let outcome;
  if(initialSnapshot.revision===intent.bindingRevisionBefore&&candidate===undefined){
    outcome='not_applied';
  }else if(initialSnapshot.revision===intent.bindingRevisionBefore+1&&sameBinding(candidate,intent)){
    outcome='accepted';
  }else{
    throw fail('Machine binding snapshot and intent disagree; no outcome can be inferred');
  }

  const held=[];
  try{
    for(const directory of directories){
      const prior=lockAt(directory);
      if(prior.present)throw fail('An existing reconciliation lock is present');
      const owner=createDurableProcessLock(directory,RECOVERY_LOCK,'reconciliation');
      held.push({directory,owner});
    }
    const auditNow=inspectDurableOwnerAudit({directory:auditDirectory});
    const trustNow=inspectDurableDeviceTrust({directory:trustDirectory});
    const snapshotNow=inspectDurableMachineBindingSnapshot({directory:bindingDirectory});
    const historyNow=readDurableOwnerMachineBindingHistory({directory:auditDirectory});
    if(auditNow.sequence!==initialAudit.sequence||auditNow.hash!==initialAudit.hash||
       trustNow.snapshotDigest!==initialTrust.snapshotDigest||
       snapshotNow.digest!==initialSnapshot.digest||historyNow.pending.length!==1||
       historyNow.pending[0].eventId!==decision.eventId){
      throw fail('Store evidence changed while recovery locks were acquired');
    }
    const afterRevision=outcome==='accepted'?intent.bindingRevisionBefore+1:intent.bindingRevisionBefore;
    appendRecoveredOwnerOutcome({directory:auditDirectory,intent,
      outcome:{...intent,at:new Date().toISOString(),phase:'outcome',outcome,
        bindingRevisionAfter:afterRevision},operatorConfirmedNoActiveWriters:true});
    const auditAfter=inspectDurableOwnerAudit({directory:auditDirectory});
    if(auditAfter.pending.length)throw fail('Binding outcome remains unresolved after recovery');
    if(initialSnapshot.lockPresent){
      if(!removeDeadDurableProcessLock({directory:bindingDirectory,
        name:'.machine-bindings-writer.lock',expectedDigest:initialSnapshot.lockDigest})){
        throw fail('Dead binding writer lock changed before release');
      }
    }
    if(initialAudit.lockPresent){
      releaseOwnerAuditLockForReconciliation({directory:auditDirectory,
        expectedSequence:auditAfter.sequence,expectedHash:auditAfter.hash,
        operatorConfirmedNoActiveWriters:true});
    }
    const final=inspectDurableMachineBindingSnapshot({directory:bindingDirectory});
    const finalHistory=readDurableOwnerMachineBindingHistory({directory:auditDirectory});
    if(finalHistory.pending.length||final.revision!==afterRevision){
      throw fail('Post-recovery binding evidence failed verification');
    }
    releaseLocks(held);
    return Object.freeze({state:outcome==='accepted'?'RECONCILED_ACCEPTED':'RECONCILED_NOT_APPLIED',
      eventId:intent.eventId,bindingRevision:final.revision});
  }catch(error){
    // Preserve recovery locks after a write may have reached disk; an operator
    // must inspect the exact WAL and snapshot before another recovery attempt.
    if(!held.length)throw error;
    const latest=inspectDurableOwnerAudit({directory:auditDirectory});
    const changed=latest.sequence!==initialAudit.sequence||latest.hash!==initialAudit.hash;
    if(!changed)releaseLocks(held);
    throw error;
  }
}
