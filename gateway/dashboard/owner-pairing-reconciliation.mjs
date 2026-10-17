import { inspectDurableProcessLock, createDurableProcessLock,
  removeDeadDurableProcessLock, removeOwnedDurableProcessLock } from '../common/durable-process-lock.mjs';
import {
  appendRecoveredOwnerOutcome, inspectDurableOwnerAudit,
  releaseOwnerAuditLockForReconciliation,
} from './durable-owner-audit.mjs';
import {
  inspectDurableDeviceTrust, releaseTrustWriterLockForReconciliation,
} from '../devices/durable-trust.mjs';

const RECOVERY_LOCK='.owner-pairing-reconciliation.lock';

function recoveryLockEvidence(directory){return inspectDurableProcessLock(directory,RECOVERY_LOCK);}
function exactReceipt(event,transition){
  return transition?.operation==='approve'&&transition.eventId===event.eventId&&
    transition.requestId===event.requestId&&transition.fingerprint===event.fingerprint&&
    transition.deviceId&&transition.previousRevision===event.trustRevisionBefore&&
    transition.revision===event.trustRevisionBefore+1;
}
function matchesOutcome(event,receipt){
  if(event.phase!=='outcome'||event.version!==2)return true;
  if(event.operation==='approve'&&event.outcome==='accepted'){
    return exactReceipt(event,receipt)&&receipt.deviceId===event.deviceId&&
      receipt.revision===event.trustRevisionAfter;
  }
  return !receipt;
}
function diagnosePairing(audit,trust){
  if(trust.temporaryFiles?.length&&!trust.lockPresent){
    return {state:'ORPHAN_TRUST_TEMP',temporaryFileCount:trust.temporaryFiles.length};
  }
  const transitions=trust.transitions;
  const receipts=transitions.filter(item=>item.operation==='approve');
  const events=audit.events.filter(event=>event.event==='g7_owner_pairing');
  const intents=new Map(events.filter(event=>event.version===2&&event.phase==='intent')
    .map(event=>[event.eventId,event]));
  const outcomes=new Map(events.filter(event=>event.version===2&&event.phase==='outcome')
    .map(event=>[event.eventId,event]));
  for(const receipt of receipts){
    if(!intents.has(receipt.eventId))return {state:'TRUST_RECEIPT_WITHOUT_AUDIT',
      eventId:receipt.eventId};
  }
  for(const outcome of outcomes.values()){
    const intent=intents.get(outcome.eventId);
    const receipt=receipts.find(item=>item.eventId===outcome.eventId);
    if(!intent||!matchesOutcome(outcome,receipt))return {state:'OUTCOME_CONTRADICTS_TRUST',
      eventId:outcome.eventId};
    if(intent.ownerId!==outcome.ownerId||intent.requestId!==outcome.requestId||
       intent.fingerprint!==outcome.fingerprint||
       intent.operation!==outcome.operation||
       intent.trustRevisionBefore!==outcome.trustRevisionBefore){
      return {state:'OUTCOME_CONTRADICTS_TRUST',eventId:outcome.eventId};
    }
    if(intent.trustRevisionBefore<trust.historyStartRevision){
      return {state:'TRUST_HISTORY_INCOMPLETE',eventId:outcome.eventId};
    }
  }
  const pending=audit.pending.filter(event=>event.event==='g7_owner_pairing');
  if(pending.length>1)return {state:'CORRUPT',reason:'multiple unresolved intents'};
  if(pending.length===1){
    const intent=pending[0];
    if(intent.version!==2)return {state:'AMBIGUOUS_LEGACY_INTENT',eventId:intent.eventId};
    if(intent.trustRevisionBefore<trust.historyStartRevision){
      return {state:'TRUST_HISTORY_INCOMPLETE',eventId:intent.eventId};
    }
    const byEvent=receipts.find(item=>item.eventId===intent.eventId);
    const byRequest=receipts.find(item=>item.requestId===intent.requestId);
    if(byRequest&&byRequest.eventId!==intent.eventId){
      return {state:'OUTCOME_CONTRADICTS_TRUST',eventId:intent.eventId};
    }
    if(byEvent){
      if(intent.operation!=='approve'||!exactReceipt(intent,byEvent)){
        return {state:'OUTCOME_CONTRADICTS_TRUST',eventId:intent.eventId};
      }
      return {state:'COMMITTED_OUTCOME_MISSING',eventId:intent.eventId,
        requestId:intent.requestId,fingerprint:intent.fingerprint,
        deviceId:byEvent.deviceId,trustRevisionBefore:intent.trustRevisionBefore,
        trustRevisionAfter:byEvent.revision};
    }
    if(trust.revision===intent.trustRevisionBefore){
      if(intent.operation==='reject')return {state:'EPHEMERAL_RESULT_UNKNOWN',
        eventId:intent.eventId,operation:intent.operation,
        reason:'Pairing rejection has no durable mutation receipt'};
      return {state:'INTENT_NOT_APPLIED',eventId:intent.eventId,
        requestId:intent.requestId,fingerprint:intent.fingerprint,
        trustRevisionBefore:intent.trustRevisionBefore};
    }
    return {state:'REVISION_DIVERGED',eventId:intent.eventId,
      expectedRevision:intent.trustRevisionBefore,observedRevision:trust.revision};
  }
  const legacyEventCount=events.filter(event=>event.version===1).length;
  if(legacyEventCount)return {state:'LEGACY_UNBOUND',legacyEventCount};
  if(events.length===0)return {state:'NO_INTENT'};
  return {state:'CONSISTENT'};
}
function diagnose(audit,trust){
  const pairing=diagnosePairing(audit,trust);
  const machineIntent=audit.pending.find(event=>event.event==='g7_owner_machine_binding');
  if(!machineIntent||!['NO_INTENT','CONSISTENT','LEGACY_UNBOUND'].includes(pairing.state))return pairing;
  return {state:'MACHINE_BINDING_OUTCOME_UNKNOWN',i2State:pairing.state,
    eventId:machineIntent.eventId,clientId:machineIntent.clientId,
    deviceId:machineIntent.deviceId,bindingRevisionBefore:machineIntent.bindingRevisionBefore};
}
function loadEvidence({auditDirectory,trustDirectory}={}){
  try{
    const audit=inspectDurableOwnerAudit({directory:auditDirectory});
    const trust=inspectDurableDeviceTrust({directory:trustDirectory});
    return {audit,trust,diagnosis:diagnose(audit,trust)};
  }catch(error){
    return {error,state:'CORRUPT',reason:String(error?.message??error).slice(0,240)};
  }
}
function withLocks(state,auditDirectory,trustDirectory){
  let recoveryLocks;
  try{recoveryLocks=[...new Set([auditDirectory,trustDirectory])]
    .map(directory=>recoveryLockEvidence(directory)).filter(lock=>lock.present);}
  catch(error){return {state:'CORRUPT',reason:String(error?.message??error).slice(0,240)};}
  const liveRecovery=recoveryLocks.find(lock=>lock.status==='active');
  if(liveRecovery)return {state:'RECOVERY_LOCK_ACTIVE',underlyingState:state.state,
    reason:'A reconciliation process is still active'};
  if(recoveryLocks.some(lock=>lock.status==='unknown'))return {
    state:'RECOVERY_LOCK_UNVERIFIED',underlyingState:state.state,
    reason:'Reconciliation lock owner identity is unavailable'};
  if(recoveryLocks.length)return {state:'RECOVERY_LOCK_PRESENT',underlyingState:state.state,
    eventId:state.eventId,reason:'An earlier reconciliation lock remains; operator review required'};
  const auditLock=state.audit?.lockPresent??false;
  const trustPermits=state.trust?.dispatchPermits??[];
  const trustLock=Boolean(state.trust?.lockPresent||state.trust?.operationGatePresent||
    trustPermits.length);
  const activeAudit=state.audit?.lockStatus==='active';
  const activeTrust=state.trust?.lockStatus==='active'||
    state.trust?.operationGateStatus==='active'||trustPermits.some(lock=>lock.status==='active');
  if(activeAudit||activeTrust)return {state:'ACTIVE_WRITER',underlyingState:state.state,
    consistencyState:state.i2State??state.state,
    auditWriterActive:activeAudit,trustWriterActive:activeTrust,eventId:state.eventId};
  const unknownAudit=auditLock&&state.audit?.lockStatus!=='dead';
  const trustLockStatuses=[
    ...(state.trust?.lockPresent?[state.trust.lockStatus]:[]),
    ...(state.trust?.operationGatePresent?[state.trust.operationGateStatus]:[]),
    ...trustPermits.map(lock=>lock.status),
  ];
  const unknownTrust=trustLock&&trustLockStatuses.some(status=>status!=='dead');
  if(unknownAudit||unknownTrust)return {state:'WRITER_LOCK_UNVERIFIED',
    underlyingState:state.state,auditWriterUnverified:unknownAudit,
    trustWriterUnverified:unknownTrust,eventId:state.eventId};
  if((auditLock||trustLock)&&['NO_INTENT','CONSISTENT','LEGACY_UNBOUND'].includes(state.state)){
    return {state:`${state.state}_LOCK_HELD`,
      auditLockPresent:auditLock,trustLockPresent:trustLock,
      auditLockStatus:state.audit?.lockStatus,trustLockStatus:state.trust?.lockStatus,
      trustOperationGateStatus:state.trust?.operationGateStatus,
      trustDispatchPermitStatuses:trustPermits.map(lock=>lock.status)};
  }
  return {...state,auditLockPresent:auditLock,trustLockPresent:trustLock,
    auditLockStatus:state.audit?.lockStatus,trustLockStatus:state.trust?.lockStatus,
    trustOperationGateStatus:state.trust?.operationGateStatus,
    trustDispatchPermitStatuses:trustPermits.map(lock=>lock.status)};
}
function analyzeInternal({auditDirectory,trustDirectory}={},ignoreRecoveryLock=false){
  const evidence=loadEvidence({auditDirectory,trustDirectory});
  if(evidence.error)return {state:'CORRUPT',reason:evidence.reason};
  if(ignoreRecoveryLock)return {...evidence.diagnosis,audit:evidence.audit,trust:evidence.trust};
  return withLocks({...evidence.diagnosis,audit:evidence.audit,trust:evidence.trust},
    auditDirectory,trustDirectory);
}
export function analyzeOwnerPairingRecovery({auditDirectory,trustDirectory}={}){
  const result=analyzeInternal({auditDirectory,trustDirectory});
  if(result.state==='NO_INTENT'&&!result.auditLockPresent&&!result.trustLockPresent){
    return Object.freeze({state:'NO_INTENT'});
  }
  const {audit,trust,...publicResult}=result;
  return Object.freeze(publicResult);
}

function acquireRecoveryLocks(directories){
  const created=[];
  try{
    for(const directory of [...new Set(directories)].sort()){
      const owner=createDurableProcessLock(directory,RECOVERY_LOCK,'reconciliation');
      created.push({directory,owner});
    }
    return created;
  }catch(error){
    for(const lock of created.reverse()){
      try{removeOwnedDurableProcessLock({directory:lock.directory,name:RECOVERY_LOCK,
        owner:lock.owner});}catch{}
    }
    if(error?.code==='EEXIST')throw Error('Reconciliation lock already exists; explicit stale-lock review required');
    throw error;
  }
}
function releaseRecoveryLocks(locks,auditDirectory){
  const releaseOrder=[...locks].sort((a,b)=>
    Number(a.directory===auditDirectory)-Number(b.directory===auditDirectory));
  for(const lock of releaseOrder){
    removeOwnedDurableProcessLock({directory:lock.directory,name:RECOVERY_LOCK,
      owner:lock.owner});
  }
}
function assertWriterLocksAreDead(evidence){
  for(const [name,lock] of [['audit',evidence.audit],['trust',evidence.trust]]){
    if(lock?.lockPresent&&lock.lockStatus!=='dead'){
      throw Error(`Pairing reconciliation blocked: ${name} writer is active or unverified`);
    }
  }
  if(evidence.trust.operationGatePresent&&evidence.trust.operationGateStatus!=='dead'){
    throw Error('Pairing reconciliation blocked: trust operation gate is active or unverified');
  }
  if(evidence.trust.dispatchPermits.some(lock=>lock.status!=='dead')){
    throw Error('Pairing reconciliation blocked: trust dispatch permit is active or unverified');
  }
}
function releaseWriterLocks(evidence,options){
  if(evidence.trust.lockPresent||evidence.trust.operationGatePresent||
     evidence.trust.dispatchPermits.length){
    releaseTrustWriterLockForReconciliation({directory:options.trustDirectory,
      expectedRevision:evidence.trust.revision,
      expectedSnapshotDigest:evidence.trust.snapshotDigest,
      operatorConfirmedNoActiveWriters:true});
  }
  if(evidence.audit.lockPresent){
    releaseOwnerAuditLockForReconciliation({directory:options.auditDirectory,
      expectedSequence:evidence.audit.sequence,expectedHash:evidence.audit.hash,
      operatorConfirmedNoActiveWriters:true});
  }
}

export function reconcileOwnerPairingRecovery({auditDirectory,trustDirectory,
  operatorConfirmedNoActiveWriters}={}){
  if(operatorConfirmedNoActiveWriters!==true){
    throw Error('Operator confirmation that no writers are active is required');
  }
  const options={auditDirectory,trustDirectory};
  const initial=analyzeInternal(options);
  if(['CORRUPT','REVISION_DIVERGED','OUTCOME_CONTRADICTS_TRUST',
      'TRUST_RECEIPT_WITHOUT_AUDIT','TRUST_HISTORY_INCOMPLETE',
      'AMBIGUOUS_LEGACY_INTENT','EPHEMERAL_RESULT_UNKNOWN','ORPHAN_TRUST_TEMP',
      'MACHINE_BINDING_OUTCOME_UNKNOWN',
      'RECOVERY_LOCK_PRESENT','RECOVERY_LOCK_ACTIVE','RECOVERY_LOCK_UNVERIFIED',
      'ACTIVE_WRITER','WRITER_LOCK_UNVERIFIED'].includes(initial.state)){
    throw Error(`Pairing reconciliation blocked: ${initial.state}`);
  }
  if(['NO_INTENT','CONSISTENT','LEGACY_UNBOUND'].includes(initial.state)&&
     !initial.auditLockPresent&&!initial.trustLockPresent)return Object.freeze(initial);
  const locks=acquireRecoveryLocks([trustDirectory,auditDirectory]);
  let changed=false;
  try{
    let evidence=analyzeInternal(options,true);
    if(['CORRUPT','REVISION_DIVERGED','OUTCOME_CONTRADICTS_TRUST',
        'TRUST_RECEIPT_WITHOUT_AUDIT','TRUST_HISTORY_INCOMPLETE',
        'AMBIGUOUS_LEGACY_INTENT','EPHEMERAL_RESULT_UNKNOWN','ORPHAN_TRUST_TEMP',
        'MACHINE_BINDING_OUTCOME_UNKNOWN'].includes(evidence.state)){
      throw Error(`Pairing reconciliation blocked: ${evidence.state}`);
    }
    assertWriterLocksAreDead(evidence);
    let repairedState='RECONCILED_CONSISTENT';
    if(evidence.state==='COMMITTED_OUTCOME_MISSING'||evidence.state==='INTENT_NOT_APPLIED'){
      const intent=evidence.audit.pending[0];
      const committed=evidence.state==='COMMITTED_OUTCOME_MISSING';
      const outcome={event:'g7_owner_pairing',version:2,
        at:new Date().toISOString(),eventId:intent.eventId,operation:intent.operation,
        ownerId:intent.ownerId,requestId:intent.requestId,fingerprint:intent.fingerprint,
        trustRevisionBefore:intent.trustRevisionBefore,phase:'outcome',
        outcome:committed?'accepted':'not_applied',
        deviceId:committed?evidence.deviceId:null,
        trustRevisionAfter:committed?evidence.trustRevisionAfter:evidence.trust.revision};
      if(evidence.trust.lockPresent){
        // Lock removal can have an uncertain fsync result; keep the recovery
        // mutex if the durable operation throws at any point.
        changed=true;
        releaseTrustWriterLockForReconciliation({directory:trustDirectory,
          expectedRevision:evidence.trust.revision,
          expectedSnapshotDigest:evidence.trust.snapshotDigest,
          operatorConfirmedNoActiveWriters:true});
      }
      // The append may reach disk before fsync reports an error. Treat the
      // WAL as mutated from the start of the attempt and preserve both locks.
      changed=true;
      appendRecoveredOwnerOutcome({directory:auditDirectory,intent,outcome,
        operatorConfirmedNoActiveWriters:true});
      repairedState=committed?'RECONCILED_ACCEPTED':'RECONCILED_NOT_APPLIED';
      evidence=analyzeInternal(options,true);
      if(!['CONSISTENT','LEGACY_UNBOUND'].includes(evidence.state)){
        throw Error(`Pairing reconciliation post-check failed: ${evidence.state}`);
      }
    }else if(!['NO_INTENT','CONSISTENT','LEGACY_UNBOUND'].includes(evidence.state)){
      throw Error(`Pairing reconciliation blocked: ${evidence.state}`);
    }
    changed=true;
    releaseWriterLocks(evidence,options);
    const final=analyzeInternal(options,true);
    if(!['NO_INTENT','CONSISTENT','LEGACY_UNBOUND'].includes(final.state))
      throw Error(`Pairing reconciliation final check failed: ${final.state}`);
    assertWriterLocksAreDead(final);
    releaseRecoveryLocks(locks,auditDirectory);
    const resultState=repairedState==='RECONCILED_CONSISTENT'&&final.state==='LEGACY_UNBOUND'
      ?'RECONCILED_LEGACY_UNBOUND'
      :repairedState==='RECONCILED_CONSISTENT'&&final.state==='NO_INTENT'
        ?'RECONCILED_NO_INTENT':repairedState;
    return Object.freeze({state:resultState,
      ...(initial.eventId?{eventId:initial.eventId}:{})});
  }catch(error){
    if(!changed){
      try{releaseRecoveryLocks(locks,auditDirectory);}catch{}
    }
    throw error;
  }
}

// Explicitly clear only abandoned reconciliation mutexes after an operator
// independently confirms no recovery process remains active.
export function clearStaleOwnerPairingRecoveryLocks({auditDirectory,trustDirectory,
  operatorConfirmedNoActiveRecovery}={}){
  if(operatorConfirmedNoActiveRecovery!==true){
    throw Error('Operator confirmation that no reconciliation process is active is required');
  }
  const directories=[...new Set([auditDirectory,trustDirectory])];
  const locks=directories.map(directory=>recoveryLockEvidence(directory))
    .filter(lock=>lock.present);
  if(locks.some(lock=>lock.status!=='dead')){
    throw Error('Cannot clear a reconciliation lock with an active or unverified owner');
  }
  const releaseOrder=locks.sort((a,b)=>
    Number(a.directory===auditDirectory)-Number(b.directory===auditDirectory));
  let cleared=0;
  for(const lock of releaseOrder){
    if(removeDeadDurableProcessLock({directory:lock.directory,name:RECOVERY_LOCK,
      expectedDigest:lock.digest}))cleared++;
  }
  return Object.freeze({cleared});
}
