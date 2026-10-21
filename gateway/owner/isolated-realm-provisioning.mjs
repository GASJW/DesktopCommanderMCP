import path from 'node:path';
import { inspectDurableDeviceTrust } from '../devices/durable-trust.mjs';
import { releaseTrustWriterLockForReconciliation } from '../devices/durable-trust.mjs';
import { appendRecoveredOwnerOutcome, createDurableOwnerAudit,
  inspectDurableOwnerAudit, releaseOwnerAuditLockForReconciliation,
  readDurableOwnerMachineBindingDecision, readDurableOwnerMachineBindingHistory }
  from '../dashboard/durable-owner-audit.mjs';
import { inspectDurableMachineBindingSnapshot }
  from '../devices/durable-machine-bindings.mjs';
import { clearStaleDurableToolGrantLocks }
  from '../devices/durable-tool-grants.mjs';
import { reconcileOwnerPairingRecovery } from '../dashboard/owner-pairing-reconciliation.mjs';
import { reconcileOwnerMachineBinding } from '../dashboard/owner-machine-binding-reconciliation.mjs';
import { createDurableProcessLock, inspectDurableProcessLock,
  removeOwnedDurableProcessLock } from '../common/durable-process-lock.mjs';
import { ownerAuthorityTargetDigest } from './durable-owner-authority.mjs';
import { validateIsolatedG7RealmConfig } from './isolated-realm.mjs';
import { isWindowsToolGrantPath, toolGrantPathApi } from '../devices/tool-grant-capability.mjs';

const APPROVAL_EVENT='g7_realm_owner_approval';
const operations=new Set(['device.approve','device.revoke','binding.create','grant.issue','grant.revoke']);
const fail=(code,message)=>Object.assign(new Error(message),{code});

export function createIsolatedRealmProvisioning({realmId,realmConfig,ownerAuthority,
  provisioningDirectory,auditDirectory,bindingDirectory,trustDirectory,trustStore,pairingCoordinator,
  auditWriter,machineBindingStore,bindingService,grantStore,readApprovalById,
  testHooks}={}){
  if(ownerAuthority?.realmId!==realmId||typeof ownerAuthority?.verifyAdministrativeApproval!=='function'||
     typeof ownerAuthority?.verifyStoredAdministrativeApproval!=='function'||
     typeof ownerAuthority?.inspect!=='function'||typeof trustStore?.revision!=='function'||
     typeof trustStore?.revokeDevice!=='function'||!trustStore.registry||
     typeof pairingCoordinator?.inspectPairing!=='function'||
     typeof pairingCoordinator?.approvePairing!=='function'||
     typeof auditWriter?.auditWrite!=='function'||typeof auditWriter?.inspect!=='function'||
     typeof machineBindingStore?.list!=='function'||typeof machineBindingStore?.revision!=='function'||
     typeof bindingService?.bind!=='function'||typeof grantStore?.list!=='function'||
     typeof grantStore?.inspect!=='function'||typeof grantStore?.directory!=='string'||
     typeof grantStore?.revision!=='function'||typeof grantStore?.grant!=='function'||
     typeof grantStore?.revoke!=='function'||typeof readApprovalById!=='function'||
     typeof provisioningDirectory!=='string'||typeof auditDirectory!=='string'||
     typeof bindingDirectory!=='string'||typeof trustDirectory!=='string'||
     typeof realmConfig!=='object'||
     testHooks!==undefined&&(!process.env.NODE_TEST_CONTEXT||
       typeof testHooks?.afterPhase!=='function')){
    throw new TypeError('Isolated realm provisioning requires its verified authority and durable stores');
  }
  const prepared=validateIsolatedG7RealmConfig(realmConfig,{requireExisting:true});
  const paths=prepared.paths;
  if(prepared.realmId!==realmId||ownerAuthority.directory!==paths.ownerAuthorityDirectory||
     provisioningDirectory!==paths.provisioningDirectory||auditDirectory!==paths.auditDirectory||
     bindingDirectory!==paths.bindingDirectory||trustDirectory!==paths.trustDirectory||
     trustStore.directory!==paths.trustDirectory||pairingCoordinator.registry!==trustStore||
     pairingCoordinator.preallocateDeviceId!==true||auditWriter.directory!==paths.auditDirectory||
     machineBindingStore.directory!==paths.bindingDirectory||
     bindingService.machineBindingStore!==machineBindingStore||
     bindingService.auditWrite!==auditWriter.auditWrite||grantStore.directory!==paths.grantDirectory||
     path.resolve(readApprovalById.auditDirectory??'')!==paths.auditDirectory||
     path.resolve(readApprovalById.trustDirectory??'')!==paths.trustDirectory){
    throw new TypeError('Provisioning dependencies must use distinct stores from the validated isolated realm');
  }
  let poisoned=false;
  function phase(name){if(testHooks)testHooks.afterPhase(name);}
  function inspectApprovalEvents(){
    const evidence=inspectDurableOwnerAudit({directory:provisioningDirectory});
    if(evidence.events.some(event=>event.event!==APPROVAL_EVENT)||
       evidence.pending.some(event=>event.event!==APPROVAL_EVENT)){
      throw fail('PROVISIONING_AUDIT_CORRUPT','Unexpected isolated realm provisioning audit event');
    }
    for(const event of evidence.events){
      if(!ownerAuthority.verifyStoredAdministrativeApproval(event.approval,{
        operation:event.operation,eventId:event.eventId,expectedRevision:event.expectedRevision,
        ownerDigest:event.ownerDigest,targetDigest:event.targetDigest,
        verifiedAt:event.verifiedAt} )){
        throw fail('PROVISIONING_APPROVAL_INVALID','Stored administrative approval is invalid or Owner is revoked');
      }
    }
    return evidence;
  }
  function runApprovedMutation({accessToken,approval,operation,expectedRevision,target},mutate){
    if(poisoned)throw fail('PROVISIONING_UNAVAILABLE','Provisioning requires reconciliation');
    if(!operations.has(operation)||!Number.isSafeInteger(expectedRevision)||expectedRevision<0||
       typeof mutate!=='function'){
      throw fail('PROVISIONING_INVALID','Unsupported operation or expected revision');
    }
    const verified=ownerAuthority.verifyAdministrativeApproval({accessToken,approval,
      operation,expectedRevision,target});
    const owner=verified.principal;
    const evidence=inspectApprovalEvents();
    if(evidence.pending.length)throw fail('PROVISIONING_RECOVERY_REQUIRED','An approval audit intent is unresolved');
    if(evidence.events.some(event=>event.eventId===approval.eventId)){
      throw fail('DUPLICATE_EVENT','Administrative approval event was already consumed');
    }
    const targetDigest=ownerAuthorityTargetDigest(operation,target);
    const signedApproval=Object.freeze({...approval});
    const base={event:APPROVAL_EVENT,version:1,at:new Date().toISOString(),
      eventId:approval.eventId,realmId,operation,ownerId:owner.ownerId,
      ownerDigest:owner.ownerDigest,verifiedAt:verified.verifiedAt,
      deviceId:target.deviceId,fingerprint:target.fingerprint,
      expectedRevision,targetDigest,
      approval:signedApproval};
    const audit=createDurableOwnerAudit({directory:provisioningDirectory});
    const complete=result=>{
      audit.auditWrite({...base,at:new Date().toISOString(),phase:'outcome',outcome:'applied'});
      phase('approval-outcome');
      return result;
    };
    try{
      audit.auditWrite({...base,phase:'intent'});
      phase('approval-intent');
      const result=mutate(owner);
      if(result&&typeof result.then==='function'){
        return Promise.resolve(result).then(complete).catch(error=>{
          poisoned=true;throw error;
        }).finally(()=>{
          try{audit.close();}catch(error){poisoned=true;throw error;}
        });
      }
      const completed=complete(result);
      audit.close();
      return completed;
    }catch(error){
      poisoned=true;
      try{audit.close();}catch(closeError){throw closeError;}
      throw error;
    }
  }
  function verifyStoredEntry({eventId,operation,ownerDigest,expectedRevision,target,
    allowPending=false}){
    const evidence=inspectApprovalEvents();
    const intents=evidence.events.filter(event=>event.eventId===eventId&&event.phase==='intent');
    const outcomes=evidence.events.filter(event=>event.eventId===eventId&&event.phase==='outcome');
    if(intents.length!==1||outcomes.length>1||
       outcomes.length===1&&outcomes[0].outcome!=='applied'||
       !allowPending&&outcomes.length!==1)return false;
    const intent=intents[0];
    return intent.operation===operation&&intent.realmId===realmId&&
      intent.ownerDigest===ownerDigest&&intent.expectedRevision===expectedRevision&&
      intent.deviceId===target.deviceId&&intent.fingerprint===target.fingerprint&&
      intent.targetDigest===ownerAuthorityTargetDigest(operation,target)&&
      ownerAuthority.verifyStoredAdministrativeApproval(intent.approval,{operation,eventId,
        expectedRevision,ownerDigest,targetDigest:intent.targetDigest,
        verifiedAt:intent.verifiedAt});
  }
  function writePairingEvent(event){
    if(auditWriter.auditWrite(event)!==true)throw fail('PAIRING_AUDIT_UNAVAILABLE','Pairing audit was not committed');
  }

  function startPairing(metadata){return pairingCoordinator.startPairing(metadata);}
  function provePairing(requestId,proof){return pairingCoordinator.provePossession(requestId,proof);}

  function approveDevice({accessToken,approval,requestId,deviceId,fingerprint}={}){
    if(poisoned)throw fail('PROVISIONING_UNAVAILABLE','Provisioning requires reconciliation');
    const pending=pairingCoordinator.inspectPairing(requestId);
    const trustRevisionBefore=trustStore.revision();
    if(!pending||pending.proofVerified!==true||pending.deviceId!==deviceId||
       pending.fingerprint!==fingerprint||!Number.isSafeInteger(trustRevisionBefore)){
      throw fail('PAIRING_DENIED','Fresh device proof and exact device identity are required');
    }
    const target={realmId,deviceId,requestId,fingerprint,trustRevision:trustRevisionBefore};
    return runApprovedMutation({accessToken,approval,operation:'device.approve',
      expectedRevision:trustRevisionBefore,target},owner=>{
      const intent={event:'g7_owner_pairing',version:2,at:new Date().toISOString(),
        eventId:approval.eventId,operation:'approve',ownerId:owner.ownerId,requestId,
        fingerprint,trustRevisionBefore,phase:'intent'};
      writePairingEvent(intent);phase('device-trust-intent');
      const trusted=pairingCoordinator.approvePairing(requestId,fingerprint,{
        eventId:approval.eventId,trustRevisionBefore});
      phase('device-trust-committed');
      const trustRevisionAfter=trustStore.revision();
      if(trusted.deviceId!==deviceId||trusted.fingerprint!==fingerprint||
         trustRevisionAfter!==trustRevisionBefore+1){
        poisoned=true;throw fail('PAIRING_OUTCOME_UNKNOWN','Device trust outcome failed its revision fence');
      }
      writePairingEvent({...intent,at:new Date().toISOString(),phase:'outcome',
        outcome:'accepted',deviceId,trustRevisionAfter});
      phase('device-trust-outcome');
      return Object.freeze({deviceId,fingerprint,trustRevisionBefore,trustRevisionAfter,
        approvalEventId:approval.eventId});
    });
  }

  function bindDevice({accessToken,approval,clientId,deviceId,fingerprint,
    expectedRevision}={}){
    if(poisoned)throw fail('PROVISIONING_UNAVAILABLE','Provisioning requires reconciliation');
    const owner=ownerAuthority.verifyAdminPrincipal(accessToken);
    const trusted=trustStore.registry.snapshotTrustedDevices().find(device=>device.deviceId===deviceId);
    const prior=machineBindingStore.list().find(binding=>binding.clientId===clientId||binding.deviceId===deviceId);
    if(!owner||!trusted||trusted.fingerprint!==fingerprint||prior||
       machineBindingStore.revision()!==expectedRevision){
      throw fail('BINDING_DENIED','Current Owner, unbound trusted device and expected revision are required');
    }
    const receipt=readApprovalById(owner.ownerId,deviceId);
    if(!receipt||receipt.fingerprint!==fingerprint||receipt.ownerId!==owner.ownerId){
      throw fail('PAIRING_RECEIPT_UNAVAILABLE','Durable Owner device approval receipt is required');
    }
    const target={realmId,ownerDigest:owner.ownerDigest,clientId,deviceId,fingerprint,
      bindingRevision:expectedRevision,pairingEventId:receipt.eventId};
    return runApprovedMutation({accessToken,approval,operation:'binding.create',
      expectedRevision,target},()=>{
      phase('machine-binding-before-write');
      return bindingService.bind({ownerAssertion:accessToken,clientId,deviceId,
        expectedRevision,eventId:approval.eventId}).then(result=>{
        phase('machine-binding-committed');
        return result;
      });
    });
  }

  function issueReadFileGrant({accessToken,approval,deviceId,fingerprint,root,
    constraints,expectedRevision}={}){
    if(poisoned)throw fail('PROVISIONING_UNAVAILABLE','Provisioning requires reconciliation');
    const owner=ownerAuthority.verifyAdminPrincipal(accessToken);
    const binding=machineBindingStore.list().find(value=>value.deviceId===deviceId);
    const device=trustStore.registry.listDevices().find(value=>value.deviceId===deviceId);
    const rootApi=toolGrantPathApi(root);
    const receipt=owner&&readApprovalById(owner.ownerId,deviceId);
    if(typeof root!=='string'||root.length>4096||root.includes('\0')||!rootApi||
       root===rootApi.parse(root).root||!owner||!device||!['linux','win32','darwin'].includes(device.platform)||
       (device.platform==='win32')!==isWindowsToolGrantPath(root)||
       !binding||binding.ownerDigest!==owner.ownerDigest||
       binding.fingerprint!==fingerprint||!receipt||receipt.fingerprint!==fingerprint||
       !Number.isSafeInteger(expectedRevision)||grantStore.revision()!==expectedRevision){
      throw fail('GRANT_DENIED','Current Owner, device platform, binding, pairing receipt and expected policy revision are required');
    }
    const grant={ownerDigest:owner.ownerDigest,deviceId,fingerprint,tool:'read_file',
      scope:{root},constraints};
    const target={realmId,...grant,policyRevision:expectedRevision};
    return runApprovedMutation({accessToken,approval,operation:'grant.issue',
      expectedRevision,target},()=>{
      phase('grant-issue-before-write');
      const created=grantStore.grant(grant,{expectedRevision,eventId:approval.eventId});
      phase('grant-issued');
      return created;
    });
  }

  function revokeReadFileGrant({accessToken,approval,deviceId,grantId,
    expectedRevision}={}){
    if(poisoned)throw fail('PROVISIONING_UNAVAILABLE','Provisioning requires reconciliation');
    const owner=ownerAuthority.verifyAdminPrincipal(accessToken);
    const grant=grantStore.list().find(value=>value.grantId===grantId&&value.active);
    if(!owner||!grant||grant.tool!=='read_file'||grant.deviceId!==deviceId||
       grant.ownerDigest!==owner.ownerDigest||!Number.isSafeInteger(expectedRevision)||
       grantStore.revision()!==expectedRevision){
      throw fail('GRANT_DENIED','Only the active Owner may revoke this realm read_file grant');
    }
    const target={realmId,ownerDigest:owner.ownerDigest,deviceId,
      fingerprint:grant.fingerprint,grantId,policyRevision:expectedRevision};
    return runApprovedMutation({accessToken,approval,operation:'grant.revoke',
      expectedRevision,target},()=>{
      phase('grant-revoke-before-write');
      const result=grantStore.revoke(grantId,{expectedRevision,eventId:approval.eventId});
      phase('grant-revoked');
      return result;
    });
  }

  function revokeDevice({accessToken,approval,deviceId,expectedRevision}={}){
    if(poisoned)throw fail('PROVISIONING_UNAVAILABLE','Provisioning requires reconciliation');
    const owner=ownerAuthority.verifyAdminPrincipal(accessToken);
    const trusted=trustStore.registry.snapshotTrustedDevices().find(device=>device.deviceId===deviceId);
    if(!owner||!trusted||trustStore.revision()!==expectedRevision){
      throw fail('DEVICE_REVOCATION_DENIED','Current Owner, trusted device and expected trust revision are required');
    }
    const target={realmId,ownerDigest:owner.ownerDigest,deviceId,
      fingerprint:trusted.fingerprint,trustRevision:expectedRevision};
    return runApprovedMutation({accessToken,approval,operation:'device.revoke',
      expectedRevision,target},()=>{
      phase('device-revoke-before-write');
      const revoked=trustStore.revokeDevice(deviceId,{expectedRevision,eventId:approval.eventId});
      phase('device-revoked');
      return Object.freeze({revoked,deviceId,trustRevision:trustStore.revision()});
    });
  }

  function requireApprovedIntent(intent){
    if(intent.event!==APPROVAL_EVENT||intent.phase!=='intent'||intent.realmId!==realmId||
       !operations.has(intent.operation)||
       !ownerAuthority.verifyStoredAdministrativeApproval(intent.approval,{
         operation:intent.operation,eventId:intent.eventId,
         expectedRevision:intent.expectedRevision,ownerDigest:intent.ownerDigest,
         targetDigest:intent.targetDigest,verifiedAt:intent.verifiedAt})){
      throw fail('PROVISIONING_RECOVERY_BLOCKED','Pending signed Owner approval is invalid or revoked');
    }
  }
  function recoverTrustLocks(evidence){
    if(evidence.temporaryFiles.length||evidence.dispatchPermits.length){
      throw fail('PROVISIONING_RECOVERY_BLOCKED','Trust temporary or dispatch evidence requires separate review');
    }
    if(evidence.lockPresent&&evidence.lockStatus!=='dead'||
       evidence.operationGatePresent&&evidence.operationGateStatus!=='dead'){
      throw fail('PROVISIONING_BUSY','Trust writer is active or cannot be verified');
    }
    if(!evidence.lockPresent&&!evidence.operationGatePresent)return;
    const name='.owner-pairing-reconciliation.lock';
    if(inspectDurableProcessLock(trustDirectory,name).present){
      throw fail('PROVISIONING_BUSY','A trust reconciliation lock already exists');
    }
    const lock=createDurableProcessLock(trustDirectory,name,'reconciliation');
    try{
      releaseTrustWriterLockForReconciliation({directory:trustDirectory,
        expectedRevision:evidence.revision,expectedSnapshotDigest:evidence.snapshotDigest,
        operatorConfirmedNoActiveWriters:true});
    }finally{removeOwnedDurableProcessLock({directory:trustDirectory,name,owner:lock});}
  }
  function reconcilePairingIntent(intent){
    let audit=inspectDurableOwnerAudit({directory:auditDirectory});
    const domainIntent=audit.events.find(event=>event.event==='g7_owner_pairing'&&
      event.eventId===intent.eventId&&event.phase==='intent');
    let trust=inspectDurableDeviceTrust({directory:trustDirectory});
    const transition=trust.transitions.find(value=>value.eventId===intent.eventId);
    if(!domainIntent){
      if(transition||trust.revision!==intent.expectedRevision){
        throw fail('PROVISIONING_RECOVERY_BLOCKED','Trust changed without its exact pairing intent');
      }
      if(trust.lockPresent||trust.operationGatePresent||audit.lockPresent){
        reconcileOwnerPairingRecovery({auditDirectory,trustDirectory,
          operatorConfirmedNoActiveWriters:true});
        trust=inspectDurableDeviceTrust({directory:trustDirectory});
      }
      if(trust.lockPresent||trust.operationGatePresent||trust.temporaryFiles.length||
         trust.dispatchPermits.length)throw fail('PROVISIONING_RECOVERY_BLOCKED',
        'Unrelated trust recovery evidence remains');
      return 'not_applied';
    }
    const target={realmId,deviceId:intent.deviceId,requestId:domainIntent.requestId,
      fingerprint:intent.fingerprint,trustRevision:intent.expectedRevision};
    if(domainIntent.version!==2||domainIntent.operation!=='approve'||
       domainIntent.fingerprint!==intent.fingerprint||domainIntent.ownerId!==intent.ownerId||
       domainIntent.trustRevisionBefore!==intent.expectedRevision||
       ownerAuthorityTargetDigest(intent.operation,target)!==intent.targetDigest){
      throw fail('PROVISIONING_RECOVERY_BLOCKED','Pairing intent differs from the signed approval');
    }
    if(audit.pending.some(event=>event.event==='g7_owner_pairing'&&event.eventId===intent.eventId)||
       audit.lockPresent||trust.lockPresent||trust.operationGatePresent){
      reconcileOwnerPairingRecovery({auditDirectory,trustDirectory,
        operatorConfirmedNoActiveWriters:true});
      audit=inspectDurableOwnerAudit({directory:auditDirectory});
    }
    const outcome=audit.events.find(event=>event.event==='g7_owner_pairing'&&
      event.eventId===intent.eventId&&event.phase==='outcome');
    const after=inspectDurableDeviceTrust({directory:trustDirectory});
    if(outcome?.outcome==='accepted'&&outcome.deviceId===intent.deviceId&&
       outcome.fingerprint===intent.fingerprint&&outcome.trustRevisionBefore===intent.expectedRevision&&
       outcome.trustRevisionAfter===intent.expectedRevision+1&&after.revision===intent.expectedRevision+1&&
       after.transitions.some(value=>value.operation==='approve'&&value.eventId===intent.eventId&&
         value.deviceId===intent.deviceId&&value.fingerprint===intent.fingerprint))return 'applied';
    if(outcome?.outcome==='not_applied'&&after.revision===intent.expectedRevision)return 'not_applied';
    throw fail('PROVISIONING_RECOVERY_BLOCKED','Pairing store outcome is ambiguous');
  }
  function reconcileBindingIntent(intent){
    let history=readDurableOwnerMachineBindingHistory({directory:auditDirectory});
    let decision=history.completed.find(item=>item.eventId===intent.eventId);
    let pending=history.pending.find(item=>item.eventId===intent.eventId);
    const snapshot=inspectDurableMachineBindingSnapshot({directory:bindingDirectory});
    if(pending){
      const value=pending.intent;
      const target={realmId,ownerDigest:intent.ownerDigest,clientId:value.clientId,
        deviceId:intent.deviceId,fingerprint:intent.fingerprint,
        bindingRevision:intent.expectedRevision,pairingEventId:value.approvalEventId};
      if(value.ownerDigest!==intent.ownerDigest||value.deviceId!==intent.deviceId||
         value.fingerprint!==intent.fingerprint||value.bindingRevisionBefore!==intent.expectedRevision||
         ownerAuthorityTargetDigest(intent.operation,target)!==intent.targetDigest){
        throw fail('PROVISIONING_RECOVERY_BLOCKED','Binding intent differs from signed approval');
      }
      reconcileOwnerMachineBinding({auditDirectory,bindingDirectory,trustDirectory,
        readApprovalReceipt:readApprovalById,operatorConfirmedNoActiveWriters:true});
      history=readDurableOwnerMachineBindingHistory({directory:auditDirectory});
      decision=history.completed.find(item=>item.eventId===intent.eventId);
    }
    if(!decision){
      if(snapshot.revision===intent.expectedRevision&&
         !snapshot.bindings.some(value=>value.deviceId===intent.deviceId))return 'not_applied';
      throw fail('PROVISIONING_RECOVERY_BLOCKED','Binding decision is absent but its store revision changed');
    }
    const value=decision.intent;
    const target={realmId,ownerDigest:intent.ownerDigest,clientId:value.clientId,
      deviceId:value.deviceId,fingerprint:value.fingerprint,
      bindingRevision:value.bindingRevisionBefore,pairingEventId:value.approvalEventId};
    if(value.deviceId!==intent.deviceId||value.ownerDigest!==intent.ownerDigest||
       value.fingerprint!==intent.fingerprint||value.bindingRevisionBefore!==intent.expectedRevision||
       ownerAuthorityTargetDigest(intent.operation,target)!==intent.targetDigest){
      throw fail('PROVISIONING_RECOVERY_BLOCKED','Completed binding differs from signed approval');
    }
    if(decision.outcome.outcome==='accepted'&&snapshot.revision===intent.expectedRevision+1&&
       snapshot.bindings.some(record=>record.bindingEventId===intent.eventId&&
         record.ownerDigest===intent.ownerDigest&&record.deviceId===intent.deviceId&&
         record.fingerprint===intent.fingerprint))return 'applied';
    if(decision.outcome.outcome==='not_applied'&&snapshot.revision===intent.expectedRevision)return 'not_applied';
    throw fail('PROVISIONING_RECOVERY_BLOCKED','Binding snapshot and audit outcome disagree');
  }
  function reconcileDeviceRevocation(intent){
    let trust=inspectDurableDeviceTrust({directory:trustDirectory});
    const transition=trust.transitions.find(value=>value.eventId===intent.eventId);
    if(!transition){
      if(trust.revision===intent.expectedRevision&&trust.devices.some(device=>
        device.deviceId===intent.deviceId&&device.fingerprint===intent.fingerprint)){
        recoverTrustLocks(trust);
        return 'not_applied';
      }
      throw fail('PROVISIONING_RECOVERY_BLOCKED','Device revocation has no exact trust transition');
    }
    const target={realmId,ownerDigest:intent.ownerDigest,deviceId:intent.deviceId,
      fingerprint:intent.fingerprint,trustRevision:transition.previousRevision};
    if(transition.operation!=='revoke'||transition.deviceId!==intent.deviceId||
       transition.fingerprint!==intent.fingerprint||transition.previousRevision!==intent.expectedRevision||
       transition.revision!==intent.expectedRevision+1||
       ownerAuthorityTargetDigest(intent.operation,target)!==intent.targetDigest||
       trust.revision!==transition.revision||trust.devices.some(device=>device.deviceId===intent.deviceId)){
      throw fail('PROVISIONING_RECOVERY_BLOCKED','Trust revocation outcome differs from signed approval');
    }
    recoverTrustLocks(trust);
    trust=inspectDurableDeviceTrust({directory:trustDirectory});
    if(trust.revision!==transition.revision||trust.lockPresent||trust.operationGatePresent){
      throw fail('PROVISIONING_RECOVERY_BLOCKED','Trust revocation locks remain unresolved');
    }
    return 'applied';
  }
  function reconcileGrantIntent(intent){
    let policy=grantStore.inspect();
    if(policy.locks.some(lock=>lock.name.startsWith('.tool-grant-permit-'))){
      throw fail('PROVISIONING_RECOVERY_BLOCKED','A grant authorization permit is unresolved');
    }
    if(policy.locks.some(lock=>lock.status!=='dead')){
      throw fail('PROVISIONING_BUSY','Grant store has an active or unverified lock');
    }
    if(policy.locks.length){
      clearStaleDurableToolGrantLocks({directory:grantStore.directory,
        operatorConfirmedNoActiveWriters:true,operatorConfirmedNoActiveRecovery:true});
      policy=grantStore.inspect();
      if(policy.locks.length)throw fail('PROVISIONING_RECOVERY_BLOCKED','Grant store locks remain unresolved');
    }
    if(intent.operation==='grant.issue'){
      const grant=policy.grants.find(value=>value.eventId===intent.eventId);
      if(!grant){
        if(policy.revision===intent.expectedRevision)return 'not_applied';
        throw fail('PROVISIONING_RECOVERY_BLOCKED','Grant issue event is absent after policy revision advanced');
      }
      const target={realmId,ownerDigest:grant.ownerDigest,deviceId:grant.deviceId,
        fingerprint:grant.fingerprint,tool:grant.tool,scope:grant.scope,
        constraints:grant.constraints,policyRevision:intent.expectedRevision};
      if(grant.active&&grant.tool==='read_file'&&grant.deviceId===intent.deviceId&&
         grant.fingerprint===intent.fingerprint&&grant.revision===intent.expectedRevision+1&&
         policy.revision===grant.revision&&
         ownerAuthorityTargetDigest(intent.operation,target)===intent.targetDigest)return 'applied';
    }else{
      const grant=policy.grants.find(value=>value.revokedEventId===intent.eventId);
      if(!grant){
        const active=policy.grants.find(value=>value.active&&value.ownerDigest===intent.ownerDigest&&
          value.deviceId===intent.deviceId&&value.fingerprint===intent.fingerprint&&value.tool==='read_file');
        if(policy.revision===intent.expectedRevision&&active)return 'not_applied';
        throw fail('PROVISIONING_RECOVERY_BLOCKED','Grant revocation event is absent after policy revision advanced');
      }
      const target={realmId,ownerDigest:grant.ownerDigest,deviceId:grant.deviceId,
        fingerprint:grant.fingerprint,grantId:grant.grantId,policyRevision:intent.expectedRevision};
      if(!grant.active&&grant.tool==='read_file'&&grant.deviceId===intent.deviceId&&
         grant.fingerprint===intent.fingerprint&&grant.revokedRevision===intent.expectedRevision+1&&
         policy.revision===grant.revokedRevision&&
         ownerAuthorityTargetDigest(intent.operation,target)===intent.targetDigest)return 'applied';
    }
    throw fail('PROVISIONING_RECOVERY_BLOCKED','Grant snapshot and signed approval disagree');
  }
  function inferOutcome(intent){
    switch(intent.operation){
      case 'device.approve':return reconcilePairingIntent(intent);
      case 'binding.create':return reconcileBindingIntent(intent);
      case 'device.revoke':return reconcileDeviceRevocation(intent);
      case 'grant.issue':case 'grant.revoke':return reconcileGrantIntent(intent);
      default:throw fail('PROVISIONING_RECOVERY_BLOCKED','Unsupported recovery operation');
    }
  }
  function reconcile({operatorConfirmedNoActiveWriters}={}){
    if(operatorConfirmedNoActiveWriters!==true)throw fail('OPERATOR_REQUIRED',
      'Explicit confirmation that all realm writers are stopped is required');
    const initial=inspectDurableOwnerAudit({directory:provisioningDirectory});
    const lockName='.owner-pairing-reconciliation.lock';
    if(initial.pending.length===0){
      if(!initial.lockPresent)return Object.freeze({state:'CONSISTENT'});
      if(initial.lockStatus!=='dead')throw fail('PROVISIONING_BUSY',
        'Provisioning writer is active or cannot be verified');
      if(inspectDurableProcessLock(provisioningDirectory,lockName).present){
        throw fail('PROVISIONING_BUSY','A provisioning recovery lock already exists');
      }
      const recoveryLock=createDurableProcessLock(provisioningDirectory,lockName,'reconciliation');
      try{
        const current=inspectDurableOwnerAudit({directory:provisioningDirectory});
        if(current.sequence!==initial.sequence||current.hash!==initial.hash||
           current.lockDigest!==initial.lockDigest||current.pending.length){
          throw fail('PROVISIONING_CONFLICT','Provisioning evidence changed during lock recovery');
        }
        releaseOwnerAuditLockForReconciliation({directory:provisioningDirectory,
          expectedSequence:current.sequence,expectedHash:current.hash,
          operatorConfirmedNoActiveWriters:true});
        const final=inspectDurableOwnerAudit({directory:provisioningDirectory});
        if(final.lockPresent||final.pending.length)throw fail('PROVISIONING_RECOVERY_BLOCKED',
          'Provisioning audit lock remains unresolved');
        removeOwnedDurableProcessLock({directory:provisioningDirectory,name:lockName,
          owner:recoveryLock});
        return Object.freeze({state:'RECONCILED_STALE_LOCK'});
      }catch(error){
        throw error;
      }
    }
    if(initial.pending.length!==1)throw fail('PROVISIONING_RECOVERY_BLOCKED','Multiple provisioning intents are unresolved');
    const intent=initial.pending[0];
    requireApprovedIntent(intent);
    if(initial.lockPresent&&initial.lockStatus!=='dead'){
      throw fail('PROVISIONING_BUSY','Provisioning writer is active or cannot be verified');
    }
    if(inspectDurableProcessLock(provisioningDirectory,lockName).present){
      throw fail('PROVISIONING_BUSY','A provisioning recovery lock already exists');
    }
    const recoveryLock=createDurableProcessLock(provisioningDirectory,lockName,'reconciliation');
    let auditChanged=false;
    poisoned=true;
    try{
      const current=inspectDurableOwnerAudit({directory:provisioningDirectory});
      const writer=inspectDurableProcessLock(provisioningDirectory,'.owner-decisions-writer.lock');
      if(current.sequence!==initial.sequence||current.hash!==initial.hash||
         current.pending.length!==1||current.pending[0].eventId!==intent.eventId||
         writer.digest!==initial.lockDigest||writer.present&&writer.status!=='dead'){
        throw fail('PROVISIONING_CONFLICT','Provisioning evidence changed during recovery');
      }
      const outcome=inferOutcome(intent);
      appendRecoveredOwnerOutcome({directory:provisioningDirectory,intent,
        outcome:{...intent,at:new Date().toISOString(),phase:'outcome',outcome},
        operatorConfirmedNoActiveWriters:true});
      auditChanged=true;
      const after=inspectDurableOwnerAudit({directory:provisioningDirectory});
      if(after.pending.length!==0)throw fail('PROVISIONING_RECOVERY_BLOCKED','Provisioning intent remains pending');
      if(after.lockPresent){
        releaseOwnerAuditLockForReconciliation({directory:provisioningDirectory,
          expectedSequence:after.sequence,expectedHash:after.hash,
          operatorConfirmedNoActiveWriters:true});
      }
      return Object.freeze({state:outcome==='applied'?'RECONCILED_APPLIED':'RECONCILED_NOT_APPLIED',
        eventId:intent.eventId,operation:intent.operation});
    }catch(error){
      const latest=inspectDurableOwnerAudit({directory:provisioningDirectory});
      auditChanged||=latest.sequence!==initial.sequence||latest.hash!==initial.hash;
      if(!auditChanged)removeOwnedDurableProcessLock({directory:provisioningDirectory,
        name:lockName,owner:recoveryLock});
      throw error;
    }finally{
      const latest=inspectDurableOwnerAudit({directory:provisioningDirectory});
      if(!latest.pending.length&&!latest.lockPresent){
        try{removeOwnedDurableProcessLock({directory:provisioningDirectory,
          name:lockName,owner:recoveryLock});}catch{}
      }
    }
  }

  function inspect(){
    try{
      const evidence=inspectApprovalEvents();
      const owner=ownerAuthority.inspect();
      const trust=inspectDurableDeviceTrust({directory:trustDirectory});
      const audit=inspectDurableOwnerAudit({directory:auditDirectory});
      const bindings=machineBindingStore.list();
      const grants=grantStore.list();
      const auditWriterState=auditWriter.inspect();
      let readyDeviceCount=0;
      if(owner.status==='active'&&owner.owner){
        for(const binding of bindings){
          if(binding.ownerDigest!==owner.owner.ownerDigest)continue;
          const device=trust.devices.find(item=>item.deviceId===binding.deviceId&&
            item.fingerprint===binding.fingerprint);
          if(!device)continue;
          const approvalReceipt=readApprovalById(owner.owner.ownerId,binding.deviceId);
          const pairingOutcome=audit.events.find(event=>event.event==='g7_owner_pairing'&&
            event.version===2&&event.phase==='outcome'&&event.eventId===binding.approvalEventId&&
            event.outcome==='accepted');
          const pairingIntent=audit.events.find(event=>event.event==='g7_owner_pairing'&&
            event.version===2&&event.phase==='intent'&&event.eventId===binding.approvalEventId);
          const pairingTarget=pairingOutcome&&pairingIntent?{realmId,deviceId:binding.deviceId,
            requestId:pairingOutcome.requestId,fingerprint:binding.fingerprint,
            trustRevision:pairingOutcome.trustRevisionBefore}:null;
          if(!approvalReceipt||approvalReceipt.fingerprint!==binding.fingerprint||
             !pairingOutcome||!pairingIntent||pairingOutcome.deviceId!==binding.deviceId||
             !verifyStoredEntry({eventId:binding.approvalEventId,operation:'device.approve',
               ownerDigest:owner.owner.ownerDigest,expectedRevision:pairingOutcome.trustRevisionBefore,
               target:pairingTarget}))continue;
          const bindingTarget={realmId,ownerDigest:binding.ownerDigest,
            clientId:binding.clientId,deviceId:binding.deviceId,fingerprint:binding.fingerprint,
            bindingRevision:binding.bindingRevision-1,pairingEventId:binding.approvalEventId};
          if(!verifyStoredEntry({eventId:binding.bindingEventId,operation:'binding.create',
            ownerDigest:binding.ownerDigest,expectedRevision:binding.bindingRevision-1,
            target:bindingTarget}))continue;
          const activeGrant=grants.find(grant=>grant.active&&grant.tool==='read_file'&&
            grant.ownerDigest===binding.ownerDigest&&grant.deviceId===binding.deviceId&&
            grant.fingerprint===binding.fingerprint);
          if(!activeGrant)continue;
          const grantTarget={realmId,ownerDigest:activeGrant.ownerDigest,
            deviceId:activeGrant.deviceId,fingerprint:activeGrant.fingerprint,
            tool:activeGrant.tool,scope:activeGrant.scope,constraints:activeGrant.constraints,
            policyRevision:activeGrant.revision-1};
          if(verifyStoredEntry({eventId:activeGrant.eventId,operation:'grant.issue',
            ownerDigest:activeGrant.ownerDigest,expectedRevision:activeGrant.revision-1,
            target:grantTarget}))readyDeviceCount++;
        }
      }
      const healthy=owner.healthy===true&&trust.lockPresent===false&&
        trust.operationGatePresent===false&&trust.dispatchPermits.length===0&&
        trust.temporaryFiles.length===0&&audit.pending.length===0&&auditWriterState.pending===0&&
        evidence.pending.length===0&&evidence.lockPresent===false&&
        !poisoned;
      return Object.freeze({healthy,pending:evidence.pending.length,
        revision:evidence.sequence,readyDeviceCount,
        ownerStatus:owner.status,trustRevision:trust.revision,
        bindingRevision:machineBindingStore.revision(),policyRevision:grantStore.revision()});
    }catch{
      return Object.freeze({healthy:false,pending:1,revision:0,readyDeviceCount:0});
    }
  }

  return Object.freeze({startPairing,provePairing,approveDevice,bindDevice,
    issueReadFileGrant,revokeReadFileGrant,revokeDevice,reconcile,inspect});
}
