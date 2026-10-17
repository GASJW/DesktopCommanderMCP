import { writeSync } from 'node:fs';
import { createDurableOwnerAudit, readDurableOwnerMachineBindingDecision,
  readDurableOwnerMachineBindingHistory } from '../dashboard/durable-owner-audit.mjs';
import { createDurableOwnerDeviceApprovalReader } from '../dashboard/durable-owner-device-authorization.mjs';
import { ownerPrincipalId } from '../dashboard/owner-identity.mjs';
import { createOwnerMachineBindingService } from '../dashboard/owner-machine-binding.mjs';
import { createDurableMachineBindingStore } from '../devices/durable-machine-bindings.mjs';

const [mode,auditDirectory,trustDirectory,bindingDirectory,deviceId,issuer,subject]=process.argv.slice(2);
const owner=Object.freeze({issuer,subject});
const ownerId=ownerPrincipalId(owner);
const readApproval=createDurableOwnerDeviceApprovalReader({auditDirectory,trustDirectory});
const approvalForOwner=(principal,id)=>{
  if(principal.issuer!==owner.issuer||principal.subject!==owner.subject)return null;
  const receipt=readApproval(principal,id);
  return receipt?Object.freeze({...receipt,ownerId:ownerId}):null;
};
const audit=createDurableOwnerAudit({directory:auditDirectory});
const durableStore=createDurableMachineBindingStore({directory:bindingDirectory,
  verifyApprovalReceipt:binding=>approvalForOwner(owner,binding.deviceId),
  readBindingDecision:binding=>readDurableOwnerMachineBindingDecision({
    directory:auditDirectory,eventId:binding.bindingEventId}),
  readBindingHistory:()=>readDurableOwnerMachineBindingHistory({directory:auditDirectory})});
const hold=(phase)=>{
  writeSync(1,Buffer.from(JSON.stringify({phase,pid:process.pid})+'\n'));
  const wait=new Int32Array(new SharedArrayBuffer(4));
  for(;;)Atomics.wait(wait,0,0,1000);
};
const machineBindingStore={
  bind(input,options){
    const result=durableStore.bind(input,options);
    if(mode==='after-snapshot-commit')hold('snapshot-committed');
    return result;
  },
  resolve:(...args)=>durableStore.resolve(...args),
  revision:(...args)=>durableStore.revision(...args),
};
const auditWrite=event=>{
  const result=audit.auditWrite(event);
  if(mode==='after-audit-intent'&&event.event==='g7_owner_machine_binding'&&
     event.phase==='intent')hold('intent-durable');
  return result;
};
const service=createOwnerMachineBindingService({
  accessVerifier:{verifyPrincipal:async assertion=>assertion==='synthetic-owner-assertion'?owner:null},
  auditWrite,readApprovalReceipt:approvalForOwner,machineBindingStore,
});
await service.bind({ownerAssertion:'synthetic-owner-assertion',
  clientId:'vpsc-crash-window-test-client',deviceId,expectedRevision:0});
writeSync(1,Buffer.from(JSON.stringify({phase:'unexpected-completion'})+'\n'));
