import { createDurableMachineBindingStore } from '../devices/durable-machine-bindings.mjs';
let input,store;
try{
  input=JSON.parse(process.env.VPSC_TEST_BINDING_INPUT);
  const record=input.record,approval=record.approvalReceipt;
  let decision={state:'NOT_FOUND',eventId:input.decision.eventId};
  store=createDurableMachineBindingStore({directory:input.directory,
    verifyApprovalReceipt:binding=>binding.approvalEventId===approval.eventId&&
      binding.ownerId===approval.ownerId&&binding.deviceId===approval.deviceId&&
      binding.fingerprint===approval.fingerprint?approval:null,
    readBindingDecision:binding=>binding.bindingEventId===decision.eventId?decision:
      {state:'NOT_FOUND',eventId:binding.bindingEventId},
    readBindingHistory:()=>({completed:[],pending:decision.state==='PENDING'?[decision]:[]})});
  decision=input.decision;
  const result=store.bind(record,{expectedRevision:0});
  process.stdout.write(JSON.stringify({ok:true,revision:result.revision})+'\n');
}catch(error){
  process.stdout.write(JSON.stringify({ok:false,code:error.code??'ERROR'})+'\n');
  process.exitCode=1;
}finally{store?.close();}
