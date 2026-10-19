// Reconnect only while idle. A delivered operation with an ambiguous outcome always fences the worker.
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const REMOTE_TOOLS=new Set(['read_file','list_directory','write_file','list_processes','run_command']);
const fail=(code,message)=>Object.assign(new Error(message),{code});

function wait(ms,signal){
  if(signal.aborted)return Promise.resolve(false);
  return new Promise(resolve=>{
    const finish=value=>{
      clearTimeout(timer);
      signal.removeEventListener('abort',onAbort);
      resolve(value);
    };
    const onAbort=()=>finish(false);
    const timer=setTimeout(()=>finish(true),ms);
    signal.addEventListener('abort',onAbort,{once:true});
  });
}
function validTask(frame,session,deviceId){
  return frame&&typeof frame==='object'&&!Array.isArray(frame)&&
    Object.keys(frame).sort().join(',')==='authorization,deviceId,method,params,requestId,sessionId,version'&&
    frame.version===1&&frame.method==='tools/call'&&frame.deviceId===deviceId&&
    frame.deviceId===session.deviceId&&frame.sessionId===session.sessionId&&
    typeof frame.requestId==='string'&&UUID.test(frame.requestId)&&
    frame.authorization&&typeof frame.authorization==='object'&&!Array.isArray(frame.authorization)&&
    Object.getPrototypeOf(frame.authorization)===Object.prototype&&
    Object.keys(frame.authorization).sort().join(',')==='claims,signature,version'&&
    frame.authorization.version===1&&typeof frame.authorization.signature==='string'&&
    /^[A-Za-z0-9_-]{86}$/.test(frame.authorization.signature)&&
    frame.authorization.claims&&typeof frame.authorization.claims==='object'&&
    !Array.isArray(frame.authorization.claims)&&
    Object.getPrototypeOf(frame.authorization.claims)===Object.prototype&&
    frame.params&&typeof frame.params==='object'&&!Array.isArray(frame.params)&&
    Object.keys(frame.params).sort().join(',')==='arguments,name'&&
    REMOTE_TOOLS.has(frame.params.name)&&frame.params.arguments&&
    typeof frame.params.arguments==='object'&&!Array.isArray(frame.params.arguments);
}
function validCancel(control,frame,session,deviceId){
  const ownerDigest=frame.authorization?.claims?.ownerDigest;
  return control&&typeof control==='object'&&!Array.isArray(control)&&
    Object.keys(control).sort().join(',')===
      'deviceId,ownerDigest,requestId,sessionId,type,version'&&
    control.version===1&&control.type==='cancel'&&control.deviceId===deviceId&&
    control.sessionId===session.sessionId&&control.requestId===frame.requestId&&
    /^[a-f0-9]{64}$/.test(ownerDigest??'')&&control.ownerDigest===ownerDigest;
}
function combinedSignal(parent,operation){
  const controller=new AbortController();
  const abort=()=>controller.abort();
  parent.addEventListener('abort',abort,{once:true});
  operation.addEventListener('abort',abort,{once:true});
  if(parent.aborted||operation.aborted)controller.abort();
  return {signal:controller.signal,close:()=>{
    parent.removeEventListener('abort',abort);operation.removeEventListener('abort',abort);
  }};
}

export function createAgentWorker({deviceId,client,executor,pollIntervalMs=250,onDiagnostic}={}){
  if(typeof deviceId!=='string'||!UUID.test(deviceId)||
     !client||!['connect','heartbeat','poll','result','close'].every(name=>
       typeof client[name]==='function')||
     !executor||!['start','handle','close'].every(name=>typeof executor[name]==='function')||
     !Number.isSafeInteger(pollIntervalMs)||pollIntervalMs<25||pollIntervalMs>5000||
     onDiagnostic!==undefined&&typeof onDiagnostic!=='function'){
    throw new TypeError('Invalid remote agent worker configuration');
  }
  const report=(requestId,route,phase,outcomeCode,startedAt)=>{
    if(!onDiagnostic)return;
    try{onDiagnostic(Object.freeze({requestId,deviceId,route,phase,outcomeCode,
      elapsedMs:Math.max(0,Math.round(performance.now()-startedAt))}));}catch{}
  };
  const controller=new AbortController();
  let started=false,closed=false,stopRequested=false,acknowledgementPending=false;
  let activeOperationController=null;
  const requestStop=()=>{
    stopRequested=true;
    if(acknowledgementPending)return;
    controller.abort();
    activeOperationController?.abort();
  };
  async function readPoll(signal,activeRequestId){
    if(typeof client.pollControl==='function'){
      const value=await client.pollControl({signal,...(activeRequestId?{activeRequestId}:{})});
      if(!value||typeof value!=='object'||Array.isArray(value)||
         Object.keys(value).sort().join(',')!=='cancel,frame'||
         !(value.frame===null||value.frame&&typeof value.frame==='object'&&!Array.isArray(value.frame))||
         !(value.cancel===null||value.cancel&&typeof value.cancel==='object'&&!Array.isArray(value.cancel))){
        throw fail('PROTOCOL','Gateway returned an invalid task/cancellation poll');
      }
      return value;
    }
    return {frame:await client.poll({signal}),cancel:null};
  }
  async function run({signal}={}){
    if(started||closed)throw fail('STATE','Agent worker is single-use');
    started=true;
    let connected=false;
    const abort=requestStop;
    signal?.addEventListener('abort',abort,{once:true});
    if(signal?.aborted)controller.abort();
    try{
      await executor.start();
      if(controller.signal.aborted)return Object.freeze({status:'stopped'});
      async function connectSession(reconnecting=false){
        let delay=250,reset=reconnecting;
        while(!controller.signal.aborted&&!stopRequested){
          try{
            if(reset&&typeof client.reconnect!=='function')
              throw fail('AMBIGUOUS_TRANSPORT','Client cannot safely replace an uncertain session');
            const current=reset
              ?await client.reconnect({signal:controller.signal})
              :await client.connect({signal:controller.signal});
            if(!current||current.deviceId!==deviceId||typeof current.sessionId!=='string'||
               !UUID.test(current.sessionId))throw fail('PROTOCOL','Agent connected to an invalid device session');
            return current;
          }catch(error){
            if(error?.code!=='AMBIGUOUS_TRANSPORT')throw error;
            reset=true;
            if(!await wait(delay,controller.signal))return null;
            delay=Math.min(delay*2,5000);
          }
        }
        return null;
      }
      let session=await connectSession();
      if(!session)return Object.freeze({status:'stopped'});
      connected=true;
      while(!controller.signal.aborted&&!stopRequested){
        let poll;
        try{
          const heartbeat=await client.heartbeat({signal:controller.signal});
          if(!heartbeat||heartbeat.deviceId!==deviceId||heartbeat.status!=='alive'){
            throw fail('PROTOCOL','Gateway heartbeat did not confirm the selected device');
          }
          if(controller.signal.aborted)break;
          poll=await readPoll(controller.signal);
        }catch(error){
          if(error?.code!=='AMBIGUOUS_TRANSPORT')throw error;
          connected=false;
          session=await connectSession(true);
          if(!session)break;
          connected=true;
          continue;
        }
        if(poll.cancel!==null)throw fail('PROTOCOL','Gateway sent a cancellation without an active request');
        const frame=poll.frame;
        if(frame!==null&&!validTask(frame,session,deviceId)){
          throw fail('PROTOCOL','Gateway poll returned an invalid device task');
        }
        if(frame===null){
          if(!await wait(pollIntervalMs,controller.signal))break;
          continue;
        }
        if(!validTask(frame,session,deviceId))throw fail('PROTOCOL','Gateway sent a task outside the authenticated device session');
        // The request is executed once. If result delivery is ambiguous, the
        // loop exits and deliberately does not poll or execute the task again.
        const requestStartedAt=performance.now();
        report(frame.requestId,'/agent/poll','delivery','DELIVERED',requestStartedAt);
        const operationController=new AbortController();
        activeOperationController=operationController;
        const signalPair=combinedSignal(controller.signal,operationController.signal);
        let settled=false,operationResult,operationError;
        const execution=Promise.resolve().then(()=>{
          report(frame.requestId,'local://mcp/tools/call','execution','STARTED',requestStartedAt);
          return executor.handle(frame,{signal:signalPair.signal});
        })
          .then(value=>{operationResult=value;settled=true;},error=>{operationError=error;settled=true;});
        let cancellationRequested=false,loopError=null;
        try{
          await Promise.resolve();
          while(!settled&&!controller.signal.aborted){
            try{
              const currentHeartbeat=await client.heartbeat({signal:controller.signal,
                activeRequestId:frame.requestId});
              if(!currentHeartbeat||currentHeartbeat.deviceId!==deviceId||currentHeartbeat.status!=='alive'){
                throw fail('PROTOCOL','Gateway heartbeat did not confirm the active device session');
              }
            }catch(error){
              if(error?.code!=='CONTROL_POLL_UNAVAILABLE')throw error;
              report(frame.requestId,'/agent/heartbeat','active_control',
                'CONTROL_POLL_UNAVAILABLE',requestStartedAt);
            }
            if(settled)break;
            let control;
            try{control=await readPoll(controller.signal,frame.requestId);}
            catch(error){
              if(error?.code!=='CONTROL_POLL_UNAVAILABLE')throw error;
              if(settled)break;
              if(!await wait(pollIntervalMs,controller.signal))break;
              continue;
            }
            if(settled&&control.frame===null&&control.cancel===null)break;
            if(control.frame!==null){
              throw fail('PROTOCOL','Gateway delivered a second task while one operation was active');
            }
            if(control.cancel!==null){
              if(!validCancel(control.cancel,frame,session,deviceId)){
                throw fail('INVALID_CANCEL_CONTROL',
                  'Gateway cancellation does not match the active owner/device/session/request');
              }
              cancellationRequested=true;
              operationController.abort();
            }
            if(!settled&&!await wait(pollIntervalMs,controller.signal))break;
          }
          if(controller.signal.aborted)operationController.abort();
          await execution;
          if(controller.signal.aborted){
            throw fail('AMBIGUOUS_CANCELLED','Operation was stopped after delivery; do not replay');
          }
          const executionOutcome=typeof operationError?.code==='string'&&/^[A-Z_]{1,48}$/.test(operationError.code)
            ?operationError.code:operationError?'OPERATION_FAILED':'COMPLETED';
          report(frame.requestId,'local://mcp/tools/call','execution',executionOutcome,requestStartedAt);
          if(cancellationRequested){
            if(typeof client.cancelAck!=='function'){
              throw fail('AMBIGUOUS_CANCEL_ACK','Cancellation acknowledgement is unavailable; do not replay');
            }
            const status=operationError
              ?operationError.code==='CANCELLED'?'cancelled':'ambiguous':'completed';
            const claims=frame.authorization.claims;
            acknowledgementPending=true;
            let acknowledgement;
            try{acknowledgement=await client.cancelAck({requestId:frame.requestId,
              ownerDigest:claims.ownerDigest,status,signal:controller.signal});}
            finally{acknowledgementPending=false;}
            if(!acknowledgement||acknowledgement.accepted!==true||
               acknowledgement.status!==status&&acknowledgement.status!=='ambiguous'){
              throw fail('AMBIGUOUS_CANCEL_ACK','Cancellation acknowledgement was not accepted; do not replay');
            }
            report(frame.requestId,'/agent/cancel-ack','cancellation',
              acknowledgement.status==='ambiguous'?'AMBIGUOUS_CANCELLED':'CANCELLED',requestStartedAt);
            continue;
          }
        }catch(error){
          loopError=error;
          // A stale or misrouted cancel control is not authority to stop this
          // request. Let the already delivered operation settle, then close
          // the session without accepting its result or replaying it.
          if(error?.code!=='INVALID_CANCEL_CONTROL')operationController.abort();
          await execution;
        }finally{
          activeOperationController=null;
          signalPair.close();
        }
        if(loopError)throw loopError;
        if(controller.signal.aborted){
          throw fail('AMBIGUOUS_CANCELLED','Operation was stopped after delivery; do not replay');
        }
        let result=operationResult;
        if(operationError!==undefined){
          const error=operationError;
          const code=typeof error?.code==='string'&&/^[A-Z_]{1,48}$/.test(error.code)
            ?error.code:'OPERATION_FAILED';
          if(code.startsWith('AMBIGUOUS_')||['LEDGER_WRITE_FAILED','LEDGER_CORRUPT',
              'RECOVERY_REQUIRED','LOCK_UNAVAILABLE','UNAVAILABLE'].includes(code)){
            throw fail(code,'Remote operation state requires session recovery');
          }
          result={isError:true,content:[{type:'text',text:`Remote operation rejected (${code})`}],
            structuredContent:{code}};
        }
        acknowledgementPending=true;
        let acknowledgement;
        report(frame.requestId,'/agent/result','submission','STARTED',requestStartedAt);
        try{acknowledgement=await client.result(frame.requestId,result,{signal:controller.signal});}
        catch(error){
          if(error?.code!=='RESULT_NOT_ACCEPTED'){
            report(frame.requestId,'/agent/result','submission',
              typeof error?.code==='string'&&/^[A-Z0-9_]{1,48}$/.test(error.code)
                ?error.code:'UNKNOWN',requestStartedAt);
            throw error;
          }
          report(frame.requestId,'/agent/result','submission','RESULT_NOT_ACCEPTED',requestStartedAt);
          if(typeof client.pollControl!=='function')throw error;
          const control=await readPoll(controller.signal,frame.requestId);
          if(control.frame!==null)throw fail('PROTOCOL','Gateway delivered a second task while reconciling a rejected result');
          if(!validCancel(control.cancel,frame,session,deviceId))throw error;
          if(typeof client.cancelAck!=='function'){
            throw fail('AMBIGUOUS_CANCEL_ACK','Cancellation acknowledgement is unavailable; do not replay');
          }
          const status=operationError
            ?operationError.code==='CANCELLED'?'cancelled':'ambiguous':'completed';
          let cancelAcknowledgement;
          try{cancelAcknowledgement=await client.cancelAck({requestId:frame.requestId,
            ownerDigest:frame.authorization.claims.ownerDigest,status,signal:controller.signal});}
          finally{acknowledgementPending=false;}
          if(!cancelAcknowledgement||cancelAcknowledgement.accepted!==true||
             cancelAcknowledgement.status!==status&&cancelAcknowledgement.status!=='ambiguous'){
            throw fail('AMBIGUOUS_CANCEL_ACK','Cancellation acknowledgement was not accepted; do not replay');
          }
          report(frame.requestId,'/agent/cancel-ack','cancellation',
            cancelAcknowledgement.status==='ambiguous'?'AMBIGUOUS_CANCELLED':'CANCELLED',requestStartedAt);
          continue;
        }
        finally{acknowledgementPending=false;}
        if(!acknowledgement||acknowledgement.accepted!==true){
          throw fail('AMBIGUOUS_ACK','Result acknowledgement missing; do not replay the task');
        }
        report(frame.requestId,'/agent/result','acknowledgement','ACCEPTED',requestStartedAt);
      }
      return Object.freeze({status:'stopped'});
    }finally{
      signal?.removeEventListener('abort',abort);
      closed=true;
      controller.abort();
      activeOperationController?.abort();
      if(connected&&typeof client.disconnect==='function'){
        try{await client.disconnect();}catch{}
      }
      try{await client.close();}catch{}
      try{await executor.close();}catch{}
    }
  }
  function stop(){
    if(closed)return false;
    requestStop();
    return true;
  }
  return Object.freeze({run,stop});
}
