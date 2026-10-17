// Explicit, single-session poll loop for the isolated agent candidate. It does
// not reconnect or replay after transport ambiguity; callers must start a new
// worker session after independently reviewing its state.
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

export function createAgentWorker({deviceId,client,executor,pollIntervalMs=250}={}){
  if(typeof deviceId!=='string'||!UUID.test(deviceId)||
     !client||!['connect','heartbeat','poll','result','close'].every(name=>
       typeof client[name]==='function')||
     !executor||!['start','handle','close'].every(name=>typeof executor[name]==='function')||
     !Number.isSafeInteger(pollIntervalMs)||pollIntervalMs<25||pollIntervalMs>5000){
    throw new TypeError('Invalid remote agent worker configuration');
  }
  const controller=new AbortController();
  let started=false,closed=false;
  let activeOperationController=null;
  async function readPoll(){
    if(typeof client.pollControl==='function'){
      const value=await client.pollControl();
      if(!value||typeof value!=='object'||Array.isArray(value)||
         Object.keys(value).sort().join(',')!=='cancel,frame'||
         !(value.frame===null||value.frame&&typeof value.frame==='object'&&!Array.isArray(value.frame))||
         !(value.cancel===null||value.cancel&&typeof value.cancel==='object'&&!Array.isArray(value.cancel))){
        throw fail('PROTOCOL','Gateway returned an invalid task/cancellation poll');
      }
      return value;
    }
    return {frame:await client.poll(),cancel:null};
  }
  async function run({signal}={}){
    if(started||closed)throw fail('STATE','Agent worker is single-use');
    started=true;
    let connected=false;
    const abort=()=>{controller.abort();activeOperationController?.abort();};
    signal?.addEventListener('abort',abort,{once:true});
    if(signal?.aborted)controller.abort();
    try{
      await executor.start();
      if(controller.signal.aborted)return Object.freeze({status:'stopped'});
      const session=await client.connect();
      if(!session||session.deviceId!==deviceId||typeof session.sessionId!=='string'||
         !UUID.test(session.sessionId))throw fail('PROTOCOL','Agent connected to an invalid device session');
      connected=true;
      while(!controller.signal.aborted){
        const heartbeat=await client.heartbeat();
        if(!heartbeat||heartbeat.deviceId!==deviceId||heartbeat.status!=='alive'){
          throw fail('PROTOCOL','Gateway heartbeat did not confirm the selected device');
        }
        if(controller.signal.aborted)break;
        const poll=await readPoll();
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
        const operationController=new AbortController();
        activeOperationController=operationController;
        const signalPair=combinedSignal(controller.signal,operationController.signal);
        let settled=false,operationResult,operationError;
        const execution=Promise.resolve().then(()=>executor.handle(frame,{signal:signalPair.signal}))
          .then(value=>{operationResult=value;settled=true;},error=>{operationError=error;settled=true;});
        let cancellationRequested=false,loopError=null;
        try{
          await Promise.resolve();
          while(!settled&&!controller.signal.aborted){
            const currentHeartbeat=await client.heartbeat();
            if(!currentHeartbeat||currentHeartbeat.deviceId!==deviceId||currentHeartbeat.status!=='alive'){
              throw fail('PROTOCOL','Gateway heartbeat did not confirm the active device session');
            }
            const control=await readPoll();
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
          if(!cancellationRequested&&typeof client.pollControl==='function'){
            const finalControl=await readPoll();
            if(finalControl.frame!==null){
              throw fail('PROTOCOL','Gateway delivered a second task before the active result');
            }
            if(finalControl.cancel!==null){
              if(!validCancel(finalControl.cancel,frame,session,deviceId)){
                throw fail('INVALID_CANCEL_CONTROL',
                  'Gateway cancellation does not match the completed owner/device/session/request');
              }
              cancellationRequested=true;
            }
          }
          if(cancellationRequested){
            if(typeof client.cancelAck!=='function'){
              throw fail('AMBIGUOUS_CANCEL_ACK','Cancellation acknowledgement is unavailable; do not replay');
            }
            const status=operationError
              ?operationError.code==='CANCELLED'?'cancelled':'ambiguous':'completed';
            const claims=frame.authorization.claims;
            const acknowledgement=await client.cancelAck({requestId:frame.requestId,
              ownerDigest:claims.ownerDigest,status});
            if(!acknowledgement||acknowledgement.accepted!==true||
               acknowledgement.status!==status&&acknowledgement.status!=='ambiguous'){
              throw fail('AMBIGUOUS_CANCEL_ACK','Cancellation acknowledgement was not accepted; do not replay');
            }
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
        const acknowledgement=await client.result(frame.requestId,result);
        if(!acknowledgement||acknowledgement.accepted!==true){
          throw fail('AMBIGUOUS_ACK','Result acknowledgement missing; do not replay the task');
        }
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
    controller.abort();
    activeOperationController?.abort();
    return true;
  }
  return Object.freeze({run,stop});
}
