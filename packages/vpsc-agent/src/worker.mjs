// Explicit, single-session poll loop for the isolated agent candidate. It does
// not reconnect or replay after transport ambiguity; callers must start a new
// worker session after independently reviewing its state.
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
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
    Object.keys(frame).sort().join(',')==='deviceId,method,params,requestId,sessionId,version'&&
    frame.version===1&&frame.method==='tools/call'&&frame.deviceId===deviceId&&
    frame.deviceId===session.deviceId&&frame.sessionId===session.sessionId&&
    typeof frame.requestId==='string'&&UUID.test(frame.requestId)&&
    frame.params&&typeof frame.params==='object'&&!Array.isArray(frame.params)&&
    Object.keys(frame.params).sort().join(',')==='arguments,name'&&
    frame.params.name==='read_file'&&frame.params.arguments&&
    typeof frame.params.arguments==='object'&&!Array.isArray(frame.params.arguments);
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
  async function run({signal}={}){
    if(started||closed)throw fail('STATE','Agent worker is single-use');
    started=true;
    let connected=false;
    const abort=()=>controller.abort();
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
        const frame=await client.poll();
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
        const result=await executor.handle(frame);
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
      if(connected&&typeof client.disconnect==='function'){
        try{await client.disconnect();}catch{}
      }
      try{client.close();}catch{}
      try{executor.close();}catch{}
    }
  }
  function stop(){
    if(closed)return false;
    controller.abort();
    return true;
  }
  return Object.freeze({run,stop});
}
