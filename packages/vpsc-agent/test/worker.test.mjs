import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { createAgentWorker } from '../src/worker.mjs';

const DEVICE='b7e92caf-f591-44c4-8fb7-6c489ea573f4';
const SESSION='171e4f09-bb6d-4b8a-91e8-01a9caf54023';
const AUTHORIZATION={version:1,claims:{},signature:'A'.repeat(86)};

function fixture({frame,resultError,resultAck={accepted:true},heartbeatValue}={}){
  const calls=[];
  const requestId=randomUUID();
  let polls=0;
  const client={
    connect:async()=>{calls.push('connect');return {deviceId:DEVICE,sessionId:SESSION};},
    heartbeat:async()=>{calls.push('heartbeat');return heartbeatValue??{status:'alive',deviceId:DEVICE};},
    poll:async()=>{
      calls.push('poll');
      if(polls++>0)return null;
      return frame===undefined?{
        version:1,method:'tools/call',deviceId:DEVICE,sessionId:SESSION,
        requestId,authorization:AUTHORIZATION,
        params:{name:'read_file',arguments:{path:'/approved/test.txt'}},
      }:frame;
    },
    result:async(id,value)=>{
      calls.push({type:'result',id,value});
      if(resultError)throw resultError;
      return resultAck;
    },
    disconnect:async()=>{calls.push('disconnect');return {disconnected:true};},
    close:()=>calls.push('client-close'),
  };
  const executor={
    start:async()=>calls.push('executor-start'),
    handle:async value=>{calls.push({type:'handle',frame:value});return {content:[{type:'text',text:'ok'}]};},
    close:()=>calls.push('executor-close'),
  };
  return {calls,client,executor,requestId};
}
const waitFor=async predicate=>{
  const deadline=Date.now()+2000;
  while(Date.now()<deadline){if(predicate())return;await new Promise(resolve=>setTimeout(resolve,5));}
  throw Error('timed out waiting for worker event');
};

test('worker starts local MCP, authenticates, and dispatches one signed device task',async()=>{
  const f=fixture(),controller=new AbortController();
  const worker=createAgentWorker({deviceId:DEVICE,client:f.client,executor:f.executor,
    pollIntervalMs:25});
  const running=worker.run({signal:controller.signal});
  await waitFor(()=>f.calls.some(item=>item?.type==='result'));
  controller.abort();
  await running;
  assert.deepEqual(f.calls.slice(0,4),['executor-start','connect','heartbeat','poll']);
  assert.equal(f.calls.filter(item=>item?.type==='handle').length,1);
  assert.equal(f.calls.filter(item=>item?.type==='result').length,1);
  assert.ok(f.calls.includes('client-close'));
  assert.ok(f.calls.includes('disconnect'));
  assert.ok(f.calls.includes('executor-close'));
});

test('idle transport ambiguity reconnects with a fresh session without replaying a delivered operation',async()=>{
  const f=fixture(),sessionId=randomUUID();
  let firstPoll=true,taskDelivered=false,reconnects=0;
  const frame={version:1,method:'tools/call',deviceId:DEVICE,sessionId,
    requestId:f.requestId,authorization:AUTHORIZATION,
    params:{name:'read_file',arguments:{path:'/approved/test.txt'}}};
  f.client.poll=async()=>{
    f.calls.push('poll');
    if(firstPoll){firstPoll=false;throw Object.assign(Error('lost idle poll response'),{code:'AMBIGUOUS_TRANSPORT'});}
    if(!taskDelivered){taskDelivered=true;return frame;}
    return null;
  };
  f.client.reconnect=async()=>{reconnects++;f.calls.push('reconnect');
    return {deviceId:DEVICE,sessionId};};
  const worker=createAgentWorker({deviceId:DEVICE,client:f.client,executor:f.executor,pollIntervalMs:25});
  const running=worker.run();
  await waitFor(()=>f.calls.some(item=>item?.type==='result'));
  worker.stop();
  await running;
  assert.equal(reconnects,1);
  assert.equal(f.calls.filter(item=>item?.type==='handle').length,1);
  assert.equal(f.calls.filter(item=>item?.type==='result').length,1);
  assert.ok(f.calls.indexOf('reconnect')<f.calls.findIndex(item=>item?.type==='handle'));
});

test('worker forwards cancellation to the executor and never reports a cancelled result',async()=>{
  const f=fixture();
  let handleSignal;
  f.executor.handle=async(_frame,{signal}={})=>{
    handleSignal=signal;
    return new Promise((_resolve,reject)=>signal.addEventListener('abort',()=>
      reject(Object.assign(Error('cancelled'),{code:'AMBIGUOUS_CANCELLED'})),{once:true}));
  };
  const worker=createAgentWorker({deviceId:DEVICE,client:f.client,executor:f.executor,pollIntervalMs:25});
  const running=worker.run();
  await waitFor(()=>handleSignal!==undefined);
  worker.stop();
  await assert.rejects(running,error=>error.code==='AMBIGUOUS_CANCELLED');
  assert.equal(f.calls.filter(item=>item?.type==='result').length,0);
  assert.ok(f.calls.includes('executor-close'));
});
test('authenticated cancel control aborts only the active request and reports ambiguity, not rollback',async()=>{
  const f=fixture();
  const ownerDigest='a'.repeat(64);
  const frame={version:1,method:'tools/call',deviceId:DEVICE,sessionId:SESSION,
    requestId:f.requestId,authorization:{version:1,claims:{ownerDigest},signature:'A'.repeat(86)},
    params:{name:'run_command',arguments:{profile:'count_lines',path:'/approved/test.txt'}}};
  let polls=0,handleSignal;
  f.client.pollControl=async()=>{
    f.calls.push('poll-control');
    if(polls++===0)return {frame,cancel:null};
    if(polls===2)return {frame:null,cancel:{version:1,type:'cancel',deviceId:DEVICE,
      sessionId:SESSION,requestId:f.requestId,ownerDigest}};
    return {frame:null,cancel:null};
  };
  f.client.cancelAck=async value=>{f.calls.push({type:'cancel-ack',value});
    return {accepted:true,status:value.status};};
  f.executor.handle=async(_value,{signal}={})=>{
    handleSignal=signal;
    return new Promise((_resolve,reject)=>signal.addEventListener('abort',()=>
      reject(Object.assign(Error('child stopped after cancellation'),{code:'AMBIGUOUS_CANCELLED'})),
    {once:true}));
  };
  const worker=createAgentWorker({deviceId:DEVICE,client:f.client,executor:f.executor,pollIntervalMs:25});
  const running=worker.run();
  await waitFor(()=>handleSignal!==undefined);
  await waitFor(()=>f.calls.some(item=>item?.type==='cancel-ack'));
  worker.stop();
  await running;
  const acknowledgement=f.calls.find(item=>item?.type==='cancel-ack').value;
  assert.equal(acknowledgement.requestId,f.requestId);
  assert.equal(acknowledgement.ownerDigest,ownerDigest);
  assert.equal(acknowledgement.status,'ambiguous');
  assert.equal(f.calls.filter(item=>item?.type==='result').length,0);
});

test('worker accepts a conservative ambiguous ack and continues when local execution was cancelled before intent',async()=>{
  const f=fixture();
  const ownerDigest='c'.repeat(64),secondRequestId=randomUUID();
  const frame={version:1,method:'tools/call',deviceId:DEVICE,sessionId:SESSION,
    requestId:f.requestId,authorization:{version:1,claims:{ownerDigest},signature:'A'.repeat(86)},
    params:{name:'read_file',arguments:{path:'/approved/cancelled-before-intent.txt'}}};
  const secondFrame={...frame,requestId:secondRequestId,
    params:{name:'read_file',arguments:{path:'/approved/allowed-after-cancel.txt'}}};
  let polls=0,executions=[];
  f.client.pollControl=async()=>{
    const poll=polls++;
    if(poll===0)return {frame,cancel:null};
    if(poll===1)return {frame:null,cancel:{version:1,type:'cancel',deviceId:DEVICE,
      sessionId:SESSION,requestId:f.requestId,ownerDigest}};
    if(poll===2)return {frame:secondFrame,cancel:null};
    return {frame:null,cancel:null};
  };
  f.client.cancelAck=async value=>{
    f.calls.push({type:'cancel-ack',value});
    return {accepted:true,status:'ambiguous'};
  };
  f.executor.handle=async(value,{signal}={})=>{
    executions.push(value.requestId);
    if(value.requestId===f.requestId){
      return new Promise((_resolve,reject)=>{
        const cancel=()=>reject(Object.assign(Error('cancelled before intent'),{code:'CANCELLED'}));
        if(signal.aborted)cancel();else signal.addEventListener('abort',cancel,{once:true});
      });
    }
    return {content:[{type:'text',text:'next operation completed'}]};
  };
  const worker=createAgentWorker({deviceId:DEVICE,client:f.client,executor:f.executor,pollIntervalMs:25});
  const running=worker.run();
  await waitFor(()=>f.calls.some(item=>item?.type==='result'&&item.id===secondRequestId));
  worker.stop();
  await running;
  const acknowledgement=f.calls.find(item=>item?.type==='cancel-ack').value;
  assert.equal(acknowledgement.requestId,f.requestId);
  assert.deepEqual(executions,[f.requestId,secondRequestId]);
  assert.deepEqual(f.calls.filter(item=>item?.type==='result').map(item=>item.id),[secondRequestId]);
});

test('cancellation arriving after completion is acknowledged as completed without replay or rollback',async()=>{
  const f=fixture();
  const ownerDigest='b'.repeat(64);
  const frame={version:1,method:'tools/call',deviceId:DEVICE,sessionId:SESSION,
    requestId:f.requestId,authorization:{version:1,claims:{ownerDigest},signature:'A'.repeat(86)},
    params:{name:'read_file',arguments:{path:'/approved/test.txt'}}};
  let polls=0,executions=0;
  f.client.pollControl=async()=>{
    const poll=polls++;
    if(poll===0)return {frame,cancel:null};
    if(poll===1)return {frame:null,cancel:{version:1,type:'cancel',deviceId:DEVICE,
      sessionId:SESSION,requestId:f.requestId,ownerDigest}};
    return {frame:null,cancel:null};
  };
  f.client.cancelAck=async value=>{
    f.calls.push({type:'cancel-ack',value});
    return {accepted:true,status:value.status};
  };
  f.executor.handle=async()=>{
    executions++;
    return {content:[{type:'text',text:'completed before cancellation'}]};
  };
  const worker=createAgentWorker({deviceId:DEVICE,client:f.client,executor:f.executor,pollIntervalMs:25});
  const running=worker.run();
  await waitFor(()=>f.calls.some(item=>item?.type==='cancel-ack'));
  worker.stop();
  await running;
  const acknowledgement=f.calls.find(item=>item?.type==='cancel-ack').value;
  assert.equal(acknowledgement.requestId,f.requestId);
  assert.equal(acknowledgement.status,'completed');
  assert.equal(executions,1,'completed work is never replayed');
  assert.equal(f.calls.filter(item=>item?.type==='result').length,0,
    'a late cancellation cannot convert completion into a result or rollback claim');
});

test('mismatched cancellation control cannot abort or acknowledge another owner request',async()=>{
  const f=fixture();
  const ownerDigest='a'.repeat(64);
  const frame={version:1,method:'tools/call',deviceId:DEVICE,sessionId:SESSION,
    requestId:f.requestId,authorization:{version:1,claims:{ownerDigest},signature:'A'.repeat(86)},
    params:{name:'run_command',arguments:{profile:'count_lines',path:'/approved/test.txt'}}};
  let polls=0,handleSignal,finish;
  f.client.pollControl=async()=>polls++===0?{frame,cancel:null}:{frame:null,cancel:{version:1,
    type:'cancel',deviceId:DEVICE,sessionId:SESSION,requestId:randomUUID(),ownerDigest}};
  f.client.cancelAck=async value=>{f.calls.push({type:'cancel-ack',value});return {accepted:true,status:value.status};};
  f.executor.handle=async(_value,{signal}={})=>{
    handleSignal=signal;
    return new Promise(resolve=>{finish=()=>resolve({content:[{type:'text',text:'completed'}]});
      signal.addEventListener('abort',()=>resolve({content:[{type:'text',text:'aborted'}]}),{once:true});});
  };
  const worker=createAgentWorker({deviceId:DEVICE,client:f.client,executor:f.executor,pollIntervalMs:25});
  const running=worker.run();
  const rejection=assert.rejects(running,error=>error.code==='INVALID_CANCEL_CONTROL');
  await waitFor(()=>handleSignal!==undefined);
  await new Promise(resolve=>setTimeout(resolve,35));
  assert.equal(handleSignal.aborted,false);
  assert.equal(f.calls.some(item=>item?.type==='cancel-ack'),false);
  finish();
  await rejection;
  assert.equal(f.calls.some(item=>item?.type==='cancel-ack'),false);
  assert.equal(f.calls.filter(item=>item?.type==='result').length,0);
});

test('worker accepts only the finite I4 operation set, never arbitrary command tools',async()=>{
  const f=fixture({frame:{version:1,method:'tools/call',deviceId:DEVICE,sessionId:SESSION,
    requestId:randomUUID(),authorization:AUTHORIZATION,
    params:{name:'run_command',arguments:{profile:'count_lines',path:'/approved/a'}}}});
  const worker=createAgentWorker({deviceId:DEVICE,client:f.client,executor:f.executor,pollIntervalMs:25});
  const running=worker.run();
  await waitFor(()=>f.calls.some(item=>item?.type==='result'));
  worker.stop();await running;
  assert.equal(f.calls.filter(item=>item?.type==='handle').length,1);
  const bad=fixture({frame:{version:1,method:'tools/call',deviceId:DEVICE,sessionId:SESSION,
    requestId:randomUUID(),authorization:AUTHORIZATION,
    params:{name:'start_process',arguments:{command:'id'}}}});
  const denied=createAgentWorker({deviceId:DEVICE,client:bad.client,executor:bad.executor,pollIntervalMs:25});
  await assert.rejects(denied.run(),error=>error.code==='PROTOCOL');
  assert.equal(bad.calls.filter(item=>item?.type==='handle').length,0);
});

test('worker refuses a task for another device or session before local execution',async()=>{
  const f=fixture({frame:{version:1,method:'tools/call',deviceId:'00000000-0000-4000-8000-000000000000',
    sessionId:SESSION,requestId:randomUUID(),authorization:AUTHORIZATION,
    params:{name:'read_file',arguments:{path:'/approved/test.txt'}}}});
  const worker=createAgentWorker({deviceId:DEVICE,client:f.client,executor:f.executor,pollIntervalMs:25});
  await assert.rejects(worker.run(),error=>error.code==='PROTOCOL');
  assert.equal(f.calls.filter(item=>item?.type==='handle').length,0);
  assert.equal(f.calls.filter(item=>item?.type==='result').length,0);
  assert.ok(f.calls.includes('client-close'));
});

test('ambiguous result transport fails once and never replays the local read',async()=>{
  const f=fixture({resultError:Object.assign(Error('lost response'),{code:'AMBIGUOUS_TRANSPORT'})});
  const worker=createAgentWorker({deviceId:DEVICE,client:f.client,executor:f.executor,pollIntervalMs:25});
  await assert.rejects(worker.run(),error=>error.code==='AMBIGUOUS_TRANSPORT');
  assert.equal(f.calls.filter(item=>item?.type==='handle').length,1);
  assert.equal(f.calls.filter(item=>item?.type==='result').length,1);
  assert.equal(f.calls.filter(item=>item==='poll').length,2,
    'one poll obtains the task and one keeps the active session while executing');
});

test('missing result acknowledgement is ambiguous and never polls the task again',async()=>{
  const f=fixture({resultAck:{}});
  const worker=createAgentWorker({deviceId:DEVICE,client:f.client,executor:f.executor,pollIntervalMs:25});
  await assert.rejects(worker.run(),error=>error.code==='AMBIGUOUS_ACK');
  assert.equal(f.calls.filter(item=>item?.type==='handle').length,1);
  assert.equal(f.calls.filter(item=>item==='poll').length,2,
    'the active poll does not replay or dequeue a second task');
});

test('heartbeat must confirm the selected device before polling',async()=>{
  const f=fixture({heartbeatValue:{status:'alive',deviceId:'00000000-0000-4000-8000-000000000000'}});
  const worker=createAgentWorker({deviceId:DEVICE,client:f.client,executor:f.executor,pollIntervalMs:25});
  await assert.rejects(worker.run(),error=>error.code==='PROTOCOL');
  assert.equal(f.calls.includes('poll'),false);
});

test('worker never starts remote access if the local MCP child fails to start',async()=>{
  const f=fixture();
  f.executor.start=async()=>{throw Object.assign(Error('offline'),{code:'UNAVAILABLE'});};
  const worker=createAgentWorker({deviceId:DEVICE,client:f.client,executor:f.executor,pollIntervalMs:25});
  await assert.rejects(worker.run(),error=>error.code==='UNAVAILABLE');
  assert.equal(f.calls.includes('connect'),false);
  assert.equal(f.calls.includes('poll'),false);
});
