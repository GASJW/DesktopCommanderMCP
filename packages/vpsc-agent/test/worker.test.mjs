import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { createAgentWorker } from '../src/worker.mjs';

const DEVICE='b7e92caf-f591-44c4-8fb7-6c489ea573f4';
const SESSION='171e4f09-bb6d-4b8a-91e8-01a9caf54023';
const AUTHORIZATION={approvalEventId:'b7e92caf-f591-44c4-8fb7-6c489ea573f5',
  approvalTrustRevisionBefore:0,approvalTrustRevisionAfter:1,fingerprint:'b'.repeat(64),
  ownerDigest:'a'.repeat(64),trustRevision:1,policyRevision:'i4-test-policy-v1'};

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
  assert.equal(f.calls.filter(item=>item==='poll').length,1);
});

test('missing result acknowledgement is ambiguous and never polls the task again',async()=>{
  const f=fixture({resultAck:{}});
  const worker=createAgentWorker({deviceId:DEVICE,client:f.client,executor:f.executor,pollIntervalMs:25});
  await assert.rejects(worker.run(),error=>error.code==='AMBIGUOUS_ACK');
  assert.equal(f.calls.filter(item=>item?.type==='handle').length,1);
  assert.equal(f.calls.filter(item=>item==='poll').length,1);
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
