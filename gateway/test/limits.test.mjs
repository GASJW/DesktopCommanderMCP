import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { startGateway } from '../server.mjs';
import { startExecutor } from '../executor-socket.mjs';

const fixture=path.join(path.dirname(fileURLToPath(import.meta.url)),'fixtures','mock-executor.mjs');
const token=randomBytes(32).toString('hex');
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const post=async(base,id,name,text)=>{
  const res=await fetch(base+'/mcp',{method:'POST',
    headers:{authorization:'Bearer '+token,'content-type':'application/json'},
    body:JSON.stringify({jsonrpc:'2.0',id,method:'tools/call',params:{name,arguments:{text}}})});
  return {status:res.status, body:await res.json(),retryAfter:res.headers.get('retry-after')};
};

test('gateway enforces output byte limit on Unicode and remains available',async()=>{
  const events=[];
  const app=await startGateway({authMode:'local',token,executorFile:fixture,port:0,
    maxResponseBytes:1024,maxUpstreamLineBytes:4096,auditEnabled:true,
    auditSink:line=>events.push(JSON.parse(line))});
  try {
    const marker='DO_NOT_ECHO_SENSITIVE_'+'é'.repeat(1200);
    const oversized=await post(app.address,1,'echo',marker);
    assert.equal(oversized.status,502);
    assert.match(oversized.body.error?.message,/smaller chunks/);
    assert.equal(JSON.stringify(oversized.body).includes(marker),false);
    const small=await post(app.address,2,'echo','G3_4_SMALL_RESPONSE_GREEN');
    assert.equal(small.status,200);
    assert.equal(small.body.result.content[0].text,'G3_4_SMALL_RESPONSE_GREEN');
    await sleep(20);
    assert.ok(events.some(x=>x.outcome==='limit_exceeded'&&x.http_status===502));
    assert.equal(JSON.stringify(events).includes('DO_NOT_ECHO_SENSITIVE_'),false);
  } finally {await app.close();}
});

test('gateway limits concurrent MCP calls and reports HTTP 429 with retry-after',async()=>{
  const events=[];
  const app=await startGateway({authMode:'local',token,executorFile:fixture,port:0,
    maxInFlight:2,auditEnabled:true,auditSink:line=>events.push(JSON.parse(line))});
  try {
    const responses=await Promise.all([
      post(app.address,1,'delay','one'),
      post(app.address,2,'delay','two'),
      post(app.address,3,'delay','three'),
    ]);
    assert.deepEqual(responses.map(x=>x.status).sort(),[200,200,429]);
    const limited=responses.find(x=>x.status===429);
    assert.equal(limited.retryAfter,'1');
    assert.match(limited.body.error.message,/concurrency limit/);
    const after=await post(app.address,4,'echo','RECOVERED_AFTER_LOAD');
    assert.equal(after.status,200);
    await sleep(20);
    assert.ok(events.some(x=>x.outcome==='busy'&&x.http_status===429));
  } finally {await app.close();}
});

test('oversized upstream frames disconnect safely and reconnect with no replay',async()=>{
  const dir=mkdtempSync(path.join(os.tmpdir(),'vpsc-g34-line-'));
  const socket=path.join(dir,'mcp.sock');
  let worker,app;
  try {
    worker=await startExecutor({socketPath:socket,executorFile:fixture,cwd:dir});
    app=await startGateway({authMode:'local',token,executorSocket:socket,port:0,
      maxResponseBytes:1024,maxUpstreamLineBytes:2048,
      recoveryInitialDelay:50,recoveryMaxDelay:250});
    const huge=await post(app.address,1,'echo','OVER_FRAME_'+'.'.repeat(4000));
    assert.ok([502,503].includes(huge.status));
    let healthy=false;
    for(let i=0;i<60;i++){
      const result=await post(app.address,i+10,'echo','G3_4_FRAME_RECOVERED');
      if(result.status===200){healthy=true;break;}
      await sleep(75);
    }
    assert.equal(healthy,true,'gateway did not reconnect after oversized frame');
  } finally {await app?.close();await worker?.close();rmSync(dir,{recursive:true,force:true});}
});

test('operational caps reject malformed or unsafe configuration before listening',async()=>{
  const common={authMode:'local',token,executorFile:fixture,port:0};
  await assert.rejects(startGateway({...common,maxResponseBytes:0}),/response byte limit/);
  await assert.rejects(startGateway({...common,maxResponseBytes:16384,maxUpstreamLineBytes:4096}),/upstream line byte limit/);
  await assert.rejects(startGateway({...common,maxInFlight:17}),/in-flight limit/);
});
