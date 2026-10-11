import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { startGateway } from '../server.mjs';
import { startExecutor } from '../executor-socket.mjs';

const fixture=path.join(path.dirname(fileURLToPath(import.meta.url)),'fixtures','mock-executor.mjs');
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));

async function waitFor(predicate, timeoutMs=6500) {
  const end=Date.now()+timeoutMs;
  while (Date.now()<end) {
    try { if(await predicate()) return true; } catch {}
    await sleep(75);
  }
  return false;
}

test('gateway returns 503 during Unix executor outage and recovers automatically without restart',async()=>{
  const root=mkdtempSync(path.join(os.tmpdir(),'vpsc-recovery-'));
  const socketPath=path.join(root,'mcp.sock');
  const token=randomBytes(32).toString('hex');
  const records=[];
  let worker,gateway;
  try {
    worker=await startExecutor({socketPath,executorFile:fixture,cwd:root});
    gateway=await startGateway({executorSocket:socketPath,authMode:'local',token,port:0,
      recoveryInitialDelay:50,recoveryMaxDelay:250,auditEnabled:true,
      auditSink:line=>records.push(JSON.parse(line))});
    const health=async()=>{
      const res=await fetch(gateway.address+'/healthz',{headers:{authorization:'Bearer '+token}});
      return res.status;
    };
    const tools=async()=>{
      const res=await fetch(gateway.address+'/mcp',{method:'POST',
        headers:{authorization:'Bearer '+token,'content-type':'application/json'},
        body:JSON.stringify({jsonrpc:'2.0',id:'recovery-sensitive-id',method:'tools/list',params:{}})});
      const payload=await res.json();
      return {status:res.status,tools:payload.result?.tools};
    };
    assert.equal((await tools()).status,200);
    await worker.close(); worker=null;
    assert.equal(await waitFor(async()=>await health()===503),true,'gateway never detected outage');
    assert.equal((await tools()).status,503,'requests must fail closed while worker unavailable');
    assert.equal((await fetch(gateway.address+'/mcp',{method:'POST',headers:{'content-type':'application/json'},
      body:JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/list'})})).status,401);
    await sleep(220);
    worker=await startExecutor({socketPath,executorFile:fixture,cwd:root});
    assert.equal(await waitFor(async()=>{
      const result=await tools();
      return result.status===200&&result.tools?.[0]?.name==='echo';
    }),true,'gateway did not reconnect to restarted worker');
    assert.equal(await health(),200);
    assert.ok(records.some(x=>x.http_status===503));
    assert.ok(records.some(x=>x.outcome==='denied'));
    assert.equal(JSON.stringify(records).includes('recovery-sensitive-id'),false);
    // Repeat to catch stale socket/listener and one-shot recovery defects.
    await worker.close(); worker=null;
    assert.equal(await waitFor(async()=>await health()===503),true);
    worker=await startExecutor({socketPath,executorFile:fixture,cwd:root});
    assert.equal(await waitFor(async()=>(await tools()).status===200),true);
  } finally {
    await gateway?.close(); await worker?.close();
    rmSync(root,{recursive:true,force:true});
  }
});
