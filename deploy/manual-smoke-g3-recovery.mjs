#!/usr/bin/env node
// G3.3 manual recovery smoke. Runs isolated gateway, real Desktop Commander and private socket.
// Does NOT kill/restart any systemd service and does not touch production socket or DNS.
import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import path from 'node:path';
import { startExecutor } from '../gateway/executor-socket.mjs';
import { startGateway } from '../gateway/server.mjs';

const root=mkdtempSync('/var/lib/vps-commander/workspace/.g3-recovery-real-');
const socketPath=path.join(root,'executor.sock');
const token=randomBytes(32).toString('hex');
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
let worker,gateway;
try {
  const newWorker=()=>startExecutor({socketPath,
    executorFile:'/opt/vps-commander/code/dist/index.js',cwd:root});
  worker=await newWorker();
  gateway=await startGateway({executorSocket:socketPath,authMode:'local',token,port:0,
    recoveryInitialDelay:50,recoveryMaxDelay:250});
  const post=async(id,method,params={})=>{
    const res=await fetch(gateway.address+'/mcp',{method:'POST',
      headers:{'authorization':'Bearer '+token,'content-type':'application/json'},
      body:JSON.stringify({jsonrpc:'2.0',id,method,params})});
    return {status:res.status,body:await res.json()};
  };
  const tryUntil=async(fn)=>{
    const end=Date.now()+8000;
    while(Date.now()<end){if(await fn())return true;await sleep(100)}
    return false;
  };
  const before=await post(1,'tools/list');
  if(before.status!==200||!before.body.result?.tools?.some(t=>t.name==='start_process'))
    throw Error('Real MCP initial tools/list failed');
  console.log('G3_3_INITIAL_TOOLS='+before.body.result.tools.length);
  await worker.close();worker=null;
  const denied=await tryUntil(async()=>(await post(2,'tools/list')).status===503);
  if(!denied)throw Error('Gateway did not enter closed/503 state');
  console.log('G3_3_DISCONNECTED_HTTP=503');
  worker=await newWorker();
  const restored=await tryUntil(async()=>(await post(3,'tools/list')).status===200);
  if(!restored)throw Error('Gateway did not reconnect to real executor');
  const shell=await post(4,'tools/call',{name:'start_process',
    arguments:{command:'printf G3_3_REAL_RECOVERY_GREEN',timeout_ms:1000}});
  if(shell.status!==200||shell.body.result?.isError||
     !JSON.stringify(shell.body.result?.content).includes('G3_3_REAL_RECOVERY_GREEN'))
    throw Error('Recovered real terminal call failed');
  console.log('G3_3_REAL_RECOVERY=GREEN');
} finally {
  await gateway?.close(); await worker?.close();
  rmSync(root,{recursive:true,force:true});
}
