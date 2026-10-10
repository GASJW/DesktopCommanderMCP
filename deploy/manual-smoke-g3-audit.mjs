#!/usr/bin/env node
// Optional G3.2 preflight: real MCP tools through ephemeral local HTTP+Unix-socket pair.
// No DNS, systemd, OAuth or production socket changes.
import {randomBytes} from 'node:crypto';
import {mkdtempSync,rmSync} from 'node:fs';
import path from 'node:path';
import {startExecutor} from '../gateway/executor-socket.mjs';
import {startGateway} from '../gateway/server.mjs';

const dir=mkdtempSync('/var/lib/vps-commander/workspace/.g3-audit-real-');
const socket=path.join(dir,'mcp.sock');
const executorFile='/opt/vps-commander/code/dist/index.js';
const token=randomBytes(32).toString('hex');
const entries=[];
let worker,gateway;
try {
  worker=await startExecutor({socketPath:socket,executorFile,cwd:dir});
  gateway=await startGateway({authMode:'local',token,port:0,executorSocket:socket,
    auditEnabled:true,auditSink:line=>entries.push(JSON.parse(line))});
  const invoke=async(id,method,params={})=>{
    const res=await fetch(gateway.address+'/mcp',{method:'POST',
      headers:{authorization:'Bearer '+token,'content-type':'application/json'},
      body:JSON.stringify({jsonrpc:'2.0',id,method,params})});
    if(res.status!==200)throw Error('MCP HTTP status='+res.status);
    const result=await res.json();
    if(result.error||result.result?.isError)throw Error('MCP tool failed');
    return result.result;
  };
  const catalog=await invoke(1,'tools/list');
  if(!catalog.tools?.some(t=>t.name==='start_process'))throw Error('Missing shell tool');
  const command=await invoke(2,'tools/call',{name:'start_process',
    arguments:{command:'printf G3_AUDIT_REAL_GREEN',timeout_ms:1000}});
  if(!JSON.stringify(command.content).includes('G3_AUDIT_REAL_GREEN'))throw Error('Shell output not found');
  const file=await invoke(3,'tools/call',{name:'read_file',arguments:{path:'/etc/os-release',length:3}});
  if(!JSON.stringify(file.content).includes('Ubuntu'))throw Error('File response missing');
  await new Promise(resolve=>setImmediate(resolve));
  const required=['tools/list','tools/call','tools/call'];
  if(entries.length!==3||entries.some(x=>x.event!=='vps_commander_audit'||
      x.identity!=='local-authenticated'||x.outcome!=='ok'||x.http_status!==200)||
      required.some((x,i)=>entries[i]?.operation!==x))throw Error('Audit metadata mismatch');
  const serialized=JSON.stringify(entries);
  if(serialized.includes('G3_AUDIT_REAL_GREEN')||serialized.includes('/etc/os-release')||
      serialized.includes(token))throw Error('Sensitive request/response content in audit log');
  console.log('G3_2_REAL_AUDIT=GREEN');
  console.log('MCP_TOOLS='+catalog.tools.length+' AUDIT_EVENTS='+entries.length);
} finally {
  await gateway?.close();
  await worker?.close();
  rmSync(dir,{recursive:true,force:true});
}
