import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, symlinkSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createLocalReadonlyMcp } from '../src/local-mcp-readonly.mjs';
import { createDeviceRegistry } from '../../../gateway/devices/registry.mjs';
import { createPairingCoordinator } from '../../../gateway/devices/pairing.mjs';
import { createDeviceRouter } from '../../../gateway/devices/router.mjs';
import { startLoopbackAgentPilot } from '../../../gateway/devices/loopback-pilot.mjs';
import { createEphemeralPairingIdentity } from '../src/pairing.mjs';
import { createLoopbackAgentClient } from '../src/loopback-client.mjs';

const FIXTURE=fileURLToPath(new URL('./fixtures-readonly-mcp.mjs',import.meta.url));
const UUID='f1a2b3c4-d5e6-4a9f-8abc-1bb9b99c0001';
const SESSION='f1a2b3c4-d5e6-4a9f-8abc-1bb9b99c0002';
const CALL='f1a2b3c4-d5e6-4a9f-8abc-1bb9b99c0003';
function frame(args,name='read_file'){
  return {version:1,deviceId:UUID,sessionId:SESSION,requestId:CALL,method:'tools/call',
    params:{name,arguments:args}};
}
async function sandbox(fn,{entrypoint=FIXTURE}={}){
  const d=mkdtempSync(path.join(os.tmpdir(),'vpsc-readonly-agent-'));
  const approved=path.join(d,'approved');
  const outside=path.join(d,'outside');
  mkdirSync(approved);
  mkdirSync(outside);
  const file=path.join(approved,'demo.txt');
  writeFileSync(file,'vpsc-readonly-real-text\n');
  const other=path.join(outside,'private.txt');
  writeFileSync(other,'SHOULD_NOT_LEAK\n');
  const executor=createLocalReadonlyMcp({allowedRoot:approved,entrypoint,timeoutMs:7000});
  try{await executor.start();return await fn({executor,file,other,approved,d});}
  finally{executor.close();rmSync(d,{recursive:true,force:true});}
}
const withResult=(e,c)=>e?.code===c;
test('actual stdio MCP read_file works under a fixed allowed directory',async()=>{
  await sandbox(async({executor,file})=>{
    const result=await executor.handle(frame({path:file}));
    assert.equal(result.isError??false,false);
    assert.match(JSON.stringify(result),/vpsc-readonly-real-text/);
  });
});
test('write_file, start_process, get_config and shell are rejected before MCP dispatch',async()=>{
  await sandbox(async({executor,file})=>{
    for(const name of ['write_file','start_process','get_config','kill_process','list_directory']){
      await assert.rejects(executor.handle(frame({path:file},name)),e=>withResult(e,'DENIED'));
    }
  });
});
test('filesystem traversal, relative paths and symlinks escaping root denied',async()=>{
  await sandbox(async({executor,file,other,approved})=>{
    for(const p of [other,path.join(approved,'..','outside','private.txt'),'demo.txt']){
      await assert.rejects(executor.handle(frame({path:p})),e=>withResult(e,'DENIED'));
    }
    const link=path.join(approved,'shortcut');
    symlinkSync(other,link);
    await assert.rejects(executor.handle(frame({path:link})),e=>withResult(e,'DENIED'));
    assert.match(JSON.stringify(await executor.handle(frame({path:file}))),/vpsc-readonly/);
  });
});
test('bad parameters, network URL and extra injected parameters denied',async()=>{
  await sandbox(async({executor,file})=>{
    const bad=[
      {path:file,isUrl:true},{path:'https://example.test/x'},{path:file,offset:-1},
      {path:file,length:0},{path:file,length:1001},{path:file,origin:'ui'},
      {path:file,options:{}},{path:file,offset:'0'},{path:file,length:1.5},{path:file,offset:Infinity}
    ];
    for(const args of bad) await assert.rejects(executor.handle(frame(args)),e=>withResult(e,'DENIED'));
  });
});
test('oversize file blocked by local side independently of Desktop Commander config',async()=>{
  await sandbox(async({executor,approved})=>{
    const large=path.join(approved,'too-big.txt');
    writeFileSync(large,'x'.repeat(70*1024));
    await assert.rejects(executor.handle(frame({path:large})),e=>withResult(e,'DENIED'));
  });
});
test('unknown session/frame shape and untrusted method denied before dispatch',async()=>{
  await sandbox(async({executor,file})=>{
    for(const value of [null,{}, {...frame({path:file}),requestId:'wrong'},
      {...frame({path:file}),method:'tools/list'}, {...frame({path:file}),version:2}]){
      await assert.rejects(executor.handle(value),e=>withResult(e,'DENIED'));
    }
  });
});
test('loopback agent performs real local MCP child read then signed result routing',async()=>{
  const registry=createDeviceRegistry();
  const pairing=createPairingCoordinator({registry});
  const router=createDeviceRouter({registry,timeoutMs:4000});
  const pilot=await startLoopbackAgentPilot({registry,router,enableLoopbackPilot:true});
  const id=createEphemeralPairingIdentity();
  const request=pairing.startPairing({name:'gui-pilot',platform:'linux',publicKeyPem:id.publicKeyPem});
  pairing.provePossession(request.requestId,id.prove(request));
  const {deviceId}=pairing.approvePairing(request.requestId,id.fingerprint);
  const client=createLoopbackAgentClient({url:pilot.url,identity:id,deviceId});
  try{
    await client.connect();
    await client.heartbeat();
    await sandbox(async({executor,file})=>{
      const pending=router.callDevice({deviceId,name:'read_file',arguments:{path:file}});
      const response=await client.poll();
      assert.equal(response.deviceId,deviceId);
      assert.equal(response.params.name,'read_file');
      const actual=await executor.handle(response);
      await client.result(response.requestId,actual);
      const result=await pending;
      assert.match(JSON.stringify(result),/vpsc-readonly-real-text/);
      assert.equal(await client.poll(),null);
    },{entrypoint:process.env.VPSC_TEST_REAL_MCP_ENTRY??FIXTURE});
  }finally{router.close();await pilot.close();}
});
test('read-only tool denial cannot accidentally execute sensitive command via signed polling',async()=>{
  const registry=createDeviceRegistry(),pairing=createPairingCoordinator({registry}),
    router=createDeviceRouter({registry,timeoutMs:4000});
  const pilot=await startLoopbackAgentPilot({registry,router,enableLoopbackPilot:true});
  const id=createEphemeralPairingIdentity();
  const request=pairing.startPairing({name:'denial-pilot',platform:'linux',publicKeyPem:id.publicKeyPem});
  pairing.provePossession(request.requestId,id.prove(request));
  const {deviceId}=pairing.approvePairing(request.requestId,id.fingerprint);
  const client=createLoopbackAgentClient({url:pilot.url,identity:id,deviceId});
  try{
    await client.connect();await client.heartbeat();
    await sandbox(async({executor})=>{
      const pending=router.callDevice({deviceId,name:'start_process',arguments:{command:'id'}});
      const frame=await client.poll();
      await assert.rejects(executor.handle(frame),e=>withResult(e,'DENIED'));
      // Rejecting the remote work does not mean it ran; send an explicit denial result.
      await client.result(frame.requestId,{isError:true,content:[{type:'text',text:'Tool denied by local agent'}]});
      const result=await pending;
      assert.equal(result.isError,true);
      assert.match(JSON.stringify(result),/denied/);
    });
  }finally{router.close();await pilot.close();}
});
test('real installed Desktop Commander child (optional host integration)',{
  skip:!process.env.VPSC_TEST_REAL_MCP_ENTRY,
},async()=>{
  await sandbox(async({executor,file})=>{
    const result=await executor.handle(frame({path:file,offset:0,length:20}));
    assert.match(JSON.stringify(result),/vpsc-readonly-real-text/);
  },{entrypoint:process.env.VPSC_TEST_REAL_MCP_ENTRY});
});
