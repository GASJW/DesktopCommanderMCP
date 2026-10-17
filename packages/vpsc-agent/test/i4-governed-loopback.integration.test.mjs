import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import path from 'node:path';
import os from 'node:os';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { createDeviceRegistry } from '../../../gateway/devices/registry.mjs';
import { createPairingCoordinator } from '../../../gateway/devices/pairing.mjs';
import { createDeviceRouter } from '../../../gateway/devices/router.mjs';
import { startLoopbackAgentPilot } from '../../../gateway/devices/loopback-pilot.mjs';
import { createEphemeralPairingIdentity } from '../src/pairing.mjs';
import { createAgentWorker } from '../src/worker.mjs';
import { createGovernedAgentExecutor } from '../src/governed-executor.mjs';
import { createLoopbackAgentClient } from '../src/loopback-client.mjs';
import { createRemoteDeviceMcpHandler } from '../../../gateway/devices/remote-mcp-handler.mjs';

const FIXTURE=fileURLToPath(new URL('./fixtures-readonly-mcp.mjs',import.meta.url));
const waitFor=async predicate=>{
  const end=Date.now()+15000;
  while(Date.now()<end){if(predicate())return;await new Promise(resolve=>setTimeout(resolve,5));}
  throw Error('Timed out waiting for loopback agent operation');
};
test('I4 signed agent loopback routes common governed operations through the owner MCP endpoint',{
  skip:typeof process.getuid==='function'&&process.getuid()===0,
},async t=>{
  const registry=createDeviceRegistry();
  const pairing=createPairingCoordinator({registry});
  const router=createDeviceRouter({registry,timeoutMs:10_000});
  const pilot=await startLoopbackAgentPilot({registry,router,enableLoopbackPilot:true});
  const identity=createEphemeralPairingIdentity();
  const request=pairing.startPairing({name:'i4-loopback-agent',platform:'linux',
    publicKeyPem:identity.publicKeyPem});
  pairing.provePossession(request.requestId,identity.prove(request));
  const {deviceId}=pairing.approvePairing(request.requestId,identity.fingerprint);
  const approvalEventId=randomUUID();
  const directory=mkdtempSync(path.join(os.tmpdir(),'vpsc-i4-loopback-'));
  const root=path.join(directory,'approved'),state=path.join(directory,'state');
  mkdirSync(root,{mode:0o700});mkdirSync(state,{mode:0o700});
  const file=path.join(root,'readme.txt');writeFileSync(file,'alpha\nbeta\ngamma\n');
  const largeFile=path.join(root,'large.txt'),largeContent='z'.repeat(32*1024);
  writeFileSync(largeFile,largeContent);
  const executor=createGovernedAgentExecutor({allowedRoot:root,
    entrypoint:process.env.VPSC_TEST_REAL_MCP_ENTRY??FIXTURE,ledgerDirectory:state});
  const enabledTools=new Set(['read_file','list_directory','write_file','list_processes','run_command']);
  const ownerServer=createServer(createRemoteDeviceMcpHandler({
    accessVerifier:{verifyPrincipal:async token=>{
      if(token!=='synthetic-owner-jwt')throw Error('owner authentication failed');
      return {issuer:'https://i4-loopback-owner.invalid',subject:'owner-i4'};
    }},deviceRegistry:registry,router,
    authorizeDevice:async(owner,id)=>owner.subject==='owner-i4'&&id===deviceId,
    authorizeTool:async(owner,id,name)=>owner.subject==='owner-i4'&&id===deviceId&&enabledTools.has(name),
    getDeviceApprovalReceipt:()=>({eventId:approvalEventId,deviceId,fingerprint:identity.fingerprint,
      trustRevisionBefore:0,trustRevisionAfter:1,trustRevision:1}),
    getTrustRevision:()=>1,authorizationPolicyRevision:'i4-loopback-policy-v1',
  }));
  await new Promise(resolve=>ownerServer.listen(0,'127.0.0.1',resolve));
  const ownerEndpoint=`http://127.0.0.1:${ownerServer.address().port}/mcp`;
  let clientClosed=false,sessionId=null,channelReady=false;
  const signedClient=createLoopbackAgentClient({url:pilot.url,identity,deviceId});
  const client={
    connect:async()=>{const session=await signedClient.connect();sessionId=session.sessionId;return session;},
    heartbeat:async()=>{const status=await signedClient.heartbeat();channelReady=status.status==='alive';return status;},
    poll:()=>signedClient.poll(),
    result:(requestId,result)=>signedClient.result(requestId,result),
    disconnect:async()=>{
      if(sessionId){registry.disconnect(deviceId,sessionId);router.detachTransport({deviceId,sessionId});}
      return {disconnected:true};
    },
    close:()=>{clientClosed=true;},
  };
  const controller=new AbortController();
  const worker=createAgentWorker({deviceId,client,executor,pollIntervalMs:25});
  const running=worker.run({signal:controller.signal});
  t.after(async()=>{
    controller.abort();
    await running.catch(()=>{});
    ownerServer.closeAllConnections();
    await new Promise(resolve=>ownerServer.close(resolve));
    router.close();await pilot.close();rmSync(directory,{recursive:true,force:true});
  });
  await waitFor(()=>sessionId!==null&&channelReady);
  const call=async(id,name,args)=>{
    const response=await fetch(ownerEndpoint,{method:'POST',headers:{
      'content-type':'application/json','cf-access-jwt-assertion':'synthetic-owner-jwt',
    },body:JSON.stringify({jsonrpc:'2.0',id,method:'tools/call',params:{name,
      arguments:{deviceId,...args}}})});
    return {status:response.status,body:await response.json()};
  };
  const read=await call('i4-read-1','read_file',{path:file,offset:0,length:20});
  assert.equal(read.status,200,JSON.stringify(read.body));
  assert.match(JSON.stringify(read.body.result),/alpha/);
  const largeRead=await call('i4-large-read','read_file',{path:largeFile,length:1000});
  assert.equal(largeRead.status,200,JSON.stringify(largeRead.body));
  assert.ok(JSON.stringify(largeRead.body.result).includes(largeContent));
  const listingResponse=await call('i4-list-2','list_directory',{path:root,depth:1});
  assert.equal(listingResponse.status,200);
  const listing=JSON.parse(listingResponse.body.result.content?.[0]?.text??'{}');
  assert.ok(listing.entries?.some(entry=>entry.name==='readme.txt'));
  const target=path.join(root,'created.txt'),writeRequestId=randomUUID();
  const written=await call(writeRequestId,'write_file',{path:target,content:'created by I4\n',mode:'create'});
  assert.equal(written.status,200);
  assert.equal(written.body.result.structuredContent.created,true);
  assert.equal(readFileSync(target,'utf8'),'created by I4\n');
  const duplicate=await call(writeRequestId,'write_file',{path:target,content:'created by I4\n',mode:'create'});
  assert.equal(duplicate.body.result.isError,true);
  const command=await call('i4-command-3','run_command',{profile:'count_lines',path:file});
  assert.equal(command.body.result.structuredContent.exitCode,0);
  assert.match(command.body.result.structuredContent.stdout,/3/);
  const processes=await call('i4-processes-4','list_processes',{});
  assert.ok(processes.body.result.structuredContent.jobs.some(job=>job.profile==='count_lines'&&job.exitCode===0));
  enabledTools.delete('write_file');
  const denied=await call('i4-denied-write','write_file',{path:path.join(root,'denied.txt'),
    content:'should not dispatch',mode:'create'});
  assert.equal(denied.status,403);
  assert.equal(readFileSync(path.join(state,'i4-execution.jsonl'),'utf8').includes('should not dispatch'),false);
  const executionLedger=readFileSync(path.join(state,'i4-execution.jsonl'),'utf8');
  const firstIntent=JSON.parse(executionLedger.split('\n')[0]);
  assert.equal(firstIntent.type,'intent');
  assert.equal(firstIntent.authorization.trustRevision,1);
  assert.equal(firstIntent.authorization.policyRevision,'i4-loopback-policy-v1');
  assert.match(firstIntent.authorization.ownerDigest,/^[a-f0-9]{64}$/);
  assert.doesNotMatch(executionLedger,/synthetic-owner-jwt|owner-i4|created by I4|alpha/);
  controller.abort();
  await running;
  assert.equal(clientClosed,true);
});
