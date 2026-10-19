import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import path from 'node:path';
import os from 'node:os';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { createHash, generateKeyPairSync, randomUUID } from 'node:crypto';
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
import { createDurableToolGrantStore } from '../../../gateway/devices/durable-tool-grants.mjs';

const FIXTURE=fileURLToPath(new URL('./fixtures-readonly-mcp.mjs',import.meta.url));
const waitFor=async predicate=>{
  const end=Date.now()+15000;
  while(Date.now()<end){if(predicate())return;await new Promise(resolve=>setTimeout(resolve,5));}
  throw Error('Timed out waiting for loopback agent operation');
};
const i4PlatformSkip=process.platform!=='linux'
  ?'Gateway durable grants require Linux /proc identity and POSIX file modes'
  :typeof process.getuid==='function'&&process.getuid()===0
    ?'Gateway durable grants require a nonroot Linux process identity':false;
test('I4 signed agent loopback routes common governed operations through the owner MCP endpoint',{
  skip:i4PlatformSkip,
},async t=>{
  const registry=createDeviceRegistry();
  const pairing=createPairingCoordinator({registry});
  const router=createDeviceRouter({registry});
  const routerOperations=[];
  const observedRouter={...router,callDevice:async options=>{
    const operation={requestId:options.requestId,tool:options.name,startedAt:Date.now()};
    routerOperations.push(operation);
    try{
      const result=await router.callDevice(options);
      operation.finishedAt=Date.now();
      return result;
    }catch(error){
      operation.finishedAt=Date.now();operation.errorCode=error?.code??'UNKNOWN';
      throw error;
    }
  }};
  const pilot=await startLoopbackAgentPilot({registry,router,enableLoopbackPilot:true});
  const identity=createEphemeralPairingIdentity();
  const request=pairing.startPairing({name:'i4-loopback-agent',platform:'linux',
    publicKeyPem:identity.publicKeyPem});
  pairing.provePossession(request.requestId,identity.prove(request));
  const {deviceId}=pairing.approvePairing(request.requestId,identity.fingerprint);
  const approvalEventId=randomUUID();
  const directory=mkdtempSync(path.join(os.tmpdir(),'vpsc-i4-loopback-'));
  const root=path.join(directory,'approved'),state=path.join(directory,'state');
  const policyDirectory=path.join(directory,'tool-policy');
  mkdirSync(root,{mode:0o700});mkdirSync(state,{mode:0o700});mkdirSync(policyDirectory,{mode:0o700});
  const file=path.join(root,'readme.txt');writeFileSync(file,'alpha\nbeta\ngamma\n');
  const largeFile=path.join(root,'large.txt'),largeContent='z'.repeat(32*1024);
  writeFileSync(largeFile,largeContent);
  const identityFingerprint=identity.fingerprint;
  const ownerDigest=createHash('sha256').update('VPSC-I4-OWNER-v1\n')
    .update(JSON.stringify(['https://i4-loopback-owner.cloudflareaccess.com','owner-i4'])).digest('hex');
  const grantStore=createDurableToolGrantStore({directory:policyDirectory});
  const policyKeys=generateKeyPairSync('ed25519');
  const grantIds={};let policyRevision=0;
  const grants=[
    ['read_file',{root},{maxBytes:64*1024,maxLength:1000,maxOffset:100_000}],
    ['list_directory',{root},{maxDepth:2,maxEntries:200}],
    ['write_file',{root},{maxBytes:64*1024}],
    ['list_processes',{}, {maxJobs:32}],
    ['run_command',{root,profile:'count_lines'},
      {maxOutputBytes:16*1024,maxRuntimeMs:10_000,profile:'count_lines'}],
  ];
  for(const [tool,scope,constraints] of grants){
    const granted=grantStore.grant({ownerDigest,deviceId,fingerprint:identityFingerprint,
      tool,scope,constraints},{expectedRevision:policyRevision,eventId:randomUUID()});
    policyRevision=granted.revision;grantIds[tool]=granted.grantId;
  }
  const workerTrace=[];
  const observe=async(component,name,operation)=>{
    try{const value=await operation();workerTrace.push({component,name,status:'ok'});return value;}
    catch(error){workerTrace.push({component,name,status:'error',code:error?.code??'UNKNOWN'});throw error;}
  };
  const rawExecutor=createGovernedAgentExecutor({allowedRoot:root,
    entrypoint:process.env.VPSC_TEST_REAL_MCP_ENTRY??FIXTURE,ledgerDirectory:state,
    gatewayPolicyPublicKey:policyKeys.publicKey,deviceId,fingerprint:identityFingerprint});
  const executor={
    start:()=>observe('executor','start',()=>rawExecutor.start()),
    handle:(...args)=>observe('executor','handle',()=>rawExecutor.handle(...args)),
    close:()=>observe('executor','close',()=>rawExecutor.close()),
  };
  const trustStore={
    acquireDispatchPermit:({deviceId:target,sessionId,expectedRevision})=>{
      if(expectedRevision!==1||!registry.isLiveSession(target,sessionId)){
        throw Object.assign(Error('Trust session unavailable'),{code:'TRUST_SESSION_STALE'});
      }
      return {trustRevision:1,release:()=>true};
    },
    withCurrentSession:({deviceId:target,sessionId,expectedRevision},callback)=>{
      if(expectedRevision!==1||!registry.isLiveSession(target,sessionId)){
        throw Object.assign(Error('Trust session unavailable'),{code:'TRUST_SESSION_STALE'});
      }
      return callback();
    },
  };
  const ownerServer=createServer(createRemoteDeviceMcpHandler({
    accessVerifier:{verifyPrincipal:async token=>{
      if(token!=='synthetic-owner-jwt')throw Error('owner authentication failed');
      return {issuer:'https://i4-loopback-owner.cloudflareaccess.com',subject:'owner-i4'};
    }},deviceRegistry:registry,trustStore,router:observedRouter,
    authorizeDevice:async(owner,id)=>owner.subject==='owner-i4'&&id===deviceId,
    grantStore,policySigningKey:policyKeys.privateKey,
    getDeviceApprovalReceipt:()=>({eventId:approvalEventId,deviceId,fingerprint:identity.fingerprint,
      trustRevisionBefore:0,trustRevisionAfter:1,trustRevision:1}),
    getTrustRevision:()=>1,
  }));
  await new Promise(resolve=>ownerServer.listen(0,'127.0.0.1',resolve));
  const ownerEndpoint=`http://127.0.0.1:${ownerServer.address().port}/mcp`;
  let clientClosed=false,sessionId=null,channelReady=false;
  const signedClient=createLoopbackAgentClient({url:pilot.url,identity,deviceId});
  const client={
    connect:()=>observe('transport','connect',async()=>{
      const session=await signedClient.connect();sessionId=session.sessionId;return session;
    }),
    heartbeat:()=>observe('transport','heartbeat',async()=>{
      const status=await signedClient.heartbeat();channelReady=status.status==='alive';return status;
    }),
    poll:()=>observe('transport','poll',()=>signedClient.poll()),
    result:(requestId,result)=>observe('transport','result',()=>signedClient.result(requestId,result)),
    disconnect:()=>observe('transport','disconnect',async()=>{
      if(sessionId){registry.disconnect(deviceId,sessionId);router.detachTransport({deviceId,sessionId});}
      return {disconnected:true};
    }),
    close:()=>{clientClosed=true;workerTrace.push({component:'transport',name:'close',status:'ok'});},
  };
  const controller=new AbortController();
  const worker=createAgentWorker({deviceId,client,executor,pollIntervalMs:25});
  const running=worker.run({signal:controller.signal});
  const workerState={settled:false,errorCode:null};
  running.then(()=>{workerState.settled=true;},error=>{
    workerState.settled=true;workerState.errorCode=error?.code??'UNKNOWN';
  });
  t.after(async()=>{
    controller.abort();
    await running.catch(()=>{});
    ownerServer.closeAllConnections();
    await new Promise(resolve=>ownerServer.close(resolve));
    router.close();await pilot.close();grantStore.close?.();rmSync(directory,{recursive:true,force:true});
  });
  await waitFor(()=>sessionId!==null&&channelReady);
  const call=async(id,name,args)=>{
    const response=await fetch(ownerEndpoint,{method:'POST',headers:{
      'content-type':'application/json','cf-access-jwt-assertion':'synthetic-owner-jwt',
    },body:JSON.stringify({jsonrpc:'2.0',id,method:'tools/call',params:{name,
      arguments:{deviceId,...args}}})});
    const result={status:response.status,body:await response.json()};
    if(result.status>=400){
      const operation=routerOperations.at(-1);
      let ledger=[];
      try{ledger=readFileSync(path.join(state,'i4-execution.jsonl'),'utf8').trim()
        .split('\n').filter(Boolean).map(line=>JSON.parse(line)).slice(-10).map(record=>({
          type:record.type,status:record.status,tool:record.tool,requestId:record.requestId,
        }));}catch{}
      result.diagnostic={operation:operation&&{requestId:operation.requestId,
        tool:operation.tool,errorCode:operation.errorCode??null,
        elapsedMs:operation.finishedAt-operation.startedAt},
        operationState:operation?.requestId?pilot.operationState(operation.requestId):null,
        recentOperations:routerOperations.slice(-5).map(item=>({requestId:item.requestId,
          tool:item.tool,errorCode:item.errorCode??null,
          elapsedMs:item.finishedAt-item.startedAt,
          state:pilot.operationState(item.requestId)?.state??null})),
        ledger,worker:workerState,workerTrace:workerTrace.slice(-24),
        sessionLive:sessionId?registry.isLiveSession(deviceId,sessionId):false};
    }
    return result;
  };
  const read=await call('i4-read-1','read_file',{path:file,offset:0,length:20});
  assert.equal(read.status,200,JSON.stringify(read));
  assert.match(JSON.stringify(read.body.result),/alpha/);
  const largeRead=await call('i4-large-read','read_file',{path:largeFile,length:1000});
  const largeReadOperation=routerOperations.at(-1);
  const largeReadLedger=(()=>{
    try{return readFileSync(path.join(state,'i4-execution.jsonl'),'utf8').trim().split('\n')
      .filter(Boolean).map(line=>JSON.parse(line)).filter(record=>
        record.requestId===largeReadOperation?.requestId).map(record=>({
          type:record.type,status:record.status,tool:record.tool,requestId:record.requestId,
        }));}catch{return [];}
  })();
  const largeReadOperationState=largeReadOperation?.requestId
    ?pilot.operationState(largeReadOperation.requestId):null;
  assert.equal(largeRead.status,200,JSON.stringify({response:largeRead.body,
    operation:largeReadOperation&&{requestId:largeReadOperation.requestId,
      tool:largeReadOperation.tool,errorCode:largeReadOperation.errorCode??null,
      elapsedMs:largeReadOperation.finishedAt-largeReadOperation.startedAt},
    operationState:largeReadOperationState,ledger:largeReadLedger,
    worker:workerState,workerTrace:workerTrace.slice(-24),
    sessionLive:sessionId?registry.isLiveSession(deviceId,sessionId):false}));
  assert.ok(JSON.stringify(largeRead.body.result).includes(largeContent));
  const listingResponse=await call('i4-list-2','list_directory',{path:root,depth:1});
  assert.equal(listingResponse.status,200,JSON.stringify(listingResponse));
  const listing=JSON.parse(listingResponse.body.result.content?.[0]?.text??'{}');
  assert.ok(listing.entries?.some(entry=>entry.name==='readme.txt'));
  const target=path.join(root,'created.txt'),writeRequestId=randomUUID();
  const written=await call(writeRequestId,'write_file',{path:target,content:'created by I4\n',mode:'create'});
  assert.equal(written.status,200,JSON.stringify(written));
  assert.equal(written.body.result.structuredContent.created,true);
  assert.equal(readFileSync(target,'utf8'),'created by I4\n');
  const duplicate=await call(writeRequestId,'write_file',{path:target,content:'created by I4\n',mode:'create'});
  assert.equal(duplicate.body.result.isError,true);
  const command=await call('i4-command-3','run_command',{profile:'count_lines',path:file});
  assert.equal(command.body.result.structuredContent.exitCode,0);
  assert.match(command.body.result.structuredContent.stdout,/3/);
  const processes=await call('i4-processes-4','list_processes',{});
  assert.ok(processes.body.result.structuredContent.jobs.some(job=>job.profile==='count_lines'&&job.exitCode===0));
  policyRevision=grantStore.revoke(grantIds.write_file,{expectedRevision:policyRevision,
    eventId:randomUUID()}).revision;
  const denied=await call('i4-denied-write','write_file',{path:path.join(root,'denied.txt'),
    content:'should not dispatch',mode:'create'});
  assert.equal(denied.status,403);
  assert.equal(readFileSync(path.join(state,'i4-execution.jsonl'),'utf8').includes('should not dispatch'),false);
  const executionLedger=readFileSync(path.join(state,'i4-execution.jsonl'),'utf8');
  const firstIntent=JSON.parse(executionLedger.split('\n')[0]);
  assert.equal(firstIntent.type,'intent');
  assert.equal(firstIntent.authorization.claims.trustRevision,1);
  assert.equal(firstIntent.authorization.claims.policyRevision,policyRevision-1);
  assert.equal(firstIntent.authorization.claims.deviceId,deviceId);
  assert.equal(firstIntent.authorization.claims.fingerprint,identityFingerprint);
  assert.match(firstIntent.authorization.claims.ownerDigest,/^[a-f0-9]{64}$/);
  assert.doesNotMatch(executionLedger,/synthetic-owner-jwt|owner-i4|created by I4|alpha/);
  controller.abort();
  await running;
  assert.equal(clientClosed,true);
});
