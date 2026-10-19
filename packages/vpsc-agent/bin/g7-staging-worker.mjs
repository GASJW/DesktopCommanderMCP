#!/usr/bin/env node
import path from 'node:path';
import { request as httpsRequest } from 'node:https';
import { createHttpsAgentClient } from '../src/https-client.mjs';
import { loadOrCreateDeviceIdentity } from '../src/identity-store.mjs';
import { createGovernedAgentExecutor } from '../src/governed-executor.mjs';
import { createAgentWorker } from '../src/worker.mjs';
import { readPrivateStagingFile } from '../../../gateway/staging/private-file.mjs';
import { assertNotElevatedWindows, readPrivateWindowsFile } from '../src/windows-security.mjs';
import { parseStagingCommandLine } from '../../../gateway/staging/runtime-mode.mjs';

const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const TEST_SCENARIOS=new Set(['owner-cancel','grant-revoke','device-revoke']);
function emitFixture(event,fields={}){
  process.stdout.write(JSON.stringify({event,...fields,monotonicNs:process.hrtime.bigint().toString()})+'\n');
}
async function waitForFixtureAbort(signal){
  if(!signal)throw Error();
  if(signal.aborted)return;
  await new Promise(resolve=>{
    signal.addEventListener('abort',resolve,{once:true});
    if(signal.aborted)resolve();
  });
}
function safeFile(filename,{privateOnly=true}={}){
  return process.platform==='win32'
    ?readPrivateWindowsFile(filename,{privateOnly,maxBytes:1024*1024})
    :readPrivateStagingFile(filename,{privateOnly});
}
function parseConfig(filename){
  if(process.platform==='win32')assertNotElevatedWindows();
  else if(process.platform!=='linux'||typeof process.getuid!=='function'||process.getuid()===0)throw Error();
  const value=JSON.parse(safeFile(filename).toString('utf8'));
  const keys='allowedRoot,deviceId,hostname,identityDirectory,ledgerDirectory,mcpEntrypoint,port,policyPublicKeyPem,version,clientId,clientSecret,caPath,pollIntervalMs';
  if(!value||typeof value!=='object'||Array.isArray(value)||Object.getPrototypeOf(value)!==Object.prototype||
     Object.keys(value).sort().join(',')!==keys.split(',').sort().join(',')||value.version!==1||
     !UUID.test(value.deviceId??'')||typeof value.hostname!=='string'||
     !/^[a-z0-9.-]{6,255}$/.test(value.hostname)||!value.hostname.includes('.')||
     value.hostname==='localhost'||value.hostname.endsWith('.local')||
     !Number.isSafeInteger(value.port)||value.port<1||value.port>65535||
     typeof value.clientId!=='string'||!/^[A-Za-z0-9_.-]{8,256}$/.test(value.clientId)||
     typeof value.clientSecret!=='string'||value.clientSecret.length<24||/[\r\n\0]/.test(value.clientSecret)||
     ![value.allowedRoot,value.identityDirectory,value.ledgerDirectory,value.mcpEntrypoint,value.caPath]
       .every(item=>typeof item==='string'&&path.isAbsolute(item)&&path.normalize(item)===item)||
     typeof value.policyPublicKeyPem!=='string'||
     !Number.isSafeInteger(value.pollIntervalMs)||value.pollIntervalMs<25||value.pollIntervalMs>5000)throw Error();
  value.ca=safeFile(value.caPath,{privateOnly:false});
  return value;
}
function stagingFetch(config){
  return (input,options)=>new Promise((resolve,reject)=>{
    const url=new URL(input);
    if(url.protocol!=='https:'||url.hostname!==config.hostname||url.port||url.pathname==='/'||
       options.redirect!=='error'||options.credentials!=='omit'||options.cache!=='no-store'){
      reject(Error('staging destination denied'));return;
    }
    const headers={...options.headers,host:config.hostname};
    const request=httpsRequest({hostname:'127.0.0.1',port:config.port,servername:config.hostname,
      method:options.method,path:url.pathname,headers,ca:config.ca,rejectUnauthorized:true},response=>{
      const chunks=[];let size=0;
      response.on('data',chunk=>{size+=chunk.length;if(size>512*1024){request.destroy(Error('response limit'));return;}chunks.push(chunk);});
      response.on('end',()=>resolve(new Response(Buffer.concat(chunks,size),{
        status:response.statusCode,headers:response.headers,
      })));
    });
    const abort=()=>request.destroy(Error('staging request aborted'));
    if(options.signal?.aborted)abort();
    else options.signal?.addEventListener('abort',abort,{once:true});
    request.once('error',reject);
    request.once('close',()=>options.signal?.removeEventListener('abort',abort));
    request.end(options.body);
  });
}

let active;
let stopping=false;
async function stop(signal){
  if(stopping)return;
  stopping=true;
  active?.controller.abort();
  try{await active?.done;}
  catch(error){process.stderr.write(JSON.stringify({event:'WORKER_STOPPED',signal,
    code:/^[A-Z_]{1,48}$/.test(error?.code??'')?error.code:'WORKER_ERROR'})+'\n');}
}
try{
  const invocation=parseStagingCommandLine(process.argv.slice(2));
  const fixtureRequested=process.env.VPSC_STAGING_TEST_ACTIVE_JOB==='1';
  const fixtureScenario=process.env.VPSC_STAGING_TEST_SCENARIO;
  if(fixtureRequested&&(!process.env.NODE_TEST_CONTEXT||!TEST_SCENARIOS.has(fixtureScenario)))throw Error();
  if(!fixtureRequested&&fixtureScenario!==undefined)throw Error();
  const fixtureCall=async(method,operation,args)=>{
    try{
      const result=await operation(...args);
      if(fixtureRequested)emitFixture('FIXTURE_CLIENT_CALL',{method,outcome:'success',
        accepted:result?.accepted===true,status:result?.status??null,
        hasFrame:result?.frame!==undefined&&result?.frame!==null,
        hasCancel:result?.cancel!==undefined&&result?.cancel!==null});
      return result;
    }catch(error){
      if(fixtureRequested)emitFixture('FIXTURE_CLIENT_CALL',{method,outcome:'error',
        code:/^[A-Z_]{1,48}$/.test(error?.code??'')?error.code:'UNKNOWN'});
      throw error;
    }
  };
  const config=parseConfig(invocation.configPath);
  const identity=loadOrCreateDeviceIdentity({directory:config.identityDirectory,platform:process.platform});
  if(!identity.deviceBinding||identity.deviceBinding.deviceId!==config.deviceId||
     identity.deviceBinding.clientId!==config.clientId||identity.deviceBinding.fingerprint!==identity.fingerprint)
    throw Error();
  const client=createHttpsAgentClient({gatewayUrl:`https://${config.hostname}/`,
    expectedHostname:config.hostname,identity,deviceId:config.deviceId,clientId:config.clientId,
    clientSecret:config.clientSecret,fetchFn:stagingFetch(config)});
  let connected=false,online=false;
  const observedClient={
    connect:async(...args)=>{const session=await client.connect(...args);connected=true;
      process.stdout.write(JSON.stringify({event:'READY',deviceId:config.deviceId,pid:process.pid})+'\n');return session;},
    reconnect:async(...args)=>{const session=await client.reconnect(...args);connected=true;
      process.stdout.write(JSON.stringify({event:'RECONNECTED',deviceId:config.deviceId,pid:process.pid})+'\n');return session;},
    heartbeat:async(...args)=>{const value=await fixtureCall('heartbeat',client.heartbeat,args);
      if(!online){online=true;process.stdout.write(JSON.stringify({event:'ONLINE',deviceId:config.deviceId})+'\n');}
      return value;},poll:(...args)=>fixtureCall('poll',client.poll,args),
    pollControl:(...args)=>fixtureCall('pollControl',client.pollControl,args),
    result:(...args)=>fixtureCall('result',client.result,args),
    cancelAck:async(...args)=>{
      const acknowledgement=await fixtureCall('cancelAck',client.cancelAck,args);
      if(fixtureRequested)emitFixture('FIXTURE_CANCEL_ACK',{requestId:args[0]?.requestId,
        status:args[0]?.status,gatewayStatus:acknowledgement?.status??null,
        accepted:acknowledgement?.accepted===true});
      return acknowledgement;
    },disconnect:(...args)=>client.disconnect(...args),
    close:(...args)=>client.close(...args),
  };
  let activeRequestId=null,firstReadHeld=false;
  const baseExecutor=createGovernedAgentExecutor({allowedRoot:config.allowedRoot,
    entrypoint:config.mcpEntrypoint,ledgerDirectory:config.ledgerDirectory,
    deviceId:config.deviceId,fingerprint:identity.fingerprint,
    gatewayPolicyPublicKey:config.policyPublicKeyPem,gatewayNowMs:client.gatewayNowMs,
    ...(fixtureRequested?{testHooks:{sleepCommandForTimeout:true,
      onCommandSpawn:pid=>emitFixture('FIXTURE_JOB_STARTED',{pid,requestId:activeRequestId})}}:{})});
  const executor=fixtureRequested?{
    start:(...args)=>baseExecutor.start(...args),
    handle:async(frame,options={})=>{
      const requestId=frame?.requestId,tool=frame?.params?.name;
      const fixturePath=frame?.params?.arguments?.path;
      if(fixtureScenario==='owner-cancel'&&tool==='read_file'&&!firstReadHeld&&
         typeof fixturePath==='string'&&fixturePath.endsWith('/cancel-before-execution-probe.txt')){
        firstReadHeld=true;
        emitFixture('FIXTURE_OPERATION_RECEIVED',{requestId,tool});
        await waitForFixtureAbort(options.signal);
        emitFixture('FIXTURE_CANCEL_BEFORE_EXECUTION',{requestId});
      }
      activeRequestId=requestId;
      emitFixture('FIXTURE_OPERATION_DELIVERED',{requestId,tool});
      try{return await baseExecutor.handle(frame,options);}
      finally{activeRequestId=null;}
    },
    close:(...args)=>baseExecutor.close(...args),
  }:baseExecutor;
  const worker=createAgentWorker({deviceId:config.deviceId,client:observedClient,executor,
    pollIntervalMs:config.pollIntervalMs});
  const controller=new AbortController();
  const done=worker.run({signal:controller.signal});
  active={controller,done};
  done.then(result=>{
    if(result?.status==='stopped')process.stdout.write(JSON.stringify({event:'STOPPED',connected})+'\n');
  },error=>{
    process.stderr.write(JSON.stringify({event:'WORKER_FAILED',
      code:/^[A-Z_]{1,48}$/.test(error?.code??'')?error.code:'WORKER_ERROR'})+'\n');
    process.exitCode=1;
  });
  process.once('SIGTERM',()=>void stop('SIGTERM'));
  process.once('SIGINT',()=>void stop('SIGINT'));
}catch(error){
  process.stderr.write(JSON.stringify({event:'STARTUP_FAILED',code:
    error?.code==='TEST_FIXTURE_ENVIRONMENT'?'TEST_FIXTURE_ENVIRONMENT':'CONFIG_OR_IDENTITY'})+'\n');
  process.exitCode=1;
}
