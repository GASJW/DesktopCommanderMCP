import { createHmac, createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { createConnection, createServer } from 'node:net';
import { request as httpsRequest } from 'node:https';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { bindApprovedDeviceIdentity, loadOrCreateDeviceIdentity } from '../src/identity-store.mjs';
import { analyzeI4ExecutionRecovery } from '../src/governed-executor.mjs';
import { assertNotElevatedWindows, securePrivateWindowsDirectory,
  securePrivateWindowsFile, readWindowsFileBeneath, verifyWindowsOperationRoot } from '../src/windows-security.mjs';

const ROOT=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../../..');
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CLIENT=/^[A-Za-z0-9_.-]{8,256}$/;
const emit=value=>process.stdout.write(JSON.stringify(value)+'\n');
const idArg=process.argv.indexOf('--run-id');
const runId=process.argv[idArg+1];
let home,identity,identityDirectory,ledgerDirectory,allowedRoot,proofFile,cancelFile,outsideFile;
let configPath,config,relay,worker,relaySockets=new Set(),forwardSecret;

function privateDirectory(directory){mkdirSync(directory,{recursive:true});securePrivateWindowsDirectory(directory);}
function reply(command,value){emit({type:'response',id:command.id,ok:true,...value});}
function failure(command,error){reply(command,{ok:false,code:/^[A-Z_]{1,64}$/.test(error?.code??'')?error.code:'CONTROLLER'});}
function waitForExit(child,timeoutMs=8000){
  return new Promise((resolve,reject)=>{
    if(child.exitCode!==null||child.signalCode!==null)return resolve({code:child.exitCode,signal:child.signalCode});
    const timer=setTimeout(()=>{try{child.kill('SIGKILL');}catch{};reject(new Error('Worker shutdown timed out'));},timeoutMs);
    child.once('exit',(code,signal)=>{clearTimeout(timer);resolve({code,signal});});
  });
}
async function stopWorker(){
  if(!worker)return {stopped:true};
  const current=worker;worker=null;
  try{current.kill('SIGTERM');}catch{}
  return {stopped:true,...await waitForExit(current)};
}
function forward(local){
  local.pause();
  const upstream=createConnection({host:config.forwardHost,port:config.forwardPort});
  relaySockets.add(local);relaySockets.add(upstream);
  const cleanup=()=>{relaySockets.delete(local);relaySockets.delete(upstream);};
  local.once('close',cleanup);upstream.once('close',cleanup);
  let buffered=Buffer.alloc(0),phase='challenge';
  const reject=()=>{local.destroy();upstream.destroy();};
  const onData=chunk=>{
    buffered=Buffer.concat([buffered,chunk]);
    if(phase==='challenge'){
      if(buffered.length<32)return;
      if(buffered.length!==32){reject();return;}
      const challenge=buffered;buffered=Buffer.alloc(0);phase='ack';
      upstream.write(createHmac('sha256',forwardSecret).update(challenge).digest());
      return;
    }
    if(phase==='ack'){
      if(buffered.length<1)return;
      if(buffered[0]!==1||buffered.length!==1){reject();return;}
      buffered=Buffer.alloc(0);phase='stream';upstream.removeListener('data',onData);
      local.pipe(upstream);upstream.pipe(local);local.resume();
    }
  };
  upstream.on('data',onData);upstream.once('error',reject);local.once('error',reject);
}
function startRelay(){
  if(relay)return Promise.resolve(relay.address().port);
  relay=createServer(forward);
  return new Promise((resolve,reject)=>{
    relay.once('error',reject);relay.listen(0,'127.0.0.1',()=>resolve(relay.address().port));
  });
}
function stopRelay(){
  for(const socket of relaySockets)socket.destroy();relaySockets.clear();
  if(!relay)return Promise.resolve();
  const server=relay;relay=null;
  return new Promise(resolve=>server.close(()=>resolve()));
}
function startWorker(){
  if(worker)throw Object.assign(new Error('Worker already active'),{code:'WORKER_STATE'});
  const env={};
  for(const key of ['PATH','SystemRoot','SystemDrive','ComSpec','LOCALAPPDATA','APPDATA','USERPROFILE','TEMP','TMP']){
    if(typeof process.env[key]==='string')env[key]=process.env[key];
  }
  env.NODE_TEST_CONTEXT='windows-network-e2e';
  env.VPSC_STAGING_TEST_ACTIVE_JOB='1';
  env.VPSC_STAGING_TEST_SCENARIO='owner-cancel';
  env.VPSC_WINDOWS_SECURITY_TEST_DIAGNOSTICS='1';
  const child=spawn(process.execPath,[path.join(ROOT,'packages','vpsc-agent','bin','g7-staging-worker.mjs'),
    '--config',configPath],{cwd:ROOT,stdio:['ignore','pipe','pipe'],windowsHide:true,env});
  worker=child;
  let output='';
  child.stdout.setEncoding('utf8').on('data',chunk=>{
    output+=chunk;
    while(true){const end=output.indexOf('\n');if(end<0)break;
      const line=output.slice(0,end);output=output.slice(end+1);
      try{const event=JSON.parse(line);if(event&&typeof event.event==='string')emit({type:'worker',event});}catch{}
    }
  });
  let stderr='';
  child.stderr.setEncoding('utf8').on('data',chunk=>{
    stderr+=chunk;
    while(true){
      const end=stderr.indexOf('\n');if(end<0)break;
      const line=stderr.slice(0,end);stderr=stderr.slice(end+1);
      try{
        const value=JSON.parse(line);
        if(['STARTUP_FAILED','WORKER_FAILED','WORKER_STOPPED'].includes(value.event)){
          emit({type:'worker_stderr',event:value.event,
            ...(typeof value.code==='string'&&/^[A-Z_]{1,48}$/.test(value.code)?{code:value.code}:{})});
        }
      }catch{}
    }
  });
  child.once('exit',(code,signal)=>{if(worker===child)worker=null;emit({type:'worker_exit',code,signal});});
  return child.pid;
}

function httpsProbe({serverName,ca,clientId,clientSecret,deviceId}){
  const payload=Buffer.from(JSON.stringify({deviceId}));
  return new Promise(resolve=>{
    const request=httpsRequest({hostname:'127.0.0.1',port:config.localPort,servername:serverName,
      method:'POST',path:'/agent/challenge',ca,rejectUnauthorized:true,headers:{host:config.hostname,
        'content-type':'application/json','content-length':payload.length,
        'cf-access-client-id':clientId,'cf-access-client-secret':clientSecret}},response=>{
      response.resume();response.once('end',()=>resolve({tls:'accepted',status:response.statusCode}));
    });
    request.once('error',error=>resolve({tls:'rejected',code:/^[A-Z0-9_]{1,64}$/.test(error?.code??'')
      ?error.code:'TLS_ERROR'}));
    request.setTimeout(5000,()=>request.destroy(Object.assign(new Error('probe timeout'),{code:'TIMEOUT'})));
    request.end(payload);
  });
}

async function cleanup(){
  await stopWorker().catch(()=>{});await stopRelay().catch(()=>{});
  forwardSecret?.fill(0);forwardSecret=null;
  if(home)rmSync(home,{recursive:true,force:true});
}

if(process.platform!=='win32'||!UUID.test(runId??''))process.exit(2);
try{
  assertNotElevatedWindows();
  home=path.join(os.tmpdir(),`vpsc-i8i-native-${runId}`);privateDirectory(home);
  identityDirectory=path.join(home,'identity');ledgerDirectory=path.join(home,'ledger');
  allowedRoot=path.join(home,'approved');
  for(const directory of [identityDirectory,ledgerDirectory,allowedRoot])privateDirectory(directory);
  allowedRoot=verifyWindowsOperationRoot(allowedRoot);
  identity=loadOrCreateDeviceIdentity({directory:identityDirectory,platform:'win32'});
  const contents=Buffer.from(`I8 native Windows proof ${runId}\n`,'utf8');
  proofFile=path.join(allowedRoot,'proof.txt');
  cancelFile=path.join(allowedRoot,'cancel-before-execution-probe.txt');
  outsideFile=path.join(home,'outside.txt');
  for(const filename of [proofFile,cancelFile,outsideFile]){
    writeFileSync(filename,contents,{flag:'wx',mode:0o600});securePrivateWindowsFile(filename);
  }
  emit({type:'identity',publicKeyPem:identity.publicKeyPem,fingerprint:identity.fingerprint,
    allowedRoot,proofFile,cancelFile,outsideFile,proofBytes:contents.length,
    proofSha256:createHash('sha256').update(contents).digest('hex'),identityDirectory,ledgerDirectory});
}catch(error){
  emit({type:'fatal',code:/^[A-Z_]{1,64}$/.test(error?.code??'')?error.code:'WINDOWS_SETUP'});
  await cleanup().catch(()=>{});process.stdin.destroy();process.exitCode=1;
}

async function handle(command){
  try{
    if(!command||typeof command!=='object'||typeof command.id!=='string')throw new Error('Invalid command');
    if(command.op==='prove'){
      reply(command,{proof:identity.prove(command.challenge)});return;
    }
    if(command.op==='bind'){
      identity=bindApprovedDeviceIdentity({directory:identityDirectory,platform:'win32',
        machineBinding:command.machineBinding});
      if(identity.deviceBinding?.fingerprint!==identity.fingerprint||
         identity.deviceBinding?.deviceId!==command.machineBinding.deviceId){
        throw Object.assign(new Error('Identity binding mismatch'),{code:'BINDING_MISMATCH'});
      }
      reply(command,{bound:true,fingerprint:identity.fingerprint,deviceId:identity.deviceBinding.deviceId});return;
    }
    if(command.op==='start'){
      const {deviceId,clientId,clientSecret,hostname,caPem,policyPublicKeyPem,mcpEntrypoint,
        forwardHost,forwardPort,hmacSecret}=command;
      if(identity?.deviceBinding?.deviceId!==deviceId||identity.deviceBinding.clientId!==clientId||
         identity.deviceBinding.fingerprint!==identity.fingerprint||!UUID.test(deviceId??'')||
         !CLIENT.test(clientId??'')||typeof clientSecret!=='string'||clientSecret.length<24||
         typeof hostname!=='string'||typeof caPem!=='string'||typeof policyPublicKeyPem!=='string'||
         !path.isAbsolute(mcpEntrypoint??'')||
         !/^172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}$|^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$|^192\.168\.\d{1,3}\.\d{1,3}$/.test(forwardHost??'')||
         !Number.isSafeInteger(forwardPort)||forwardPort<1||forwardPort>65535){
        throw Object.assign(new Error('Invalid private worker profile'),{code:'CONFIG'});
      }
      forwardSecret=Buffer.from(hmacSecret??'','base64url');
      if(forwardSecret.length!==32)throw Object.assign(new Error('Invalid relay key'),{code:'RELAY_KEY'});
      const localPort=await startRelay();
      const caPath=path.join(home,'gateway-ca.pem');configPath=path.join(home,'agent.json');
      writeFileSync(caPath,caPem,{flag:'wx',mode:0o600});securePrivateWindowsFile(caPath);
      config={version:1,deviceId,hostname,caPem,identityDirectory,ledgerDirectory,mcpEntrypoint,
        port:localPort,policyPublicKeyPem,clientId,clientSecret,caPath,allowedRoot,pollIntervalMs:35,
        forwardHost,forwardPort,localPort};
      writeFileSync(configPath,JSON.stringify({version:config.version,deviceId:config.deviceId,
        hostname:config.hostname,identityDirectory:config.identityDirectory,ledgerDirectory:config.ledgerDirectory,
        mcpEntrypoint:config.mcpEntrypoint,port:config.port,policyPublicKeyPem:config.policyPublicKeyPem,
        clientId:config.clientId,clientSecret:config.clientSecret,caPath:config.caPath,
        allowedRoot:config.allowedRoot,pollIntervalMs:config.pollIntervalMs})+'\n',{flag:'wx',mode:0o600});
      securePrivateWindowsFile(configPath);
      const pid=startWorker();
      emit({type:'relay_ready',localHost:'127.0.0.1',localPort,forwardHost,forwardPort,
        tlsHostname:hostname,caSha256:createHash('sha256').update(caPem).digest('hex')});
      reply(command,{started:true,pid,localPort,identityFingerprint:identity.fingerprint,
        bindingRevision:identity.deviceBinding.bindingRevision});return;
    }
    if(command.op==='probe'){
      let result;
      if(command.kind==='hostname')result=await httpsProbe({serverName:'wrong-i8i.example.test',
        ca:config.caPem,clientId:config.clientId,clientSecret:config.clientSecret,deviceId:config.deviceId});
      else if(command.kind==='ca')result=await httpsProbe({serverName:config.hostname,
        ca:command.caPem,clientId:config.clientId,clientSecret:config.clientSecret,deviceId:config.deviceId});
      else if(command.kind==='credentials')result=await httpsProbe({serverName:config.hostname,
        ca:config.caPem,clientId:`${config.clientId}.wrong`,clientSecret:'synthetic-invalid-credential',
        deviceId:config.deviceId});
      else throw new Error('Invalid probe');
      reply(command,result);return;
    }
    if(command.op==='stop_worker'){
      reply(command,await stopWorker());return;
    }
    if(command.op==='restart_worker'){
      const pid=startWorker();reply(command,{started:true,pid});return;
    }
    if(command.op==='ledger'){
      const state=analyzeI4ExecutionRecovery({ledgerDirectory});
      let records=[];
      const ledgerPath=path.join(ledgerDirectory,'i4-execution.jsonl');
      if(existsSync(ledgerPath))records=readFileSync(ledgerPath,'utf8').trim().split(/\r?\n/)
        .filter(Boolean).map(line=>JSON.parse(line));
      reply(command,{status:state.status,recordCount:state.recordCount,
        unresolvedCount:state.unresolved.length,ambiguousCount:state.ambiguous.length,
        automaticReplay:state.automaticReplay,automaticLockRemoval:state.automaticLockRemoval,
        ...(typeof command.requestId==='string'?{requestRecords:records.filter(record=>
          record.requestId===command.requestId).map(record=>({type:record.type,status:record.status??null,
            tool:record.tool??null}))}:{})});return;
    }
    if(command.op==='identity'){
      const current=loadOrCreateDeviceIdentity({directory:identityDirectory,platform:'win32'});
      const binding=current.deviceBinding;
      reply(command,{fingerprint:current.fingerprint,deviceId:binding?.deviceId??null,
        clientId:binding?.clientId??null,bindingRevision:binding?.bindingRevision??null});return;
    }
    if(command.op==='proof-diagnostics'){
      const disk=readFileSync(proofFile),secure=readWindowsFileBeneath(allowedRoot,proofFile,{maxBytes:4096});
      reply(command,{diskBytes:disk.length,diskSha256:createHash('sha256').update(disk).digest('hex'),
        secureBytes:secure.length,secureSha256:createHash('sha256').update(secure).digest('hex')});return;
    }
    if(command.op==='cleanup'){
      await cleanup();reply(command,{cleaned:true});process.exitCode=0;process.stdin.destroy();return;
    }
    throw new Error('Unsupported command');
  }catch(error){failure(command,error);}
}

const input=createInterface({input:process.stdin,crlfDelay:Infinity});
for await(const line of input){let command;try{command=JSON.parse(line);}catch{continue;}await handle(command);}
await cleanup();
