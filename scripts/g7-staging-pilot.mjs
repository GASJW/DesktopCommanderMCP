#!/usr/bin/env node
import { spawn, execFileSync } from 'node:child_process';
import { createInterface } from 'node:readline';
import { once } from 'node:events';
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync,
  rmSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { request as httpsRequest } from 'node:https';
import { createHash, generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import { loadOrCreateDeviceIdentity, bindApprovedDeviceIdentity } from '../packages/vpsc-agent/src/identity-store.mjs';
import { analyzeI4ExecutionRecovery } from '../packages/vpsc-agent/src/governed-executor.mjs';
import { analyzeOwnerPairingRecovery, reconcileOwnerPairingRecovery }
  from '../gateway/dashboard/owner-pairing-reconciliation.mjs';

const ROOT=fileURLToPath(new URL('../',import.meta.url));
const HOST='g7-staging.test';
const CLIENT='g7-staging-agent.synthetic';
const OWNER_ISSUER='https://g7-owner-staging.cloudflareaccess.com';
const MACHINE_ISSUER='https://g7-machine-staging.cloudflareaccess.com';
const OWNER_AUD='a'.repeat(64),MACHINE_AUD='b'.repeat(64);
const OWNER_EMAIL='g7-staging-owner@example.test',OWNER_SUBJECT='synthetic-staging-owner';
const DISPLAYED_READ='G7 standalone staging real MCP read\n';
const TEST_ACTIVE_JOB_SCENARIOS=new Set(['owner-cancel','grant-revoke','device-revoke']);
const FIXTURE_COMMAND_TIMEOUT_MS=10_000;
const trace=message=>{if(process.env.VPSC_STAGING_TRACE==='1')process.stderr.write(`[g7-staging] ${message}\n`);};
function ensure(condition,message){if(!condition)throw Error(message);}
function modeDir(dir){mkdirSync(dir,{recursive:true,mode:0o700});chmodSync(dir,0o700);}
function privateJson(filename,value){writeFileSync(filename,JSON.stringify(value)+'\n',{mode:0o600,flag:'wx'});chmodSync(filename,0o600);}
function replacePrivateJson(filename,value){
  const stat=statSync(filename);
  ensure(stat.isFile()&&(stat.mode&0o077)===0,'staging config lost private permissions');
  writeFileSync(filename,JSON.stringify(value)+'\n',{mode:0o600,flag:'w'});chmodSync(filename,0o600);
}
function rsa(kid){
  const {privateKey,publicKey}=generateKeyPairSync('rsa',{modulusLength:2048});
  return {privateKey,jwk:{...publicKey.export({format:'jwk'}),kid,alg:'RS256'}};
}
function makeJwt(privateKey,kid,claims){
  const header=Buffer.from(JSON.stringify({alg:'RS256',kid})).toString('base64url');
  const body=Buffer.from(JSON.stringify(claims)).toString('base64url');
  return `${header}.${body}.${sign('RSA-SHA256',Buffer.from(`${header}.${body}`),privateKey).toString('base64url')}`;
}
function ownerToken(owner){
  const now=Math.floor(Date.now()/1000);
  return makeJwt(owner.privateKey,owner.jwk.kid,{iss:OWNER_ISSUER,aud:OWNER_AUD,
    email:OWNER_EMAIL,sub:OWNER_SUBJECT,iat:now-1,exp:now+3600});
}
function machineConfig(machine,privateKeyPath,secret){
  return {issuer:MACHINE_ISSUER,audience:MACHINE_AUD,clientId:CLIENT,jwks:[machine.jwk],
    signingKeyPath:privateKeyPath,serviceSecret:secret};
}
function waitForEvent(proc,event,timeoutMs=15_000){
  if(proc.events.some(value=>value.event===event))return Promise.resolve(proc.events.find(value=>value.event===event));
  return new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>{proc.waiters.delete(onEvent);reject(Error(`${event} timeout`));},timeoutMs);
    const onEvent=value=>{if(value.event!==event)return;clearTimeout(timer);proc.waiters.delete(onEvent);resolve(value);};
    proc.waiters.add(onEvent);
    proc.exited.then(code=>{if(code!==null){clearTimeout(timer);proc.waiters.delete(onEvent);reject(Error(`${event} process exited ${code}: ${proc.stderrText}`));}});
  });
}
function waitForMatchingEvent(proc,event,predicate,timeoutMs=15_000){
  const existing=proc.events.find(value=>value.event===event&&predicate(value));
  if(existing)return Promise.resolve(existing);
  return new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>{proc.waiters.delete(onEvent);reject(Error(`${event} timeout`));},timeoutMs);
    const onEvent=value=>{
      if(value.event!==event||!predicate(value))return;
      clearTimeout(timer);proc.waiters.delete(onEvent);resolve(value);
    };
    proc.waiters.add(onEvent);
    proc.exited.then(code=>{if(code!==null){clearTimeout(timer);proc.waiters.delete(onEvent);
      const fixtureEvents=proc.events.filter(value=>String(value.event).startsWith('FIXTURE_'));
      reject(Error(`${event} process exited ${code}: ${proc.stderrText}; `+
        `fixture=${JSON.stringify(fixtureEvents).slice(-1600)}`));}});
  });
}
function startProcess(script,args,{cwd=ROOT,home,tmp,testActiveJob=false}={}){
  const env={PATH:'/usr/bin:/bin',HOME:home,TMPDIR:tmp,LANG:'C.UTF-8'};
  if(testActiveJob){
    if(!process.env.NODE_TEST_CONTEXT||process.env.VPSC_STAGING_TEST_ACTIVE_JOB!=='1'||
       !TEST_ACTIVE_JOB_SCENARIOS.has(process.env.VPSC_STAGING_TEST_SCENARIO))
      throw Error('Test active-job fixture is available only to the Node test runner');
    env.NODE_TEST_CONTEXT=process.env.NODE_TEST_CONTEXT;
    env.VPSC_STAGING_TEST_ACTIVE_JOB='1';
    env.VPSC_STAGING_TEST_SCENARIO=process.env.VPSC_STAGING_TEST_SCENARIO;
  }
  const child=spawn(process.execPath,[script,...args],{cwd,detached:true,shell:false,
    stdio:['ignore','pipe','pipe'],env});
  const proc={child,events:[],waiters:new Set(),stderrText:''};
  const lines=createInterface({input:child.stdout,crlfDelay:Infinity});
  lines.on('line',line=>{
    let value;try{value=JSON.parse(line);}catch{return;}
    proc.events.push(value);
    if(process.env.VPSC_STAGING_TRACE==='1')trace(`child pid=${child.pid} ${value.event??'message'}${value.code?` (${value.code})`:''}`);
    for(const waiter of [...proc.waiters])waiter(value);
  });
  child.stderr.setEncoding('utf8').on('data',chunk=>{proc.stderrText=(proc.stderrText+chunk).slice(-4096);});
  proc.exited=once(child,'exit').then(([code,signal])=>{proc.exitCode=code;proc.signal=signal;return code;});
  return proc;
}
function processRows(){
  const rows=[];
  for(const entry of readdirSync('/proc')){
    if(!/^\d+$/.test(entry))continue;
    const pid=Number(entry);
    try{
      const stat=readFileSync(`/proc/${entry}/stat`,'utf8');
      const end=stat.lastIndexOf(')');
      const fields=stat.slice(end+1).trim().split(/\s+/);
      const uid=Number(readFileSync(`/proc/${entry}/status`,'utf8').match(/^Uid:\s+(\d+)/m)?.[1]);
      if(Number.isSafeInteger(uid)&&fields.length>19){
        rows.push({pid,uid,state:fields[0],ppid:Number(fields[1]),pgid:Number(fields[2]),
          startTime:fields[19]});
      }
    }catch{}
  }
  return rows;
}
function processTree(rootPid){
  const rows=processRows(),byParent=new Map();
  for(const row of rows){const list=byParent.get(row.ppid)??[];list.push(row);byParent.set(row.ppid,list);}
  const root=rows.find(row=>row.pid===rootPid),found=[];
  if(!root)return found;
  const queue=[root],seen=new Set([rootPid]);
  while(queue.length){
    const row=queue.shift();found.push(row);
    for(const child of byParent.get(row.pid)??[]){
      if(child.uid===process.getuid()&&!seen.has(child.pid)){seen.add(child.pid);queue.push(child);}
    }
  }
  return found;
}
function processStillLive(expected){
  const row=processRows().find(item=>item.pid===expected.pid&&item.startTime===expected.startTime);
  return Boolean(row&&row.state!=='Z'&&row.state!=='X');
}
function fixedSleepProcess(pid,agentPid){
  const row=processRows().find(item=>item.pid===pid);
  if(!row||row.state==='Z'||row.state==='X'||row.uid!==process.getuid()||
     row.ppid!==agentPid||row.pgid!==pid)return null;
  let args;
  try{args=readFileSync(`/proc/${pid}/cmdline`).toString('utf8').split('\0').filter(Boolean);}
  catch{return null;}
  if(args.length!==2||args[0]!=='/usr/bin/sleep'||args[1]!=='30')return null;
  return row;
}
async function waitForProcessExit(expected,timeoutMs=5000){
  const deadline=Date.now()+timeoutMs;
  while(Date.now()<deadline){
    if(!processStillLive(expected))return true;
    await new Promise(resolve=>setTimeout(resolve,25));
  }
  return !processStillLive(expected);
}
function processGroupHasLiveMember(group){
  return processRows().some(row=>row.uid===process.getuid()&&row.pgid===group&&
    row.state!=='Z'&&row.state!=='X');
}
async function stopProcess(proc,signal='SIGTERM'){
  if(!proc||proc.stopVerified)return true;
  const groupRows=processRows().filter(row=>row.uid===process.getuid()&&row.pgid===proc.child.pid);
  const captured=new Map();
  for(const row of [...processTree(proc.child.pid),...groupRows])
    captured.set(`${row.pid}:${row.startTime}`,row);
  const expected=[...captured.values()];
  const selfGroup=processRows().find(row=>row.pid===process.pid)?.pgid;
  const groups=new Set([proc.child.pid,...expected.map(row=>row.pgid)]);
  if(groups.has(selfGroup))throw Error('Refusing to signal the staging pilot process group');
  const signalGroups=kind=>{for(const group of groups){try{process.kill(-group,kind);}catch{}}};
  const childExited=()=>proc.child.exitCode!==null||proc.child.signalCode!==null;
  const settled=()=>childExited()&&expected.every(item=>!processStillLive(item))&&
    [...groups].every(group=>!processGroupHasLiveMember(group));
  if(process.env.VPSC_STAGING_TRACE==='1')trace(`stopping pid=${proc.child.pid} signal=${signal} groups=${[...groups].join(',')}`);
  signalGroups(signal);
  const deadline=Date.now()+8000;
  while(Date.now()<deadline){
    if(settled()){
      proc.stopVerified=true;return true;
    }
    await new Promise(resolve=>setTimeout(resolve,25));
  }
  signalGroups('SIGKILL');
  const hardDeadline=Date.now()+8000;
  while(Date.now()<hardDeadline){
    if(settled()){proc.stopVerified=true;return true;}
    await new Promise(resolve=>setTimeout(resolve,25));
  }
  const liveGroups=[...groups].filter(group=>processGroupHasLiveMember(group));
  const survivors=processRows().filter(row=>groups.has(row.pgid)&&row.uid===process.getuid()&&
    row.state!=='Z'&&row.state!=='X').map(row=>`${row.pid}:${row.pgid}:${row.state}`);
  throw Error(`Staging process group did not stop (pid=${proc.child.pid}, exit=${proc.child.exitCode}, `+
    `groups=${liveGroups.join(',')||'none'}, survivors=${survivors.join(',')||'none'})`);
}
function tlsRequest({port,ca,pathname,method='GET',headers={},body,signal}){
  return new Promise((resolve,reject)=>{
    const req=httpsRequest({hostname:'127.0.0.1',port,servername:HOST,method,path:pathname,
      headers:{host:HOST,...headers},ca,rejectUnauthorized:true},res=>{
      const chunks=[];let bytes=0;
      res.on('data',chunk=>{bytes+=chunk.length;if(bytes>1024*1024){req.destroy(Error('response limit'));return;}chunks.push(chunk);});
      res.on('end',()=>{
        const text=Buffer.concat(chunks,bytes).toString('utf8');let json=null;
        try{json=text?JSON.parse(text):null;}catch{}
        resolve({status:res.statusCode,headers:res.headers,text,json});
      });
    });
    const abort=()=>req.destroy(Object.assign(Error('aborted'),{name:'AbortError'}));
    if(signal?.aborted)abort();else signal?.addEventListener('abort',abort,{once:true});
    req.once('error',reject);req.once('close',()=>signal?.removeEventListener('abort',abort));
    req.end(body);
  });
}
function post(port,ca,pathname,payload,{headers={},signal}={}){
  return tlsRequest({port,ca,pathname,method:'POST',headers:{'content-type':'application/json',...headers},
    body:JSON.stringify(payload),signal});
}
async function health(port,ca){return tlsRequest({port,ca,pathname:'/healthz'});}
async function waitHealth(port,ca){
  const deadline=Date.now()+10_000;
  while(Date.now()<deadline){try{const value=await health(port,ca);if(value.status===200)return value.json;}catch{}await new Promise(r=>setTimeout(r,50));}
  throw Error('staging health timeout');
}
function assertMcpOk(response,label){
  ensure(response.status===200,`${label} HTTP ${response.status} ${JSON.stringify(response.json??response.text)}`);
  ensure(response.json&&response.json.jsonrpc==='2.0',`${label} invalid MCP response`);
  return response.json;
}
async function runPilot(){
  if(process.platform!=='linux'||typeof process.getuid!=='function'||process.getuid()===0)
    throw Error('Run the staging pilot as a nonroot Linux user');
  const fixtureRequested=process.env.VPSC_STAGING_TEST_ACTIVE_JOB==='1';
  const activeJobScenario=process.env.VPSC_STAGING_TEST_SCENARIO;
  if(fixtureRequested&&(!process.env.NODE_TEST_CONTEXT||!TEST_ACTIVE_JOB_SCENARIOS.has(activeJobScenario)))
    throw Error('Active-job scenarios are available only to the Node test runner');
  if(!fixtureRequested&&activeJobScenario!==undefined)throw Error('Staging test scenario denied');
  const mcpEntrypoint=process.env.VPSC_STAGING_MCP_ENTRYPOINT;
  if(!mcpEntrypoint||!path.isAbsolute(mcpEntrypoint)||path.normalize(mcpEntrypoint)!==mcpEntrypoint||
     !existsSync(mcpEntrypoint))
    throw Error('Set VPSC_STAGING_MCP_ENTRYPOINT to a built Desktop Commander dist/index.js');
  const entryStat=lstatSync(mcpEntrypoint);
  if(!entryStat.isFile()||entryStat.isSymbolicLink()||entryStat.nlink!==1||
     (entryStat.mode&0o022)!==0)throw Error('Desktop Commander entrypoint is not a safe regular file');
  // Prefer the caller's private temp parent; this host intentionally keeps
  // /tmp inaccessible to unprivileged users, so use sticky /var/tmp otherwise.
  const scratch=mkdtempSync(path.join(process.env.TMPDIR||'/var/tmp','g7-i5a-'));
  chmodSync(scratch,0o700);
  trace('private scratch created');
  const gatewayHome=path.join(scratch,'gateway-home'),agentHome=path.join(scratch,'agent-home');
  const ownerClientHome=path.join(scratch,'owner-client-home');
  const gatewayTmp=path.join(scratch,'gateway-tmp'),agentTmp=path.join(scratch,'agent-tmp');
  const ownerClientTmp=path.join(scratch,'owner-client-tmp');
  for(const dir of [gatewayHome,agentHome,ownerClientHome,gatewayTmp,agentTmp,ownerClientTmp])modeDir(dir);
  let gatewayProc,agentProc,agentRestartProc,gatewayRestartProc;
  const allProcesses=[];
  const launchProcess=(script,args,options)=>{
    const proc=startProcess(script,args,options);allProcesses.push(proc);return proc;
  };
  let gatewayPort=null,report;
  try{
    const dirs={};
    for(const name of ['audit','trust','bindings','grants','policy','identity','ledger']){
      dirs[name]=path.join(scratch,name);modeDir(dirs[name]);
    }
    dirs['allowed-root']=path.join(scratch,'g7-staging-approved-root');modeDir(dirs['allowed-root']);
    const inputFile=path.join(dirs['allowed-root'],'approved.txt');
    writeFileSync(inputFile,DISPLAYED_READ,{mode:0o600,flag:'wx'});
    const owner=rsa('g7-staging-owner-i5d-pilot'),machine=rsa('g7-staging-machine');
    const policy=generateKeyPairSync('ed25519');
    const tlsDir=path.join(scratch,'tls');modeDir(tlsDir);
    const tlsKey=path.join(tlsDir,'staging.key'),tlsCert=path.join(tlsDir,'staging.crt');
    execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-days','1',
      '-subj',`/CN=${HOST}`,'-addext',`subjectAltName=DNS:${HOST}`,
      '-keyout',tlsKey,'-out',tlsCert],{stdio:'ignore'});
    chmodSync(tlsKey,0o600);chmodSync(tlsCert,0o600);
    const machinePrivate=path.join(scratch,'machine-signing.key');
    writeFileSync(machinePrivate,machine.privateKey.export({format:'pem',type:'pkcs8'}),{mode:0o600,flag:'wx'});
    const controlToken=randomUUID().replaceAll('-','')+randomUUID().replaceAll('-','');
    const serviceSecret=randomUUID().replaceAll('-','')+randomUUID().replaceAll('-','');
    const gatewayConfigPath=path.join(scratch,'gateway.json');
    const agentConfigPath=path.join(scratch,'agent.json');
    const ownerSigningKeyPath=path.join(ownerClientHome,'owner-signing.key');
    writeFileSync(ownerSigningKeyPath,owner.privateKey.export({format:'pem',type:'pkcs8'}),
      {mode:0o600,flag:'wx'});
    const ownerClientConfigPath=path.join(ownerClientHome,'owner-client.json');
    const ownerPrincipal={issuer:OWNER_ISSUER,subject:OWNER_SUBJECT};
    const ownerDigest=createHash('sha256').update('VPSC-I4-OWNER-v1\n')
      .update(JSON.stringify([OWNER_ISSUER,OWNER_SUBJECT])).digest('hex');
    privateJson(gatewayConfigPath,{version:1,hostname:HOST,listen:{host:'127.0.0.1',port:0},
      tls:{keyPath:tlsKey,certificatePath:tlsCert},
      owner:{issuer:OWNER_ISSUER,audience:OWNER_AUD,email:OWNER_EMAIL,subject:OWNER_SUBJECT,
        origin:`https://${HOST}`,controlToken,jwks:[owner.jwk]},
      machine:machineConfig(machine,machinePrivate,serviceSecret),
      policy:{directory:dirs.policy,privateKeyPem:policy.privateKey.export({format:'pem',type:'pkcs8'}),
        publicKeyPem:policy.publicKey.export({format:'pem',type:'spki'})},
      storage:{auditDirectory:dirs.audit,trustDirectory:dirs.trust,
        bindingDirectory:dirs.bindings,grantDirectory:dirs.grants}});
    const ownerJwt=ownerToken(owner);
    const authHeaders={'cf-access-jwt-assertion':ownerJwt};
    const controlHeaders={...authHeaders,'origin':`https://${HOST}`,'x-vpsc-stage-control':controlToken};
    gatewayProc=launchProcess(path.join(ROOT,'gateway/staging/server.mjs'),['--config',gatewayConfigPath],
      {home:gatewayHome,tmp:gatewayTmp});
    const gatewayReady=await waitForEvent(gatewayProc,'READY');gatewayPort=gatewayReady.port;
    trace('Gateway process ready');
    const initialHealth=await waitHealth(gatewayPort,readFileSync(tlsCert));
    ensure(initialHealth.trustRevision===0&&initialHealth.policyRevision===0,'fresh Gateway state was not empty');

    const invalidOwner=await post(gatewayPort,readFileSync(tlsCert),'/mcp',{
      jsonrpc:'2.0',id:1,method:'tools/list',
    },{headers:{'cf-access-jwt-assertion':'invalid-owner-token'}});
    ensure(invalidOwner.status===401,'invalid Owner token was not rejected');
    const machineToOwner=await post(gatewayPort,readFileSync(tlsCert),'/mcp',{
      jsonrpc:'2.0',id:2,method:'tools/list',
    },{headers:{'cf-access-client-id':CLIENT,'cf-access-client-secret':serviceSecret}});
    ensure(machineToOwner.status===401,'M2M credentials were accepted as Owner authentication');
    const ownerToMachine=await post(gatewayPort,readFileSync(tlsCert),'/agent/challenge',{deviceId:randomUUID()},
      {headers:{...authHeaders,'cf-access-client-id':CLIENT,'cf-access-client-secret':serviceSecret}});
    ensure(ownerToMachine.status===403,'Owner JWT crossed into the M2M endpoint');
    const invalidMachineSecret=await post(gatewayPort,readFileSync(tlsCert),'/agent/challenge',{
      deviceId:randomUUID(),
    },{headers:{'cf-access-client-id':CLIENT,'cf-access-client-secret':`${serviceSecret}x`}});
    ensure(invalidMachineSecret.status===403,'invalid M2M service secret was accepted');

    const identity=loadOrCreateDeviceIdentity({directory:dirs.identity,platform:process.platform});
    const started=await post(gatewayPort,readFileSync(tlsCert),'/pairing/start',{
      name:'g7-i5a-synthetic-agent',platform:'linux',publicKeyPem:identity.publicKeyPem,
    });
    ensure(started.status===201,'synthetic pairing request failed');
    const pairing=started.json;
    trace('pairing challenge created');
    const proof=identity.prove(pairing);
    const proved=await post(gatewayPort,readFileSync(tlsCert),'/pairing/prove',{
      requestId:pairing.requestId,proof,
    });
    ensure(proved.status===200&&proved.json.proved===true,'Ed25519 pairing proof failed');
    const ownerClientConfig={version:1,origin:`https://${HOST}`,connectAddress:'127.0.0.1',
      connectPort:gatewayPort,tlsServerName:HOST,caPath:tlsCert,stageControlToken:controlToken,
      owner:{issuer:OWNER_ISSUER,audience:OWNER_AUD,email:OWNER_EMAIL,subject:OWNER_SUBJECT,
        kid:owner.jwk.kid,publicJwk:owner.jwk,privateKeyPath:ownerSigningKeyPath},
      machineClientId:CLIENT,allowedRoot:dirs['allowed-root']};
    privateJson(ownerClientConfigPath,ownerClientConfig);
    const ownerProvisioning=JSON.parse(execFileSync(process.execPath,
      [path.join(ROOT,'scripts/g7-staging-owner-provision.mjs'),'--config',ownerClientConfigPath],{
        cwd:ROOT,encoding:'utf8',maxBuffer:64*1024,timeout:20_000,
        input:JSON.stringify({requestId:pairing.requestId,code:pairing.displayCode,
          fingerprint:pairing.fingerprint})+'\n',
        env:{PATH:'/usr/bin:/bin',HOME:ownerClientHome,TMPDIR:ownerClientTmp,LANG:'C.UTF-8'},
      }));
    ensure(ownerProvisioning.status==='provisioned'&&ownerProvisioning.clientId===CLIENT&&
      ownerProvisioning.fingerprint===pairing.fingerprint&&
      ownerProvisioning.binding?.deviceId===ownerProvisioning.deviceId&&
      ownerProvisioning.grant?.deviceId===ownerProvisioning.deviceId,
      'separate Owner provisioning client did not return the approved durable records');
    trace('separate synthetic Owner CLI completed durable approval, binding, and grant');
    const deviceId=ownerProvisioning.deviceId;
    ensure(identity.fingerprint===pairing.fingerprint,'pairing fingerprint differs from persistent identity');

    const wrongClientBinding=await post(gatewayPort,readFileSync(tlsCert),'/stage/bind',{
      clientId:'g7-staging-other.synthetic',deviceId,expectedRevision:ownerProvisioning.bindingRevision,
    },{headers:controlHeaders});
    ensure(wrongClientBinding.status===400,'staging allowed a binding for another machine client');
    const wrongDeviceChallenge=await post(gatewayPort,readFileSync(tlsCert),'/agent/challenge',{
      deviceId:randomUUID(),
    },{headers:{'cf-access-client-id':CLIENT,'cf-access-client-secret':serviceSecret}});
    ensure(wrongDeviceChallenge.status===403,'M2M identity reached a different device challenge');
    const boundIdentity=bindApprovedDeviceIdentity({directory:dirs.identity,
      machineBinding:ownerProvisioning.binding});
    ensure(boundIdentity.deviceBinding.bindingEventId===ownerProvisioning.binding.bindingEventId,
      'identity binding was not persisted');
    trace('durable M2M binding persisted');

    let policyRevision=ownerProvisioning.grantRevision;
    const grant=async(tool,scope,constraints)=>{
      const response=await post(gatewayPort,readFileSync(tlsCert),'/stage/grant',{
        deviceId,expectedRevision:policyRevision,tool,scope,constraints,
      },{headers:controlHeaders});
      ensure(response.status===201,`durable ${tool} grant failed`);
      policyRevision=response.json.revision;
      return response.json.grant;
    };
    const readGrant=ownerProvisioning.grant;
    const writeGrant=await grant('write_file',{root:dirs['allowed-root']},{maxBytes:65_536});
    const commandGrant=await grant('run_command',{root:dirs['allowed-root'],profile:'count_lines'},
      {maxOutputBytes:4096,maxRuntimeMs:FIXTURE_COMMAND_TIMEOUT_MS,profile:'count_lines'});
    ensure(readGrant.deviceId===deviceId&&writeGrant.deviceId===deviceId,'grant identity binding mismatch');
    trace('durable grants committed');

    const makeAgentConfig=port=>({version:1,hostname:HOST,port,deviceId,clientId:CLIENT,clientSecret:serviceSecret,
      identityDirectory:dirs.identity,allowedRoot:dirs['allowed-root'],ledgerDirectory:dirs.ledger,
      mcpEntrypoint:path.resolve(mcpEntrypoint),policyPublicKeyPem:policy.publicKey.export({format:'pem',type:'spki'}),
      caPath:tlsCert,pollIntervalMs:25});
    privateJson(agentConfigPath,makeAgentConfig(gatewayPort));
    const startAgent=()=>launchProcess(path.join(ROOT,'packages/vpsc-agent/bin/g7-staging-worker.mjs'),
      ['--config',agentConfigPath],{home:agentHome,tmp:agentTmp,testActiveJob:fixtureRequested});
    agentProc=startAgent();
    const agentReady=await waitForEvent(agentProc,'READY');
    await waitForEvent(agentProc,'ONLINE');
    trace('agent process connected');
    ensure(agentReady.deviceId===deviceId,'agent connected as wrong device');

    let rpcId=0;
    const ownerCall=async(name,args,{signal}={})=>post(gatewayPort,readFileSync(tlsCert),'/mcp',{
      jsonrpc:'2.0',id:++rpcId,method:'tools/call',params:{name,arguments:{deviceId,...args}},
    },{headers:authHeaders,signal});
    let preExecutionCancellation=null;
    if(activeJobScenario==='owner-cancel'){
      const beforeExecutionFile=path.join(dirs['allowed-root'],'cancel-before-execution-probe.txt');
      writeFileSync(beforeExecutionFile,'cancel before local execution\n',{mode:0o600,flag:'wx'});
      const controller=new AbortController();
      const pending=ownerCall('read_file',{path:beforeExecutionFile},{signal:controller.signal})
        .then(response=>({response}),error=>({error}));
      const received=await waitForMatchingEvent(agentProc,'FIXTURE_OPERATION_RECEIVED',event=>
        event.tool==='read_file'&&typeof event.requestId==='string');
      controller.abort();
      const acknowledgement=await waitForMatchingEvent(agentProc,'FIXTURE_CANCEL_ACK',event=>
        event.requestId===received.requestId);
      const callOutcome=await pending;
      ensure(acknowledgement.accepted===true&&acknowledgement.status==='cancelled',
        'agent did not acknowledge cancellation after receipt and before execution');
      ensure(callOutcome.error instanceof Error,'cancelled Owner request returned a successful result');
      const cancelledLedger=existsSync(path.join(dirs.ledger,'i4-execution.jsonl'))
        ?readFileSync(path.join(dirs.ledger,'i4-execution.jsonl'),'utf8').trim().split('\n')
          .filter(Boolean).map(line=>JSON.parse(line)):[];
      ensure(!cancelledLedger.some(record=>record.requestId===received.requestId),
        'cancelled before execution request created an execution-ledger intent');
      preExecutionCancellation={requestId:received.requestId,receivedByAgent:true,
        acknowledged:acknowledgement.accepted===true,agentExecutionStatus:acknowledgement.status,
        gatewayAcknowledgementStatus:acknowledgement.gatewayStatus,
        ownerResult:'ambiguous_after_disconnect',noExecutionIntent:true,
        ownerTransportAborted:callOutcome.error instanceof Error};
      trace('agent acknowledged cancellation after delivery and before execution');
    }
    const read1=assertMcpOk(await ownerCall('read_file',{path:inputFile}),'real MCP read');
    trace('real MCP read completed');
    ensure(JSON.stringify(read1).includes(DISPLAYED_READ.trim()),'real Desktop Commander MCP did not return file content');
    const outputFile=path.join(dirs['allowed-root'],'created-by-governed-tool.txt');
    const write=assertMcpOk(await ownerCall('write_file',{path:outputFile,
      content:'I4 governed create-only write\n',mode:'create'}),'governed write');
    ensure(write.result?.structuredContent?.created===true,'governed create-only write did not execute');
    const read2=assertMcpOk(await ownerCall('read_file',{path:outputFile}),'read governed write');
    ensure(JSON.stringify(read2).includes('I4 governed create-only write'),'governed result not readable');
    trace('governed write and readback completed');

    // Kill the idle agent process. The durable key/binding and I4 outcome ledger survive;
    // a replacement worker must perform a new challenge and cannot replay old requests.
    const firstIdentityFingerprint=identity.fingerprint;
    await stopProcess(agentProc,'SIGKILL');
    agentProc=null;
    await new Promise(resolve=>setTimeout(resolve,150));
    const identityAfterAgentCrash=loadOrCreateDeviceIdentity({directory:dirs.identity,platform:process.platform});
    ensure(identityAfterAgentCrash.fingerprint===firstIdentityFingerprint&&
      identityAfterAgentCrash.deviceBinding.bindingEventId===ownerProvisioning.binding.bindingEventId,
      'agent identity or binding did not survive SIGKILL');
    agentRestartProc=startAgent();
    const agentRestartReady=await waitForEvent(agentRestartProc,'READY');
    await waitForEvent(agentRestartProc,'ONLINE');
    ensure(agentRestartReady.deviceId===deviceId,'restarted agent authenticated as wrong device');
    trace('agent SIGKILL restart authenticated');
    const readAfterAgentRestart=assertMcpOk(await ownerCall('read_file',{path:inputFile}),
      'read after agent restart');
    ensure(JSON.stringify(readAfterAgentRestart).includes(DISPLAYED_READ.trim()),'agent restart lost real MCP access');

    await stopProcess(agentRestartProc,'SIGTERM');agentRestartProc=null;
    const gatewayStopped=waitForEvent(gatewayProc,'STOPPED');
    await stopProcess(gatewayProc,'SIGTERM');await gatewayStopped;gatewayProc=null;
    gatewayRestartProc=launchProcess(path.join(ROOT,'gateway/staging/server.mjs'),
      ['--config',gatewayConfigPath],{home:gatewayHome,tmp:gatewayTmp});
    const gatewayRestartReady=await waitForEvent(gatewayRestartProc,'READY');gatewayPort=gatewayRestartReady.port;
    const restored=await waitHealth(gatewayPort,readFileSync(tlsCert));
    trace('Gateway graceful restart restored durable state');
    ensure(restored.trustRevision===1&&restored.policyRevision===3&&restored.bindingRevision===1,
      'Gateway durable trust, binding or grant revision did not survive restart');
    replacePrivateJson(agentConfigPath,makeAgentConfig(gatewayPort));
    agentRestartProc=startAgent();
    const agentAfterGatewayRestart=await waitForEvent(agentRestartProc,'READY');
    await waitForEvent(agentRestartProc,'ONLINE');
    ensure(agentAfterGatewayRestart.deviceId===deviceId,'agent failed to establish fresh post-Gateway-restart session');
    const readAfterGatewayRestart=assertMcpOk(await ownerCall('read_file',{path:inputFile}),
      'read after Gateway restart');
    ensure(JSON.stringify(readAfterGatewayRestart).includes(DISPLAYED_READ.trim()),'Gateway restart lost approved device');
    trace('new session passed post-restart real MCP read');

    await stopProcess(agentRestartProc,'SIGTERM');agentRestartProc=null;
    await stopProcess(gatewayRestartProc,'SIGKILL');gatewayRestartProc=null;
    ensure(allProcesses.every(proc=>proc.stopVerified===true),
      'a known Gateway or agent process group remained live at reconciliation time');
    trace('idle Gateway process stopped by SIGKILL');
    const crashEvidence=analyzeOwnerPairingRecovery({auditDirectory:dirs.audit,trustDirectory:dirs.trust});
    ensure(crashEvidence.state==='CONSISTENT_LOCK_HELD'&&crashEvidence.auditLockPresent===true&&
      crashEvidence.auditLockStatus==='dead'&&
      (!crashEvidence.trustLockPresent||crashEvidence.trustLockStatus==='dead'),
      `Gateway SIGKILL recovery evidence was not safe: ${JSON.stringify(crashEvidence)}`);
    const crashRecovery=reconcileOwnerPairingRecovery({auditDirectory:dirs.audit,
      trustDirectory:dirs.trust,operatorConfirmedNoActiveWriters:true});
    ensure(crashRecovery.state==='RECONCILED_CONSISTENT',
      `Gateway SIGKILL recovery did not reconcile consistently: ${crashRecovery.state}`);
    trace('stale locks reconciled after captured Gateway process groups were verified stopped');
    gatewayRestartProc=launchProcess(path.join(ROOT,'gateway/staging/server.mjs'),
      ['--config',gatewayConfigPath],{home:gatewayHome,tmp:gatewayTmp});
    const gatewayAfterSigkillReady=await waitForEvent(gatewayRestartProc,'READY');
    gatewayPort=gatewayAfterSigkillReady.port;
    const restoredAfterSigkill=await waitHealth(gatewayPort,readFileSync(tlsCert));
    ensure(restoredAfterSigkill.trustRevision===restored.trustRevision&&
      restoredAfterSigkill.policyRevision===restored.policyRevision&&
      restoredAfterSigkill.bindingRevision===restored.bindingRevision,
      'Gateway durable state changed after SIGKILL restart');
    replacePrivateJson(agentConfigPath,makeAgentConfig(gatewayPort));
    agentRestartProc=startAgent();
    const agentAfterGatewaySigkill=await waitForEvent(agentRestartProc,'READY');
    await waitForEvent(agentRestartProc,'ONLINE');
    ensure(agentAfterGatewaySigkill.deviceId===deviceId,
      'agent failed to establish a fresh session after Gateway SIGKILL');
    const readAfterGatewaySigkill=assertMcpOk(await ownerCall('read_file',{path:inputFile}),
      'read after Gateway SIGKILL restart');
    ensure(JSON.stringify(readAfterGatewaySigkill).includes(DISPLAYED_READ.trim()),
      'Gateway SIGKILL restart lost approved device access');
    trace('new session passed post-Gateway-SIGKILL real MCP read');

    const revokeGrant=await post(gatewayPort,readFileSync(tlsCert),'/stage/revoke-grant',{
      deviceId,expectedRevision:policyRevision,grantId:writeGrant.grantId,
    },{headers:controlHeaders});
    ensure(revokeGrant.status===200&&revokeGrant.json.revision===4,'grant revocation was not durable');
    policyRevision=4;
    trace('grant revoked');
    const deniedWrite=await ownerCall('write_file',{path:path.join(dirs['allowed-root'],'revoked-write.txt'),
      content:'must not be created\n',mode:'create'});
    ensure(deniedWrite.status===403&&deniedWrite.json?.error!==undefined&&
      !existsSync(path.join(dirs['allowed-root'],'revoked-write.txt')),
      'revoked grant allowed a file write');

    let activeExecution=null,grantRevocationDuringJob=null,deviceRevocationDuringJob=null;
    let revokedDevice=null;
    if(activeJobScenario){
      const cancelledPath=path.join(dirs['allowed-root'],'active-cancel-probe.txt');
      writeFileSync(cancelledPath,'active cancellation fixture\n',{mode:0o600,flag:'wx'});
      const ownerController=activeJobScenario==='owner-cancel'?new AbortController():null;
      const pending=ownerCall('run_command',{path:cancelledPath,profile:'count_lines'},
        ownerController?{signal:ownerController.signal}:{}).then(response=>({response}),error=>({error}));
      const started=await waitForMatchingEvent(agentRestartProc,'FIXTURE_JOB_STARTED',event=>
        typeof event.requestId==='string'&&Number.isSafeInteger(event.pid));
      const liveProcess=fixedSleepProcess(started.pid,agentAfterGatewaySigkill.pid);
      ensure(liveProcess,'executor start event did not match a live /usr/bin/sleep 30 child');
      const ledgerPath=path.join(dirs.ledger,'i4-execution.jsonl');
      const ledgerRecords=()=>existsSync(ledgerPath)
        ?readFileSync(ledgerPath,'utf8').trim().split('\n').filter(Boolean).map(line=>JSON.parse(line)):[];
      const intent=ledgerRecords().find(record=>record.type==='intent'&&record.requestId===started.requestId);
      ensure(intent?.tool==='run_command'&&intent.deviceId===deviceId,
        'active process has no matching durable I4 intent');

      let acknowledgement=null;
      if(activeJobScenario==='owner-cancel'){
        ownerController.abort();
        acknowledgement=await waitForMatchingEvent(agentRestartProc,'FIXTURE_CANCEL_ACK',event=>
          event.requestId===started.requestId);
      }else if(activeJobScenario==='grant-revoke'){
        ensure(processStillLive(liveProcess),'active fixture command stopped before grant revocation was requested');
        const revocationRequestNs=process.hrtime.bigint();
        const revoked=await post(gatewayPort,readFileSync(tlsCert),'/stage/revoke-grant',{
          deviceId,expectedRevision:policyRevision,grantId:commandGrant.grantId,
        },{headers:controlHeaders});
        const revocationResponseNs=process.hrtime.bigint();
        ensure(revoked.status===200&&revoked.json.active===false,
          'active run_command grant was not durably revoked');
        policyRevision=revoked.json.revision;
        const jobStartedNs=BigInt(started.monotonicNs);
        const commitElapsedMs=Number(revocationResponseNs-jobStartedNs)/1_000_000;
        const commitBeforeCommandTimeout=commitElapsedMs<FIXTURE_COMMAND_TIMEOUT_MS-500;
        ensure(commitBeforeCommandTimeout,
          'grant revocation did not commit before the fixed command timeout safety margin');
        acknowledgement=await waitForMatchingEvent(agentRestartProc,'FIXTURE_CANCEL_ACK',event=>
          event.requestId===started.requestId);
        const acknowledgementNs=BigInt(acknowledgement.monotonicNs);
        const acknowledgementElapsedMs=Number(acknowledgementNs-jobStartedNs)/1_000_000;
        const acknowledgementAfterRevocationRequest=acknowledgementNs>=revocationRequestNs;
        const acknowledgementBeforeCommandTimeout=acknowledgementElapsedMs<FIXTURE_COMMAND_TIMEOUT_MS-500;
        ensure(acknowledgementAfterRevocationRequest&&acknowledgementBeforeCommandTimeout,
          'agent did not acknowledge grant-revocation cancellation before the command timeout safety margin');
        grantRevocationDuringJob={revoked:true,revision:policyRevision,commitBeforeCommandTimeout,
          acknowledgementAfterRevocationRequest,acknowledgementBeforeCommandTimeout,
          commitElapsedMs,acknowledgementElapsedMs,commandTimeoutMs:FIXTURE_COMMAND_TIMEOUT_MS};
      }else{
        ensure(processStillLive(liveProcess),'active fixture command stopped before trust revocation was requested');
        const revocationRequestNs=process.hrtime.bigint();
        revokedDevice=await post(gatewayPort,readFileSync(tlsCert),'/stage/revoke-device',{
          clientId:CLIENT,deviceId,
        },{headers:controlHeaders});
        const revocationResponseNs=process.hrtime.bigint();
        ensure(revokedDevice.status===200&&revokedDevice.json.revoked===true&&
          revokedDevice.json.trustRevision===2,'active device trust revocation was not durable');
        const jobStartedNs=BigInt(started.monotonicNs);
        const commitElapsedMs=Number(revocationResponseNs-jobStartedNs)/1_000_000;
        const commitBeforeCommandTimeout=commitElapsedMs<FIXTURE_COMMAND_TIMEOUT_MS-500;
        ensure(commitBeforeCommandTimeout,
          'device trust revocation did not commit before the fixed command timeout safety margin');
        const sessionRejection=await waitForMatchingEvent(agentRestartProc,'FIXTURE_CLIENT_CALL',event=>
          ['heartbeat','pollControl'].includes(event.method)&&event.outcome==='error'&&event.code==='REJECTED');
        const sessionRejectionNs=BigInt(sessionRejection.monotonicNs);
        const rejectionElapsedMs=Number(sessionRejectionNs-jobStartedNs)/1_000_000;
        const sessionRejectionBeforeCommandTimeout=rejectionElapsedMs<FIXTURE_COMMAND_TIMEOUT_MS-500;
        ensure(sessionRejectionNs>=revocationRequestNs&&sessionRejectionBeforeCommandTimeout,
          'agent did not observe the revoked trust session before the command timeout safety margin');
        deviceRevocationDuringJob={revoked:true,trustRevision:revokedDevice.json.trustRevision,
          sessionRejectionObserved:true,sessionRejectionMethod:sessionRejection.method,
          sessionRejectionCode:sessionRejection.code,commitBeforeCommandTimeout,
          commitElapsedMs,sessionRejectionBeforeCommandTimeout,rejectionElapsedMs,
          commandTimeoutMs:FIXTURE_COMMAND_TIMEOUT_MS};
      }
      const callOutcome=await pending;
      if(activeJobScenario==='owner-cancel'){
        ensure(callOutcome.error instanceof Error,'Owner HTTP cancellation returned a result');
      }else{
        ensure(callOutcome.response&&callOutcome.response.status>=400,
          'revoked active operation crossed the Owner response fence');
      }
      if(acknowledgement){
        ensure(acknowledgement.accepted===true&&acknowledgement.status==='ambiguous',
          'agent did not durably acknowledge the active job as ambiguous');
      }
      const processStopped=await waitForProcessExit(liveProcess);
      ensure(processStopped,'active fixture child remained alive after cancellation or revocation');
      const matchingRecords=ledgerRecords().filter(record=>record.requestId===started.requestId);
      const intents=matchingRecords.filter(record=>record.type==='intent');
      const outcomes=matchingRecords.filter(record=>record.type==='outcome');
      ensure(intents.length===1&&outcomes.length===1&&outcomes[0].status==='ambiguous',
        'active operation lacks one ambiguous durable outcome without replay');
      activeExecution={scenario:activeJobScenario,requestId:started.requestId,
        startProven:true,processWasLiveAtCancel:true,processPid:started.pid,
        cancelAcknowledged:acknowledgement?.accepted===true,
        acknowledgedStatus:acknowledgement?.status??'unavailable_after_device_revocation',
        gatewayAcknowledgementStatus:acknowledgement?.gatewayStatus??null,
        ownerResponseStatus:callOutcome.response?.status??null,
        ownerResponseCode:callOutcome.response?.json?.error?.data?.code??null,
        responseFenced:true,processStopped,automaticReplay:intents.length!==1};
      ensure(activeExecution.automaticReplay===false,'active operation was replayed');
      trace(`active job ${activeJobScenario} fenced with durable ambiguous outcome`);
    }

    if(!revokedDevice){
      revokedDevice=await post(gatewayPort,readFileSync(tlsCert),'/stage/revoke-device',{
        clientId:CLIENT,deviceId,
      },{headers:controlHeaders});
      ensure(revokedDevice.status===200&&revokedDevice.json.revoked===true&&revokedDevice.json.trustRevision===2,
        'device revocation was not durably committed');
    }
    const afterDeviceRevoke=await ownerCall('read_file',{path:inputFile});
    ensure(afterDeviceRevoke.status===403&&afterDeviceRevoke.json?.error!==undefined,
      'revoked device received a new dispatch');

    await stopProcess(agentRestartProc,'SIGTERM');agentRestartProc=null;
    const ledger=analyzeI4ExecutionRecovery({ledgerDirectory:dirs.ledger});
    ensure(ledger.automaticReplay===false&&ledger.automaticLockRemoval===false,
      'I4 recovery contract enabled automatic replay or lock removal');
    ensure(ledger.status==='consistent'||ledger.status==='ambiguous-outcome',
      `unexpected I4 ledger recovery state: ${ledger.status}`);
    const auditText=readFileSync(path.join(dirs.audit,'owner-decisions-v1.jsonl'),'utf8');
    const forbidden=[ownerJwt,serviceSecret,controlToken,pairing.nonce,pairing.displayCode,
      owner.privateKey.export({format:'pem',type:'pkcs8'}).toString(),
      machine.privateKey.export({format:'pem',type:'pkcs8'}).toString()];
    ensure(forbidden.every(secret=>!auditText.includes(secret)),'synthetic credentials leaked into owner WAL');
    report={status:'pass_with_limitations',gateway:{processIndependent:true,pid:gatewayReady.pid},
      agent:{processIndependent:true,pid:agentReady.pid,deviceId},
      https:{tlsValidated:true,hostname:HOST,loopbackOnly:true},
      ownerAuthentication:{verified:true,separateFromMachine:true,
        provisioningClientProcess:true,durableApproval:true,durableBinding:true,durableGrant:true},
      machineAuthentication:{clientIdBinding:true,ed25519Fingerprint:identity.fingerprint},
      operations:{realMcpRead:true,governedWrite:true,revokedGrantDenied:true},
      restart:{agent:true,gateway:true,identityPersistent:true,newGatewaySession:true,
        gatewayAfterSigkill:true,gatewayAfterSigkillRecovery:crashRecovery.state,
        gatewayAfterSigkillTrustRevision:restoredAfterSigkill.trustRevision,
        trustRevision:restored.trustRevision,policyRevision:restored.policyRevision},
      revocation:{grantBlocksDispatch:true,deviceBlocksDispatch:true,trustRevision:revokedDevice.json.trustRevision},
      security:{invalidOwnerRejected:true,ownerTokenRejectedByMachineIngress:true,
        invalidMachineSecretRejected:true,mismatchedMachineClientIdRejected:true,
        crossDeviceChallengeRejected:true},
      cancellation:{ownerTransportAbortObserved:activeJobScenario==='owner-cancel',
        scenario:activeJobScenario??'not_tested_outside_node_test',
        afterReceiptBeforeExecution:preExecutionCancellation,
        followUpReadSucceeded:preExecutionCancellation?true:null,
        activeExecution:activeExecution??{startProven:false,processWasLiveAtCancel:false,
          cancelAcknowledged:false,acknowledgedStatus:'not_tested',processStopped:false,automaticReplay:false},
        grantRevocationDuringJob,deviceRevocationDuringJob,
        noAutomaticReplay:ledger.automaticReplay===false,ledgerState:ledger.status},
      cleanup:{processGroupsGone:false,temporaryStateRemoved:false}};
  }finally{
    let cleanupError;
    for(const proc of [...allProcesses].reverse()){
      try{await stopProcess(proc);}catch(error){cleanupError??=error;}
    }
    if(cleanupError){
      const detail=String(cleanupError?.message??'unknown process error').replace(/[\r\n]/g,' ').slice(0,180);
      const error=Error(`Staging process cleanup failed (${detail}); private state retained at ${scratch}`);
      error.code='STAGING_CLEANUP_FAILED';error.cause=cleanupError;throw error;
    }
    rmSync(scratch,{recursive:true,force:true});
    if(existsSync(scratch))throw Error('Staging temporary state could not be removed');
    if(report){report.cleanup.processGroupsGone=allProcesses.every(proc=>proc.stopVerified===true);
      report.cleanup.temporaryStateRemoved=true;}
  }
  return report;
}

if(process.argv.length>2&&!(process.argv.length===3&&process.argv[2]==='--json')){
  process.stderr.write('Usage: node scripts/g7-staging-pilot.mjs [--json]\n');process.exitCode=2;
}else{
  runPilot().then(report=>process.stdout.write(JSON.stringify(report)+'\n'),error=>{
    const diagnosticLimit=process.env.VPSC_STAGING_TEST_ACTIVE_JOB==='1'?1600:240;
    process.stderr.write(JSON.stringify({status:'blocked',code:
      /^[A-Z_]{1,48}$/.test(error?.code??'')?error.code:'STAGING_PILOT_FAILED',
      message:String(error?.message??'staging pilot failed').replace(/[\r\n]/g,' ').slice(0,diagnosticLimit)})+'\n');
    process.exitCode=1;
  });
}
