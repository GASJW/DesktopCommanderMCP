import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac, createPublicKey, generateKeyPairSync, randomBytes, randomUUID,
  sign, timingSafeEqual } from 'node:crypto';
import { execFileSync, spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { connect as createConnection, createServer as createNetServer } from 'node:net';
import { request as httpsRequest } from 'node:https';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { networkInterfaces, tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createAuth0OwnerVerifier } from '../owner/auth0-owner-auth.mjs';
import { createDurableOwnerAuthority, ownerAuthorityApprovalSigningBytes,
  ownerAuthorityTargetDigest } from '../owner/durable-owner-authority.mjs';
import { createIsolatedRealmProvisioning } from '../owner/isolated-realm-provisioning.mjs';
import { createDurableOwnerAudit, inspectDurableOwnerAudit,
  readDurableOwnerMachineBindingDecision, readDurableOwnerMachineBindingHistory }
  from '../dashboard/durable-owner-audit.mjs';
import { createDurableOwnerDeviceApprovalByIdReader, createDurableOwnerDeviceApprovalReader }
  from '../dashboard/durable-owner-device-authorization.mjs';
import { createOwnerMachineBindingService } from '../dashboard/owner-machine-binding.mjs';
import { createDurableDeviceTrustStore, inspectDurableDeviceTrust } from '../devices/durable-trust.mjs';
import { createDurableMachineBindingStore } from '../devices/durable-machine-bindings.mjs';
import { inspectDurableMachineBindingSnapshot } from '../devices/durable-machine-bindings.mjs';
import { createDurableToolGrantStore } from '../devices/durable-tool-grants.mjs';
import { createPairingCoordinator, pairingProofMessage } from '../devices/pairing.mjs';
import { createDeviceRouter } from '../devices/router.mjs';
import { createDurableOwnerDeviceAuthorizer } from '../dashboard/durable-owner-device-authorization.mjs';
import { analyzeI4ExecutionRecovery } from '../../packages/vpsc-agent/src/governed-executor.mjs';
import { bindApprovedDeviceIdentity, loadOrCreateDeviceIdentity } from '../../packages/vpsc-agent/src/identity-store.mjs';
import { startIsolatedG7AgentGateway } from '../owner/isolated-agent-gateway.mjs';
import { createIsolatedG7Realm } from '../owner/isolated-realm.mjs';

const linuxUnprivileged=process.platform==='linux'&&typeof process.getuid==='function'&&process.getuid()!==0;
const ISSUER='https://auth.example.test/';
const RESOURCE='https://g7.example.test/chatgpt/mcp';
const CLIENT='chatgpt-cimd-test';
const REALM='8ef7e14e-6291-4a58-bd25-1707d1f2067f';
const ROOT='/srv/g7-read';
const REPO_ROOT=fileURLToPath(new URL('../../',import.meta.url));
const WORKER_CLI=path.join(REPO_ROOT,'packages/vpsc-agent/bin/g7-staging-worker.mjs');
const MCP_ENTRYPOINT=path.join(REPO_ROOT,'packages/vpsc-agent/test/fixtures-readonly-mcp.mjs');
const CONSTRAINTS={maxBytes:4096,maxLength:100,maxOffset:2000};
const initialNow=Date.now();
const seconds=Math.floor(initialNow/1000);
const b64=value=>Buffer.from(JSON.stringify(value)).toString('base64url');

function fixture(t,{testHooks,bindingTestHooks,realtime=false}={}){
  let currentTime=initialNow,timeAdjustment=0;
  const now=()=>realtime?Date.now()+timeAdjustment:currentTime;
  const home=mkdtempSync(path.join(tmpdir(),'g7-i8h-provision-'));
  chmodSync(home,0o700);
  const storageRoot=path.join(home,'realm'),protectedRoot=path.join(home,'i7-protected');
  mkdirSync(storageRoot,{mode:0o700});mkdirSync(protectedRoot,{mode:0o700});
  const aliases={authority:'ownerAuthorityDirectory',provisioning:'provisioningDirectory',
    audit:'auditDirectory',trust:'trustDirectory',binding:'bindingDirectory',
    grant:'grantDirectory',ledger:'ledgerDirectory',policy:'policyDirectory',runtime:'runtimeDirectory'};
  const paths={storageRoot};
  const realmPaths={storageRoot};
  for(const [alias,name] of Object.entries(aliases)){
    const directory=path.join(storageRoot,name);
    mkdirSync(directory,{mode:0o700});chmodSync(directory,0o700);
    paths[alias]=directory;realmPaths[name]=directory;
  }
  const configFile=path.join(storageRoot,'config.json');
  writeFileSync(configFile,'{}\n',{mode:0o600});
  realmPaths.configFile=configFile;
  const control=generateKeyPairSync('ed25519');
  const publicKeyPem=control.publicKey.export({type:'spki',format:'pem'});
  const realmConfig={version:1,realmId:REALM,listen:{host:'127.0.0.1',port:19443},
    paths:realmPaths,controlIdentity:{algorithm:'Ed25519',keyId:'i8h-control-test',
      publicKeyPem,fingerprint:createHash('sha256').update(
        control.publicKey.export({type:'spki',format:'der'})).digest('hex')},
    protectedKeyFingerprints:[],protectedPaths:[protectedRoot]};
  const auth=generateKeyPairSync('rsa',{modulusLength:2048});
  const signer=generateKeyPairSync('ed25519');
  const authJwk={...auth.publicKey.export({format:'jwk'}),kid:'auth0-test',alg:'RS256',use:'sig'};
  const signerJwk={...signer.publicKey.export({format:'jwk'}),kid:'operator-test'};
  const verifierConfig={issuer:ISSUER,resource:RESOURCE,authorizedClientIds:[CLIENT],
    readScope:'g7.read',ownerScope:'g7.owner',jwks:[authJwk]};
  const verifier=createAuth0OwnerVerifier(verifierConfig,{now});
  const payload={iss:ISSUER,sub:'google-oauth2|synthetic-i8h-owner',aud:RESOURCE,
    client_id:CLIENT,iat:seconds,exp:seconds+600};
  const tokenFor=(scope='g7.owner',sub=payload.sub)=>{
    const header=b64({alg:'RS256',kid:authJwk.kid,typ:'JWT'});
    const issuedAt=Math.floor(now()/1000);
    const claims=b64({...payload,sub,scope,...(realtime?{iat:issuedAt,exp:issuedAt+600}:{})});
    const input=`${header}.${claims}`;
    return `${input}.${sign('RSA-SHA256',Buffer.from(input),auth.privateKey).toString('base64url')}`;
  };
  const principal=verifier.verifyAdminPrincipal(tokenFor());
  const authority=createDurableOwnerAuthority({directory:paths.authority,realmId:REALM,
    issuer:ISSUER,verifier,approvalJwks:[signerJwk],now});
  const makeApproval=({operation,eventId=randomUUID(),expectedRevision,target,
    realmId=REALM,ownerDigest=principal.ownerDigest,key=signer.privateKey,
    issuedAt=Math.floor(now()/1000),expiresAt=issuedAt+120}={})=>{
    const fields={version:1,realmId,eventId,operation,expectedRevision,ownerDigest,
      targetDigest:ownerAuthorityTargetDigest(operation,target),issuedAt,
      expiresAt,keyId:signerJwk.kid};
    return {...fields,signature:sign(null,ownerAuthorityApprovalSigningBytes({
      ...fields,signature:'A'.repeat(86)}),key).toString('base64url')};
  };
  const bootstrapTarget={issuer:ISSUER,ownerDigest:principal.ownerDigest};
  authority.bootstrap({accessToken:tokenFor('g7.read'),approval:makeApproval({
    operation:'bootstrap',expectedRevision:0,target:bootstrapTarget})});
  const auditWriter=createDurableOwnerAudit({directory:paths.audit});
  const trustStore=createDurableDeviceTrustStore({directory:paths.trust,now});
  const pairingCoordinator=createPairingCoordinator({registry:trustStore,now,
    preallocateDeviceId:true});
  const readApprovalById=createDurableOwnerDeviceApprovalByIdReader({
    auditDirectory:paths.audit,trustDirectory:paths.trust});
  const machineBindingStore=createDurableMachineBindingStore({directory:paths.binding,
    verifyApprovalReceipt:binding=>binding.ownerId===principal.ownerId&&
      binding.ownerDigest===principal.ownerDigest?readApprovalById(binding.ownerId,binding.deviceId):null,
    readBindingDecision:binding=>readDurableOwnerMachineBindingDecision({
      directory:paths.audit,eventId:binding.bindingEventId}),
    readBindingHistory:()=>readDurableOwnerMachineBindingHistory({directory:paths.audit})});
  const bindingService=createOwnerMachineBindingService({accessVerifier:authority.accessVerifier,
    auditWrite:auditWriter.auditWrite,
    readApprovalReceipt:(owner,deviceId)=>readApprovalById(owner.ownerId,deviceId),
    machineBindingStore,now:()=>new Date(now()),testHooks:bindingTestHooks});
  const grantStore=createDurableToolGrantStore({directory:paths.grant,now});
  const provisioner=createIsolatedRealmProvisioning({realmId:REALM,realmConfig,ownerAuthority:authority,
    provisioningDirectory:paths.provisioning,auditDirectory:paths.audit,bindingDirectory:paths.binding,
    trustDirectory:paths.trust,trustStore,pairingCoordinator,auditWriter,
    machineBindingStore,bindingService,grantStore,readApprovalById,testHooks});
  t.after(()=>{try{auditWriter.close();}catch{};try{trustStore.close();}catch{};
    try{machineBindingStore.close();}catch{};rmSync(home,{recursive:true,force:true});});
  return {home,paths,protectedRoot,realmConfig,authority,principal,tokenFor,makeApproval,trustStore,
    pairingCoordinator,auditWriter,machineBindingStore,grantStore,readApprovalById,
    bindingService,provisioner,advanceTime:ms=>{if(realtime)timeAdjustment+=ms;else currentTime+=ms;}};
}

function pairDevice(f,t,{platform='linux',testHooks}={}){
  const key=generateKeyPairSync('ed25519');
  const publicKeyPem=key.publicKey.export({type:'spki',format:'pem'});
  const challenge=f.provisioner.startPairing({name:'Synthetic Gui-PC',platform,publicKeyPem});
  const proof=sign(null,pairingProofMessage(challenge.requestId,challenge.nonce,
    challenge.fingerprint),key.privateKey).toString('base64url');
  assert.equal(f.provisioner.provePairing(challenge.requestId,proof),true);
  const target={realmId:REALM,deviceId:challenge.deviceId,requestId:challenge.requestId,
    fingerprint:challenge.fingerprint,trustRevision:f.trustStore.revision()};
  const approval=f.makeApproval({operation:'device.approve',expectedRevision:target.trustRevision,target});
  const result=f.provisioner.approveDevice({accessToken:f.tokenFor(),approval,
    requestId:challenge.requestId,deviceId:challenge.deviceId,fingerprint:challenge.fingerprint});
  return {challenge,approval,result,key};
}

function bindDevice(f,device,clientId='i8h-synthetic-client'){
  const target={realmId:REALM,ownerDigest:f.principal.ownerDigest,clientId,
    deviceId:device.challenge.deviceId,fingerprint:device.challenge.fingerprint,
    bindingRevision:f.machineBindingStore.revision(),pairingEventId:device.approval.eventId};
  const approval=f.makeApproval({operation:'binding.create',expectedRevision:target.bindingRevision,target});
  return f.provisioner.bindDevice({accessToken:f.tokenFor(),approval,clientId:target.clientId,
    deviceId:target.deviceId,fingerprint:target.fingerprint,expectedRevision:target.bindingRevision});
}

function issueGrant(f,device,root=ROOT){
  const expectedRevision=f.grantStore.revision();
  const grant={ownerDigest:f.principal.ownerDigest,deviceId:device.challenge.deviceId,
    fingerprint:device.challenge.fingerprint,tool:'read_file',scope:{root},constraints:CONSTRAINTS};
  const target={realmId:REALM,...grant,policyRevision:expectedRevision};
  const approval=f.makeApproval({operation:'grant.issue',expectedRevision,target});
  return f.provisioner.issueReadFileGrant({accessToken:f.tokenFor(),approval,
    deviceId:grant.deviceId,fingerprint:grant.fingerprint,root,
    constraints:CONSTRAINTS,expectedRevision});
}

async function unusedLoopbackPort(){
  const server=createNetServer();
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
  const port=server.address().port;
  await new Promise(resolve=>server.close(resolve));
  return port;
}

function makeTlsCertificate(directory,hostname,name){
  const key=path.join(directory,`${name}.key`),certificate=path.join(directory,`${name}.crt`);
  execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-days','1',
    '-subj',`/CN=${hostname}`,'-addext',`subjectAltName=DNS:${hostname}`,
    '-keyout',key,'-out',certificate],{stdio:'ignore'});
  chmodSync(key,0o600);chmodSync(certificate,0o644);
  return {key:readFileSync(key),certificate:readFileSync(certificate),keyPath:key,certificatePath:certificate};
}

function startSyntheticWorker(configPath){
  const child=spawn(process.execPath,[WORKER_CLI,'--config',configPath],{
    cwd:REPO_ROOT,stdio:['ignore','pipe','pipe'],windowsHide:true,detached:true,
    env:{PATH:process.env.PATH??'/usr/bin:/bin',HOME:process.env.HOME??'',TMPDIR:process.env.TMPDIR??''},
  });
  const events=[],waiters=[];
  let stderr='';
  const lines=createInterface({input:child.stdout,crlfDelay:Infinity});
  lines.on('line',line=>{
    let event;try{event=JSON.parse(line);}catch{return;}
    events.push(event);
    const index=waiters.findIndex(waiter=>waiter.predicate(event));
    if(index>=0){const [waiter]=waiters.splice(index,1);clearTimeout(waiter.timer);waiter.resolve(event);}
  });
  child.stderr.setEncoding('utf8').on('data',chunk=>{stderr=(stderr+chunk).slice(-3000);});
  child.once('error',error=>{for(const waiter of waiters.splice(0)){clearTimeout(waiter.timer);waiter.reject(error);}});
  child.once('exit',(code,signal)=>{
    for(const waiter of waiters.splice(0)){clearTimeout(waiter.timer);waiter.reject(
      Error(`Synthetic worker exited before event (${code}, ${signal}): ${stderr}`));}
  });
  return {child,events,waitFor(predicate,label,timeoutMs=15_000){
    const existing=events.find(predicate);if(existing)return Promise.resolve(existing);
    return new Promise((resolve,reject)=>{
      const waiter={predicate,resolve,reject,timer:setTimeout(()=>{
        const index=waiters.indexOf(waiter);if(index>=0)waiters.splice(index,1);
        reject(Error(`Timed out waiting for synthetic worker ${label}: ${stderr}`));
      },timeoutMs)};
      waiters.push(waiter);
    });
  },async stop(signal='SIGTERM'){
    if(child.exitCode!==null||child.signalCode!==null)return;
    if(signal==='SIGKILL')process.kill(-child.pid,signal);else child.kill(signal);
    await new Promise((resolve,reject)=>{
      const timer=setTimeout(()=>{cleanup();reject(Error(`Synthetic worker did not stop (${stderr})`));},5000);
      const onExit=()=>{cleanup();resolve();};
      const cleanup=()=>{clearTimeout(timer);child.removeListener('exit',onExit);};
      child.once('exit',onExit);
      if(child.exitCode!==null||child.signalCode!==null)onExit();
    });
  }};
}

function httpsJson({port,hostname,ca,pathname,payload,headers={},signal,timeoutMs=10_000}){
  const body=Buffer.from(JSON.stringify(payload));
  return new Promise((resolve,reject)=>{
    const request=httpsRequest({hostname:'127.0.0.1',port,servername:hostname,method:'POST',
      path:pathname,ca,rejectUnauthorized:true,headers:{host:hostname,
        'content-type':'application/json','content-length':body.length,...headers}},response=>{
      const chunks=[];let size=0;
      response.on('data',chunk=>{size+=chunk.length;if(size>2*1024*1024){request.destroy(Error('response limit'));return;}chunks.push(chunk);});
      response.on('end',()=>{
        let value=null;try{value=JSON.parse(Buffer.concat(chunks,size).toString('utf8'));}catch{}
        resolve({status:response.statusCode,body:value});
      });
    });
    const abort=()=>request.destroy(Object.assign(Error('Test HTTPS request aborted'),{code:'ABORT_ERR'}));
    if(signal?.aborted)abort();else signal?.addEventListener('abort',abort,{once:true});
    request.once('error',reject);request.once('close',()=>signal?.removeEventListener('abort',abort));
    request.setTimeout(timeoutMs,()=>request.destroy(Error('HTTPS test request timeout')));
    request.end(body);
  });
}

async function persistentPairing(f,identity,directory,name,platform,clientId){
  const challenge=f.provisioner.startPairing({name,platform,publicKeyPem:identity.publicKeyPem});
  assert.equal(f.provisioner.provePairing(challenge.requestId,identity.prove(challenge)),true);
  const target={realmId:REALM,deviceId:challenge.deviceId,requestId:challenge.requestId,
    fingerprint:challenge.fingerprint,trustRevision:f.trustStore.revision()};
  const approval=f.makeApproval({operation:'device.approve',expectedRevision:target.trustRevision,target});
  f.provisioner.approveDevice({accessToken:f.tokenFor(),approval,requestId:challenge.requestId,
    deviceId:challenge.deviceId,fingerprint:challenge.fingerprint});
  const bindingResult=await bindDevice(f,{challenge,approval},clientId);
  const bound=bindApprovedDeviceIdentity({directory,machineBinding:bindingResult.binding});
  return {challenge,clientId,deviceId:challenge.deviceId,binding:bindingResult.binding,identity:bound};
}

function revokeReadGrant(f,deviceId,grantId){
  const grant=f.grantStore.list().find(value=>value.grantId===grantId&&value.active);
  const expectedRevision=f.grantStore.revision();
  if(!grant)throw Error('Synthetic active read_file grant missing');
  const target={realmId:REALM,ownerDigest:f.principal.ownerDigest,deviceId,
    fingerprint:grant.fingerprint,grantId,policyRevision:expectedRevision};
  const approval=f.makeApproval({operation:'grant.revoke',expectedRevision,target});
  return f.provisioner.revokeReadFileGrant({accessToken:f.tokenFor(),approval,
    deviceId,grantId,expectedRevision});
}

function revokeTrustedDevice(f,deviceId){
  const expectedRevision=f.trustStore.revision();
  const device=f.trustStore.registry.snapshotTrustedDevices().find(value=>value.deviceId===deviceId);
  if(!device)throw Error('Synthetic trusted device missing');
  const target={realmId:REALM,ownerDigest:f.principal.ownerDigest,deviceId,
    fingerprint:device.fingerprint,trustRevision:expectedRevision};
  const approval=f.makeApproval({operation:'device.revoke',expectedRevision,target});
  return f.provisioner.revokeDevice({accessToken:f.tokenFor(),approval,deviceId,expectedRevision});
}

function workerLedger(directory){
  const state=analyzeI4ExecutionRecovery({ledgerDirectory:directory});
  const filename=path.join(directory,'i4-execution.jsonl');
  const records=readFileSync(filename,'utf8').trim().split('\n').filter(Boolean).map(line=>JSON.parse(line));
  return {state,records};
}

function startNativeWindowsController(runId){
  const windowsRoot=process.env.VPSC_WINDOWS_REPO_ROOT??
    execFileSync('wslpath',['-w',REPO_ROOT],{encoding:'utf8'}).trim();
  const windowsNode=execFileSync('powershell.exe',['-NoLogo','-NoProfile','-NonInteractive','-Command',
    '(Get-Command node.exe -ErrorAction Stop).Source'],{encoding:'utf8'}).trim();
  if(!path.win32.isAbsolute(windowsRoot)||!path.win32.isAbsolute(windowsNode)){
    throw new Error('Native Windows Node or repository path is unavailable');
  }
  const linuxInteropNode=execFileSync('wslpath',['-u',windowsNode],{encoding:'utf8'}).trim();
  const script=path.win32.join(windowsRoot,'packages','vpsc-agent','test',
    'windows-i8i-network-controller.mjs');
  const child=spawn(linuxInteropNode,[script,'--run-id',runId],{stdio:['pipe','pipe','pipe'],windowsHide:true});
  const events=[],waiters=[];
  child.stdout.setEncoding('utf8');child.stderr.resume();
  const lines=createInterface({input:child.stdout,crlfDelay:Infinity});
  lines.on('line',line=>{
    let event;try{event=JSON.parse(line);}catch{return;}
    events.push(event);
    for(const waiter of [...waiters]){
      if(waiter.predicate(event)){
        waiters.splice(waiters.indexOf(waiter),1);clearTimeout(waiter.timer);waiter.resolve(event);
      }else if(event.type==='fatal'){
        waiters.splice(waiters.indexOf(waiter),1);clearTimeout(waiter.timer);
        waiter.reject(Error(`Native Windows fixture failed (${event.code})`));
      }
    }
  });
  child.once('error',error=>{for(const waiter of waiters.splice(0)){clearTimeout(waiter.timer);waiter.reject(error);}});
  child.once('exit',(code,signal)=>{for(const waiter of waiters.splice(0)){clearTimeout(waiter.timer);
    waiter.reject(Error(`Native Windows controller exited (${code}, ${signal})`));}});
  const diagnosticSummary=()=>events.slice(-8).map(value=>({
    type:value.type,...(['worker','worker_stderr'].includes(value.type)?{event:value.event}:{}),
    ...(typeof value.event?.phase==='string'&&/^[A-Z_]{1,48}$/.test(value.event.phase)?{phase:value.event.phase}:{}),
    ...(typeof value.code==='number'||typeof value.code==='string'?{code:value.code}:{}),
    ...(typeof value.signal==='string'?{signal:value.signal}:{}),
  }));
  const waitFor=(predicate,label,timeoutMs=15_000)=>{
    const existing=events.find(predicate);if(existing)return Promise.resolve(existing);
    return new Promise((resolve,reject)=>{
      const waiter={predicate,resolve,reject,timer:setTimeout(()=>{
        const index=waiters.indexOf(waiter);if(index>=0)waiters.splice(index,1);
        reject(Error(`Timed out waiting for native Windows ${label}; safe events=${JSON.stringify(diagnosticSummary())}`));
      },timeoutMs)};waiters.push(waiter);
    });
  };
  const send=async command=>{
    const id=randomUUID();
    child.stdin.write(JSON.stringify({...command,id})+'\n');
    const response=await waitFor(value=>value.type==='response'&&value.id===id,command.op);
    if(response.ok!==true)throw Object.assign(Error(`Native Windows command failed (${response.code})`),
      {code:response.code});
    return response;
  };
  return {child,events,waitFor,send,windowsRoot,
    async close(){
      if(child.exitCode!==null||child.signalCode!==null)return;
      try{await send({op:'cleanup'});}catch{}
      child.stdin.end();
      await Promise.race([new Promise(resolve=>child.once('close',resolve)),
        new Promise(resolve=>setTimeout(()=>{try{child.kill();}catch{};resolve();},5000))]);
    }};
}

function privateWslAddresses(){
  const iface=networkInterfaces().eth0?.find(value=>value.family==='IPv4'&&!value.internal);
  const route=execFileSync('ip',['route','show','default'],{encoding:'utf8'});
  const peer=route.match(/\bvia\s+(\d+\.\d+\.\d+\.\d+)/)?.[1];
  const privateV4=value=>{
    const octets=value?.split('.').map(Number);
    return octets?.length===4&&(octets[0]===10||octets[0]===172&&octets[1]>=16&&octets[1]<=31||
      octets[0]===192&&octets[1]===168);
  };
  if(!/microsoft/i.test(readFileSync('/proc/sys/kernel/osrelease','utf8'))||
     !privateV4(iface?.address)||!privateV4(peer)){
    throw Object.assign(new Error('Private WSL host interface is unavailable'),{code:'WSL_PRIVATE_NETWORK'});
  }
  return Object.freeze({listenAddress:iface.address,allowedPeer:peer});
}

async function startAuthenticatedGatewayForwarder(gatewayPort,forwardSecret,listenPort=0){
  if(!Buffer.isBuffer(forwardSecret)||forwardSecret.length!==32)throw new TypeError('32-byte relay key required');
  const {listenAddress,allowedPeer}=privateWslAddresses();
  const sockets=new Set();
  const server=createNetServer(socket=>{
    sockets.add(socket);socket.once('close',()=>sockets.delete(socket));
    const remote=socket.remoteAddress?.replace(/^::ffff:/,'');
    if(remote!==allowedPeer||sockets.size>8){socket.destroy();return;}
    const nonce=randomBytes(32);socket.write(nonce);
    let received=Buffer.alloc(0),phase='proof';
    const timer=setTimeout(()=>socket.destroy(),5000);
    const reject=()=>{clearTimeout(timer);socket.destroy();};
    const authenticate=chunk=>{
      received=Buffer.concat([received,chunk]);
      if(phase==='proof'){
        if(received.length<32)return;
        if(received.length!==32){reject();return;}
        const expected=createHmac('sha256',forwardSecret).update(nonce).digest();
        if(!timingSafeEqual(received,expected)){reject();return;}
        received=Buffer.alloc(0);phase='connecting';socket.removeListener('data',authenticate);
        const upstream=createConnection({host:'127.0.0.1',port:gatewayPort});
        sockets.add(upstream);upstream.once('close',()=>sockets.delete(upstream));
        upstream.once('error',reject);
        upstream.once('connect',()=>{
          clearTimeout(timer);phase='stream';socket.removeListener('data',authenticate);
          socket.write(Buffer.from([1]));socket.pipe(upstream);upstream.pipe(socket);
        });
      }
    };
    socket.on('data',authenticate);socket.once('error',()=>clearTimeout(timer));
  });
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(listenPort,listenAddress,resolve);});
  return Object.freeze({host:listenAddress,allowedPeer,port:server.address().port,
    close:async()=>{
      for(const socket of sockets)socket.destroy();
      if(server.listening)await new Promise(resolve=>server.close(resolve));
    }});
}

async function startI7SyntheticPilot(){
  const script=path.join(REPO_ROOT,'scripts/g7-staging-pilot.mjs');
  const child=spawn(process.execPath,[script,'--json'],{cwd:REPO_ROOT,stdio:['ignore','pipe','pipe'],detached:true,
    env:{PATH:process.env.PATH??'/usr/bin:/bin',HOME:process.env.HOME??'',TMPDIR:process.env.TMPDIR??'',
      VPSC_STAGING_TRACE:'1',VPSC_STAGING_MCP_ENTRYPOINT:MCP_ENTRYPOINT}});
  let stdout='',stderr='';
  const markerWaiters=[];
  child.stdout.setEncoding('utf8').on('data',chunk=>{stdout=(stdout+chunk).slice(-200_000);});
  child.stderr.setEncoding('utf8').on('data',chunk=>{
    stderr=(stderr+chunk).slice(-60_000);
    for(const waiter of [...markerWaiters])if(stderr.includes(waiter.marker)){
      markerWaiters.splice(markerWaiters.indexOf(waiter),1);clearTimeout(waiter.timer);waiter.resolve();
    }
  });
  child.once('exit',()=>{for(const waiter of markerWaiters.splice(0)){
    clearTimeout(waiter.timer);waiter.reject(Error(
      `Synthetic I7 pilot exited before ${waiter.marker}: ${stderr.slice(-6000)}`));
  }});
  return {child,waitForMarker(marker,timeoutMs=60_000){
    if(stderr.includes(marker))return Promise.resolve();
    return new Promise((resolve,reject)=>{
      const waiter={marker,resolve,reject,timer:setTimeout(()=>{
        const index=markerWaiters.indexOf(waiter);if(index>=0)markerWaiters.splice(index,1);
        reject(Error(`Timed out waiting for synthetic I7 pilot marker ${marker}`));
      },timeoutMs)};
      markerWaiters.push(waiter);
    });
  },async result(){
    if(child.exitCode===null&&child.signalCode===null)await new Promise(resolve=>child.once('close',resolve));
    if(child.exitCode!==0)throw Error(`Synthetic I7 pilot failed (${child.exitCode}, ${child.signalCode}): ${stderr.slice(-3000)}`);
    const report=JSON.parse(stdout.trim().split('\n').at(-1));
    if(report.status!=='pass_with_limitations'||report.devices?.count!==2||
       report.restart?.agent!==true||report.restart?.gatewayAfterSigkillRecovery!=='RECONCILED_CONSISTENT'){
      throw Error('Synthetic I7 pilot did not certify its disposable runtime');
    }
    return report;
  },async stop(){
    if(child.exitCode!==null||child.signalCode!==null)return;
    try{process.kill(-child.pid,'SIGTERM');}catch{}
    await Promise.race([new Promise(resolve=>child.once('close',resolve)),
      new Promise(resolve=>setTimeout(resolve,5000))]);
    if(child.exitCode===null&&child.signalCode===null){
      try{process.kill(-child.pid,'SIGKILL');}catch{}
      await new Promise(resolve=>child.once('close',resolve));
    }
  }};
}

test('isolated Auth0 realm serves two independent workers while the synthetic I7 runtime restarts',
  {skip:!linuxUnprivileged&&'requires nonroot Linux durable Gateway stores'},async t=>{
    const f=fixture(t,{realtime:true});
    const hostname='g7-i8i.example.test';
    const port=await unusedLoopbackPort();
    assert.notEqual(port,18443,'I8 listener must not reuse the current I7 staging port');
    f.realmConfig.listen.port=port;

    const i7Policy=generateKeyPairSync('ed25519');
    const i7PolicyFingerprint=createHash('sha256').update(
      i7Policy.publicKey.export({type:'spki',format:'der'})).digest('hex');
    f.realmConfig.protectedKeyFingerprints=[i7PolicyFingerprint];
    const i7Tls=makeTlsCertificate(f.protectedRoot,'g7-i7-protected.example.test','i7-protected');
    const i7CertificateFingerprint=createHash('sha256').update(i7Tls.certificate).digest('hex');

    const profiles=['linux-a','linux-b'].map(name=>{
      const directory=path.join(f.home,'realm','workers',name);
      const identityDirectory=path.join(directory,'identity');
      const ledgerDirectory=path.join(directory,'ledger');
      const allowedRoot=path.join(directory,'approved');
      mkdirSync(identityDirectory,{recursive:true,mode:0o700});chmodSync(identityDirectory,0o700);
      mkdirSync(ledgerDirectory,{recursive:true,mode:0o700});chmodSync(ledgerDirectory,0o700);
      mkdirSync(allowedRoot,{recursive:true,mode:0o700});chmodSync(allowedRoot,0o700);
      const identity=loadOrCreateDeviceIdentity({directory:identityDirectory});
      const contents=`I8 synthetic approved content ${name}\n`;
      const proofFile=path.join(allowedRoot,'proof.txt');writeFileSync(proofFile,contents,{mode:0o600,flag:'wx'});
      return {name,directory,identityDirectory,ledgerDirectory,allowedRoot,proofFile,contents,identity,
        clientId:`i8i-${name}.synthetic`,clientSecret:randomUUID()+randomUUID()};
    });
    const tls=makeTlsCertificate(f.paths.runtime,hostname,'i8-gateway');
    assert.notEqual(createHash('sha256').update(tls.certificate).digest('hex'),i7CertificateFingerprint);
    const machineKey=generateKeyPairSync('rsa',{modulusLength:2048});
    const machine={issuer:'https://g7-i8i-machine.cloudflareaccess.com',audience:'c'.repeat(64),
      jwks:[{...machineKey.publicKey.export({format:'jwk'}),kid:'i8i-machine-test',alg:'RS256',use:'sig'}],
      signingKey:machineKey.privateKey,
      clients:profiles.map(({clientId,clientSecret})=>({clientId,serviceSecret:clientSecret}))};
    const policy=generateKeyPairSync('ed25519');
    const storeInspectors={
      audit:()=>{const value=f.auditWriter.inspect();return {healthy:value.pending===0,pending:value.pending,revision:value.sequence};},
      binding:()=>{const value=inspectDurableMachineBindingSnapshot({directory:f.paths.binding});
        return {healthy:!value.lockPresent,pending:0,revision:value.revision};},
      grant:()=>{const value=f.grantStore.inspect();return {healthy:value.locks.every(lock=>lock.status==='absent'),
        pending:0,revision:value.revision};},
      ledger:()=>{const states=profiles.map(profile=>analyzeI4ExecutionRecovery({ledgerDirectory:profile.ledgerDirectory}));
        return {healthy:states.every(value=>value.status==='consistent'),
          pending:states.reduce((sum,value)=>sum+value.unresolved.length+value.ambiguous.length,0),
          revision:states.reduce((sum,value)=>sum+value.recordCount,0)};},
      policy:()=>{const value=f.grantStore.inspect();return {healthy:value.locks.every(lock=>lock.status==='absent'),
        pending:0,revision:value.revision};},
      provisioning:()=>f.provisioner.inspect(),
      trust:()=>{const value=inspectDurableDeviceTrust({directory:f.paths.trust});
        return {healthy:!value.lockPresent&&!value.operationGatePresent&&value.dispatchPermits.length===0&&
          value.temporaryFiles.length===0,pending:0,revision:value.revision};},
    };
    let triggerLateGrantRevocation=false,lateGrantRevoked=false,lateGrantRevocation=null;
    let gateway=null,i7Pilot=null;
    const routerDiagnostics=[];
    const workers=[];
    const readDeviceApproval=createDurableOwnerDeviceApprovalReader({
      auditDirectory:f.paths.audit,trustDirectory:f.paths.trust});
    t.after(async()=>{
      for(const worker of workers)await worker.stop().catch(()=>{});
      await i7Pilot?.stop();
      await gateway?.close();
    });
    const realm=createIsolatedG7Realm({config:f.realmConfig,ownerAuthority:f.authority,storeInspectors,
      startLoopback:async options=>{
        const baseRouter=createDeviceRouter({registry:f.trustStore.registry,timeoutMs:15_000,
          onDiagnostic:event=>routerDiagnostics.push(event)});
        const router={
          attachTransport:value=>baseRouter.attachTransport(value),
          detachTransport:value=>baseRouter.detachTransport(value),
          acceptResponse:value=>baseRouter.acceptResponse(value),
          acceptCancellation:value=>baseRouter.acceptCancellation(value),
          rejectBeforeDelivery:value=>baseRouter.rejectBeforeDelivery(value),
          callDevice:async value=>{
            const result=await baseRouter.callDevice(value);
            if(triggerLateGrantRevocation&&!lateGrantRevoked&&value.name==='read_file'&&
               value.arguments.path===profiles[0].proofFile){
              const grant=f.grantStore.list().find(item=>item.deviceId===profiles[0].deviceId&&item.active);
              if(grant){lateGrantRevocation=revokeReadGrant(f,profiles[0].deviceId,grant.grantId);lateGrantRevoked=true;}
            }
            return result;
          },
          close:()=>baseRouter.close(),
        };
        gateway=await startIsolatedG7AgentGateway({
          config:{hostname,listen:{host:options.host,port:options.port},machine,
            tls:{certificate:tls.certificate,key:tls.key}},
          realmConfig:f.realmConfig,ownerAuthority:f.authority,trustStore:f.trustStore,
          machineBindingStore:f.machineBindingStore,grantStore:f.grantStore,router,
          policySigningKey:policy.privateKey,getTrustRevision:()=>f.trustStore.revision(),
          getDeviceApprovalReceipt:readDeviceApproval,
        });
        return gateway;
      }});
    assert.equal(realm.inspectActivation().ready,false);
    await assert.rejects(realm.activate(),error=>error.code==='REALM_ACTIVATION_BLOCKED'&&
      error.blockers.includes('NO_APPROVED_READ_ONLY_DEVICE'));

    for(const profile of profiles){
      const device=await persistentPairing(f,profile.identity,profile.identityDirectory,
        `Synthetic ${profile.name}`,'linux',profile.clientId);
      Object.assign(profile,device);
      mkdirSync(profile.allowedRoot,{recursive:true,mode:0o700});
      issueGrant(f,profile,profile.allowedRoot);
    }
    assert.equal(realm.inspectActivation().ready,true,JSON.stringify(realm.inspectActivation()));
    await realm.activate();
    for(const profile of profiles){
      const configPath=path.join(profile.directory,'agent.json');
      const config={version:1,deviceId:profile.challenge.deviceId,hostname,identityDirectory:profile.identityDirectory,
        ledgerDirectory:profile.ledgerDirectory,mcpEntrypoint:MCP_ENTRYPOINT,port:gateway.port,
        policyPublicKeyPem:policy.publicKey.export({type:'spki',format:'pem'}),clientId:profile.clientId,
        clientSecret:profile.clientSecret,caPath:tls.certificatePath,allowedRoot:profile.allowedRoot,pollIntervalMs:35};
      writeFileSync(configPath,JSON.stringify(config)+'\n',{mode:0o600,flag:'wx'});chmodSync(configPath,0o600);
      profile.configPath=configPath;
      const worker=startSyntheticWorker(configPath);workers.push(worker);
      assert.equal((await worker.waitFor(value=>value.event==='READY','READY')).deviceId,profile.challenge.deviceId);
      await worker.waitFor(value=>value.event==='ONLINE','ONLINE');
    }

    const ownerHeaders={authorization:`Bearer ${f.tokenFor('g7.read')}`};
    const ownerCall=(id,name,args)=>httpsJson({port:gateway.port,hostname,ca:tls.certificate,
      pathname:'/mcp',payload:{jsonrpc:'2.0',id,method:'tools/call',params:{name,arguments:args}},headers:ownerHeaders});
    const listed=await httpsJson({port:gateway.port,hostname,ca:tls.certificate,pathname:'/mcp',
      payload:{jsonrpc:'2.0',id:'tools-list',method:'tools/list'},headers:ownerHeaders});
    assert.equal(listed.status,200);
    assert.deepEqual(listed.body.result.tools.map(tool=>tool.name),['read_file']);

    const first=await ownerCall('read-a-1','read_file',{deviceId:profiles[0].challenge.deviceId,
      path:profiles[0].proofFile,length:100});
    const second=await ownerCall('read-b-1','read_file',{deviceId:profiles[1].challenge.deviceId,
      path:profiles[1].proofFile,length:100});
    assert.equal(first.status,200,JSON.stringify(first.body));
    assert.equal(second.status,200,JSON.stringify(second.body));
    assert.equal(first.body.result.content[0].text,profiles[0].contents);
    assert.equal(second.body.result.content[0].text,profiles[1].contents);
    assert.notEqual(profiles[0].challenge.deviceId,profiles[1].challenge.deviceId);
    assert.notEqual(profiles[0].identity.fingerprint,profiles[1].identity.fingerprint);
    assert.notEqual(profiles[0].clientId,profiles[1].clientId);
    assert.notEqual(profiles[0].clientSecret,profiles[1].clientSecret);
    assert.notEqual(profiles[0].identityDirectory,profiles[1].identityDirectory);
    assert.notEqual(profiles[0].ledgerDirectory,profiles[1].ledgerDirectory);
    assert.equal(createHash('sha256').update(createPublicKey(policy.privateKey)
      .export({type:'spki',format:'der'})).digest('hex')===i7PolicyFingerprint,false);

    const outside=await ownerCall('outside-root','read_file',{deviceId:profiles[0].challenge.deviceId,
      path:profiles[1].proofFile,length:100});
    assert.equal(outside.status,403);
    const escalation=await ownerCall('tool-escalation','write_file',{deviceId:profiles[0].challenge.deviceId,
      path:path.join(profiles[0].allowedRoot,'created.txt'),content:'denied',mode:'create'});
    assert.equal(escalation.status,400);
    const mismatchedClient=await httpsJson({port:gateway.port,hostname,ca:tls.certificate,
      pathname:'/agent/challenge',payload:{deviceId:profiles[1].challenge.deviceId},
      headers:{'cf-access-client-id':profiles[0].clientId,'cf-access-client-secret':profiles[0].clientSecret}});
    assert.equal(mismatchedClient.status,403);
    const reusedSecret=await httpsJson({port:gateway.port,hostname,ca:tls.certificate,
      pathname:'/agent/challenge',payload:{deviceId:profiles[0].challenge.deviceId},
      headers:{'cf-access-client-id':profiles[0].clientId,'cf-access-client-secret':profiles[1].clientSecret}});
    assert.equal(reusedSecret.status,403);
    const malformedSecret=await httpsJson({port:gateway.port,hostname,ca:tls.certificate,
      pathname:'/agent/challenge',payload:{deviceId:profiles[0].challenge.deviceId},
      headers:{'cf-access-client-id':profiles[0].clientId,
        'cf-access-client-secret':`é${profiles[0].clientSecret.slice(1)}`}});
    assert.equal(malformedSecret.status,403);
    assert.equal((await ownerCall('read-after-malformed-secret','read_file',{
      deviceId:profiles[0].challenge.deviceId,path:profiles[0].proofFile,length:100})).status,200);

    i7Pilot=await startI7SyntheticPilot();
    await i7Pilot.waitForMarker('two independent device agents connected');
    assert.equal(workers.every(worker=>worker.child.exitCode===null),true);
    assert.notEqual(gateway.port,18443);
    assert.notEqual(createHash('sha256').update(tls.certificate).digest('hex'),i7CertificateFingerprint);

    await workers[0].stop('SIGKILL');
    const crashedLedger=workerLedger(profiles[0].ledgerDirectory);
    assert.equal(crashedLedger.state.status,'consistent');
    assert.equal(crashedLedger.state.automaticReplay,false);
    const otherAfterCrash=await ownerCall('read-b-after-a-crash','read_file',{
      deviceId:profiles[1].challenge.deviceId,path:profiles[1].proofFile,length:100});
    assert.equal(otherAfterCrash.status,200);
    const recoveredWorker=startSyntheticWorker(profiles[0].configPath);workers[0]=recoveredWorker;
    assert.equal((await recoveredWorker.waitFor(value=>value.event==='READY','recovered READY')).deviceId,
      profiles[0].challenge.deviceId);
    await recoveredWorker.waitFor(value=>value.event==='ONLINE','recovered ONLINE');
    const recoveredRead=await ownerCall('read-a-after-recovery','read_file',{
      deviceId:profiles[0].challenge.deviceId,path:profiles[0].proofFile,length:100});
    assert.equal(recoveredRead.status,200);
    assert.equal(recoveredRead.body.result.content[0].text,profiles[0].contents,JSON.stringify({
      status:recoveredRead.status,
      response:recoveredRead.body?.result?.content?.map(item=>({type:item.type,text:item.text?.slice(0,96)})),
      router:routerDiagnostics.slice(-8),
      worker:recoveredWorker.events.filter(event=>event.event==='REQUEST_DIAGNOSTIC').slice(-4),
      ledger:workerLedger(profiles[0].ledgerDirectory).records.slice(-6).map(record=>({
        type:record.type,requestId:record.requestId,tool:record.tool,status:record.status,
      })),
    }));
    await i7Pilot.waitForMarker('Gateway graceful restart restored durable state');
    const i8AfterI7Restart=await ownerCall('read-b-after-i7-restart','read_file',{
      deviceId:profiles[1].challenge.deviceId,path:profiles[1].proofFile,length:100});
    assert.equal(i8AfterI7Restart.status,200);
    const i7Report=await i7Pilot.result();
    assert.equal(i7Report.agent.processIndependent,true);
    assert.equal(i7Report.devices.routingIsolation,true);
    assert.equal(i7Report.cleanup.temporaryStateRemoved,true);

    triggerLateGrantRevocation=true;
    const late=await ownerCall('late-result-fence','read_file',{
      deviceId:profiles[0].challenge.deviceId,path:profiles[0].proofFile,length:100});
    assert.equal(lateGrantRevoked,true);
    assert.equal(lateGrantRevocation.active,false);
    assert.equal(late.status,503);
    assert.equal(late.body.error.data.code,'AMBIGUOUS_GRANT_REVOCATION');
    const deniedAfterGrantRevoke=await ownerCall('grant-revoked','read_file',{
      deviceId:profiles[0].challenge.deviceId,path:profiles[0].proofFile,length:100});
    assert.equal(deniedAfterGrantRevoke.status,403);
    const otherAfterGrantRevoke=await ownerCall('other-device-after-grant-revoke','read_file',{
      deviceId:profiles[1].challenge.deviceId,path:profiles[1].proofFile,length:100});
    assert.equal(otherAfterGrantRevoke.status,200);

    const revokeB=revokeTrustedDevice(f,profiles[1].challenge.deviceId);
    assert.equal(revokeB.revoked,true);
    const deniedAfterDeviceRevoke=await ownerCall('device-revoked','read_file',{
      deviceId:profiles[1].challenge.deviceId,path:profiles[1].proofFile,length:100});
    assert.equal(deniedAfterDeviceRevoke.status,403);
    const ownerDigest=f.principal.ownerDigest;
    const ownerTarget={issuer:ISSUER,ownerDigest};
    const ownerRevocationApproval=f.makeApproval({operation:'revoke',expectedRevision:1,
      ownerDigest,targetDigest:ownerAuthorityTargetDigest('revoke',ownerTarget),target:ownerTarget});
    assert.equal(f.authority.revoke({accessToken:f.tokenFor('g7.owner'),
      approval:ownerRevocationApproval}).status,'revoked');
    const deniedAfterOwnerRevoke=await ownerCall('owner-revoked','read_file',{
      deviceId:profiles[0].challenge.deviceId,path:profiles[0].proofFile,length:100});
    assert.equal(deniedAfterOwnerRevoke.status,401);

    for(const profile of profiles){
      const ledger=workerLedger(profile.ledgerDirectory);
      assert.equal(ledger.state.status,'consistent');
      assert.equal(ledger.state.unresolved.length,0);
      assert.equal(ledger.state.ambiguous.length,0);
      assert.equal(ledger.state.automaticReplay,false);
      assert.equal(ledger.state.automaticLockRemoval,false);
      const grouped=new Map();
      for(const record of ledger.records){
        const group=grouped.get(record.requestId)??{intent:0,outcome:0};
        if(record.type==='intent')group.intent++;else if(record.type==='outcome')group.outcome++;
        grouped.set(record.requestId,group);
      }
      assert.equal([...grouped.values()].every(group=>group.intent===1&&group.outcome===1),true);
    }
    assert.equal(profiles.some(profile=>path.resolve(profile.identityDirectory)===path.resolve(profile.ledgerDirectory)),false);
    t.diagnostic(JSON.stringify({realmId:REALM,port:gateway.port,deviceIds:profiles.map(x=>x.challenge.deviceId),
      fingerprints:profiles.map(x=>x.identity.fingerprint),clientIds:profiles.map(x=>x.clientId),
      independentIdentityAndLedgerPaths:true,tlsHostnameVerified:true,tools:['read_file'],
      syntheticI7Pilot:i7Report.status,lateResult:'suppressed-after-grant-revocation',
      noReplay:profiles.every(profile=>workerLedger(profile.ledgerDirectory).state.automaticReplay===false)}));
  });

test('isolated realm provisioning binds fresh device proof, Owner approval, binding and read_file grant',
  {skip:!linuxUnprivileged&&'requires nonroot Linux durable stores'},async t=>{
    const f=fixture(t);
    const device=pairDevice(f,t);
    const binding=await bindDevice(f,device);
    const grant=issueGrant(f,device);
    assert.equal(binding.binding.deviceId,device.challenge.deviceId);
    assert.equal(grant.tool,'read_file');
    assert.equal(grant.ownerDigest,f.principal.ownerDigest);
    assert.deepEqual(grant.scope,{root:ROOT});
    assert.equal(f.provisioner.inspect().healthy,true);
    assert.equal(f.provisioner.inspect().readyDeviceCount,1);
    assert.equal(f.provisioner.inspect().pending,0);
    f.advanceTime(180_000);
    assert.equal(f.provisioner.inspect().healthy,true);
    assert.equal(f.provisioner.inspect().readyDeviceCount,1);
    assert.equal(inspectDurableOwnerAudit({directory:f.paths.provisioning}).events.length,6);
  });

test('read scope, wrong Owner, wrong realm, replay, revision conflict and tool escalation fail closed',
  {skip:!linuxUnprivileged&&'requires nonroot Linux durable stores'},async t=>{
    const f=fixture(t);
    const key=generateKeyPairSync('ed25519');
    const challenge=f.provisioner.startPairing({name:'Synthetic',platform:'linux',
      publicKeyPem:key.publicKey.export({type:'spki',format:'pem'})});
    const proof=sign(null,pairingProofMessage(challenge.requestId,challenge.nonce,
      challenge.fingerprint),key.privateKey).toString('base64url');
    f.provisioner.provePairing(challenge.requestId,proof);
    const target={realmId:REALM,deviceId:challenge.deviceId,requestId:challenge.requestId,
      fingerprint:challenge.fingerprint,trustRevision:0};
    const approval=f.makeApproval({operation:'device.approve',expectedRevision:0,target});
    assert.throws(()=>f.provisioner.approveDevice({accessToken:f.tokenFor('g7.read'),approval,
      requestId:challenge.requestId,deviceId:challenge.deviceId,fingerprint:challenge.fingerprint}),
      error=>error.code==='OWNER_APPROVAL_REQUIRED');
    assert.throws(()=>f.provisioner.approveDevice({accessToken:f.tokenFor('g7.owner','google-oauth2|other'),
      approval,requestId:challenge.requestId,deviceId:challenge.deviceId,fingerprint:challenge.fingerprint}),
      error=>error.code==='OWNER_APPROVAL_REQUIRED');
    const wrongRealm=f.makeApproval({operation:'device.approve',expectedRevision:0,target,
      realmId:'7ef7e14e-6291-4a58-bd25-1707d1f2067f'});
    assert.throws(()=>f.provisioner.approveDevice({accessToken:f.tokenFor(),approval:wrongRealm,
      requestId:challenge.requestId,deviceId:challenge.deviceId,fingerprint:challenge.fingerprint}),
      error=>error.code==='OWNER_APPROVAL_REQUIRED');
    const wrongFingerprint=f.makeApproval({operation:'device.approve',expectedRevision:0,
      target:{...target,fingerprint:'f'.repeat(64)}});
    assert.throws(()=>f.provisioner.approveDevice({accessToken:f.tokenFor(),approval:wrongFingerprint,
      requestId:challenge.requestId,deviceId:challenge.deviceId,fingerprint:challenge.fingerprint}),
      error=>error.code==='OWNER_APPROVAL_REQUIRED');
    const expired=f.makeApproval({operation:'device.approve',expectedRevision:0,target,
      issuedAt:seconds-200,expiresAt:seconds-100});
    assert.throws(()=>f.provisioner.approveDevice({accessToken:f.tokenFor(),approval:expired,
      requestId:challenge.requestId,deviceId:challenge.deviceId,fingerprint:challenge.fingerprint}),
      error=>error.code==='OWNER_APPROVAL_REQUIRED');
    const expiresSoon=f.makeApproval({operation:'device.approve',expectedRevision:0,target,
      issuedAt:seconds,expiresAt:seconds+1});
    f.advanceTime(2_000);
    assert.throws(()=>f.provisioner.approveDevice({accessToken:f.tokenFor(),approval:expiresSoon,
      requestId:challenge.requestId,deviceId:challenge.deviceId,fingerprint:challenge.fingerprint}),
      error=>error.code==='OWNER_APPROVAL_REQUIRED');
    assert.throws(()=>f.provisioner.approveDevice({accessToken:f.tokenFor(),
      requestId:challenge.requestId,deviceId:challenge.deviceId,fingerprint:challenge.fingerprint}),
      error=>error.code==='OWNER_APPROVAL_REQUIRED');
    const accepted=f.provisioner.approveDevice({accessToken:f.tokenFor(),approval,
      requestId:challenge.requestId,deviceId:challenge.deviceId,fingerprint:challenge.fingerprint});
    assert.equal(accepted.trustRevisionAfter,1);
    assert.throws(()=>f.provisioner.approveDevice({accessToken:f.tokenFor(),approval,
      requestId:challenge.requestId,deviceId:challenge.deviceId,fingerprint:challenge.fingerprint}),
      error=>error.code==='PAIRING_DENIED'||error.code==='DUPLICATE_EVENT');
    await bindDevice(f,{challenge,approval});
    const grantApproval=f.makeApproval({operation:'grant.issue',expectedRevision:0,target:{
      realmId:REALM,ownerDigest:f.principal.ownerDigest,deviceId:challenge.deviceId,
      fingerprint:challenge.fingerprint,tool:'write_file',scope:{root:ROOT},
      constraints:{maxBytes:128},policyRevision:0}});
    assert.throws(()=>f.provisioner.issueReadFileGrant({accessToken:f.tokenFor(),
      approval:grantApproval,deviceId:challenge.deviceId,fingerprint:challenge.fingerprint,
      root:ROOT,constraints:CONSTRAINTS,expectedRevision:0}),
      error=>error.code==='OWNER_APPROVAL_REQUIRED');
    assert.equal(f.grantStore.revision(),0);
  });

test('grant and device revocation independently close the activation eligibility gate',
  {skip:!linuxUnprivileged&&'requires nonroot Linux durable stores'},async t=>{
    const f=fixture(t);
    const device=pairDevice(f,t);await bindDevice(f,device);const grant=issueGrant(f,device);
    assert.equal(f.provisioner.inspect().readyDeviceCount,1);
    const revokeTarget={realmId:REALM,ownerDigest:f.principal.ownerDigest,
      deviceId:device.challenge.deviceId,fingerprint:device.challenge.fingerprint,
      grantId:grant.grantId,policyRevision:f.grantStore.revision()};
    const revokeApproval=f.makeApproval({operation:'grant.revoke',expectedRevision:1,target:revokeTarget});
    f.provisioner.revokeReadFileGrant({accessToken:f.tokenFor(),approval:revokeApproval,
      deviceId:device.challenge.deviceId,grantId:grant.grantId,expectedRevision:1});
    assert.equal(f.provisioner.inspect().readyDeviceCount,0);
    const renewed=issueGrant(f,device);
    assert.equal(renewed.revision,3);
    assert.equal(f.provisioner.inspect().readyDeviceCount,1);
    const deviceTarget={realmId:REALM,ownerDigest:f.principal.ownerDigest,
      deviceId:device.challenge.deviceId,fingerprint:device.challenge.fingerprint,trustRevision:1};
    const deviceApproval=f.makeApproval({operation:'device.revoke',expectedRevision:1,target:deviceTarget});
    f.provisioner.revokeDevice({accessToken:f.tokenFor(),approval:deviceApproval,
      deviceId:device.challenge.deviceId,expectedRevision:1});
    assert.equal(f.provisioner.inspect().readyDeviceCount,0);
  });

test('crash after approval intent is reconciled not_applied and cannot be replayed',
  {skip:!linuxUnprivileged&&'requires nonroot Linux durable stores'},t=>{
    const f=fixture(t,{testHooks:{afterPhase(stage){if(stage==='approval-intent')throw Error('injected crash');}}});
    const key=generateKeyPairSync('ed25519');
    const challenge=f.provisioner.startPairing({name:'Synthetic',platform:'linux',
      publicKeyPem:key.publicKey.export({type:'spki',format:'pem'})});
    const proof=sign(null,pairingProofMessage(challenge.requestId,challenge.nonce,
      challenge.fingerprint),key.privateKey).toString('base64url');
    f.provisioner.provePairing(challenge.requestId,proof);
    const target={realmId:REALM,deviceId:challenge.deviceId,requestId:challenge.requestId,
      fingerprint:challenge.fingerprint,trustRevision:0};
    const approval=f.makeApproval({operation:'device.approve',expectedRevision:0,target});
    assert.throws(()=>f.provisioner.approveDevice({accessToken:f.tokenFor(),approval,
      requestId:challenge.requestId,deviceId:challenge.deviceId,fingerprint:challenge.fingerprint}),/injected crash/);
    f.auditWriter.close();
    assert.equal(f.trustStore.revision(),0);
    assert.equal(inspectDurableOwnerAudit({directory:f.paths.provisioning}).pending.length,1);
    f.advanceTime(180_000);
    const recovered=f.provisioner.reconcile({operatorConfirmedNoActiveWriters:true});
    assert.equal(recovered.state,'RECONCILED_NOT_APPLIED');
    assert.throws(()=>f.provisioner.approveDevice({accessToken:f.tokenFor(),approval,
      requestId:challenge.requestId,deviceId:challenge.deviceId,fingerprint:challenge.fingerprint}),
      error=>error.code==='DUPLICATE_EVENT'||error.code==='PROVISIONING_UNAVAILABLE');
    assert.equal(inspectDurableOwnerAudit({directory:f.paths.provisioning}).pending.length,0);
    assert.equal(f.trustStore.revision(),0);
    assert.equal(inspectDurableOwnerAudit({directory:f.paths.provisioning}).events.at(-1).outcome,'not_applied');
  });

test('committed pairing with a lost audit outcome reconciles from the exact trust transition',
  {skip:!linuxUnprivileged&&'requires nonroot Linux durable stores'},t=>{
    const f=fixture(t,{testHooks:{afterPhase(stage){if(stage==='device-trust-committed')throw Error('injected crash');}}});
    const key=generateKeyPairSync('ed25519');
    const challenge=f.provisioner.startPairing({name:'Synthetic',platform:'linux',
      publicKeyPem:key.publicKey.export({type:'spki',format:'pem'})});
    const proof=sign(null,pairingProofMessage(challenge.requestId,challenge.nonce,
      challenge.fingerprint),key.privateKey).toString('base64url');
    f.provisioner.provePairing(challenge.requestId,proof);
    const target={realmId:REALM,deviceId:challenge.deviceId,requestId:challenge.requestId,
      fingerprint:challenge.fingerprint,trustRevision:0};
    const approval=f.makeApproval({operation:'device.approve',expectedRevision:0,target});
    assert.throws(()=>f.provisioner.approveDevice({accessToken:f.tokenFor(),approval,
      requestId:challenge.requestId,deviceId:challenge.deviceId,fingerprint:challenge.fingerprint}),/injected crash/);
    f.auditWriter.close();
    const result=f.provisioner.reconcile({operatorConfirmedNoActiveWriters:true});
    assert.equal(result.state,'RECONCILED_APPLIED');
    assert.equal(f.trustStore.revision(),1);
    assert.equal(inspectDurableOwnerAudit({directory:f.paths.audit}).pending.length,0);
    assert.equal(inspectDurableOwnerAudit({directory:f.paths.provisioning}).events.at(-1).outcome,'applied');
  });

test('machine binding crash before snapshot is durably reconciled as not applied',
  {skip:!linuxUnprivileged&&'requires nonroot Linux durable stores'},async t=>{
    const f=fixture(t,{bindingTestHooks:{afterDurableWrite(stage){
      if(stage==='after-intent')throw Error('injected binding crash before store commit');
    }}});
    const device=pairDevice(f,t);
    const target={realmId:REALM,ownerDigest:f.principal.ownerDigest,clientId:'i8h-synthetic-client',
      deviceId:device.challenge.deviceId,fingerprint:device.challenge.fingerprint,
      bindingRevision:0,pairingEventId:device.approval.eventId};
    const approval=f.makeApproval({operation:'binding.create',expectedRevision:0,target});
    await assert.rejects(f.provisioner.bindDevice({accessToken:f.tokenFor(),approval,
      clientId:target.clientId,deviceId:target.deviceId,fingerprint:target.fingerprint,
      expectedRevision:0}),error=>error.code==='AUDIT_UNAVAILABLE');
    f.auditWriter.close();
    const recovered=f.provisioner.reconcile({operatorConfirmedNoActiveWriters:true});
    assert.equal(recovered.state,'RECONCILED_NOT_APPLIED');
    assert.equal(inspectDurableMachineBindingSnapshot({directory:f.paths.binding}).revision,0);
    assert.deepEqual(inspectDurableMachineBindingSnapshot({directory:f.paths.binding}).bindings,[]);
  });

test('machine binding crash after atomic snapshot is reconciled as accepted',
  {skip:!linuxUnprivileged&&'requires nonroot Linux durable stores'},async t=>{
    const f=fixture(t,{bindingTestHooks:{afterDurableWrite(stage){
      if(stage==='after-store-commit')throw Error('injected binding crash after store commit');
    }}});
    const device=pairDevice(f,t);
    const target={realmId:REALM,ownerDigest:f.principal.ownerDigest,clientId:'i8h-synthetic-client',
      deviceId:device.challenge.deviceId,fingerprint:device.challenge.fingerprint,
      bindingRevision:0,pairingEventId:device.approval.eventId};
    const approval=f.makeApproval({operation:'binding.create',expectedRevision:0,target});
    await assert.rejects(f.provisioner.bindDevice({accessToken:f.tokenFor(),approval,
      clientId:target.clientId,deviceId:target.deviceId,fingerprint:target.fingerprint,
      expectedRevision:0}),error=>error.code==='BINDING_OUTCOME_UNKNOWN');
    f.auditWriter.close();
    const recovered=f.provisioner.reconcile({operatorConfirmedNoActiveWriters:true});
    assert.equal(recovered.state,'RECONCILED_APPLIED');
    const snapshot=inspectDurableMachineBindingSnapshot({directory:f.paths.binding});
    assert.equal(snapshot.revision,1);
    assert.equal(snapshot.bindings[0].deviceId,device.challenge.deviceId);
  });

test('grant issue crash reconciles the committed grant without replay',
  {skip:!linuxUnprivileged&&'requires nonroot Linux durable stores'},async t=>{
    const f=fixture(t,{testHooks:{afterPhase(stage){if(stage==='grant-issued')throw Error('injected grant issue crash');}}});
    const device=pairDevice(f,t);await bindDevice(f,device);
    const expectedRevision=f.grantStore.revision();
    const grant={ownerDigest:f.principal.ownerDigest,deviceId:device.challenge.deviceId,
      fingerprint:device.challenge.fingerprint,tool:'read_file',scope:{root:ROOT},constraints:CONSTRAINTS};
    const target={realmId:REALM,...grant,policyRevision:expectedRevision};
    const approval=f.makeApproval({operation:'grant.issue',expectedRevision,target});
    assert.throws(()=>f.provisioner.issueReadFileGrant({accessToken:f.tokenFor(),approval,
      deviceId:grant.deviceId,fingerprint:grant.fingerprint,root:ROOT,
      constraints:CONSTRAINTS,expectedRevision}),/injected grant issue crash/);
    f.auditWriter.close();
    const recovered=f.provisioner.reconcile({operatorConfirmedNoActiveWriters:true});
    assert.equal(recovered.state,'RECONCILED_APPLIED');
    const stored=f.grantStore.inspect().grants.find(value=>value.eventId===approval.eventId);
    assert.equal(stored.active,true);
    assert.equal(stored.tool,'read_file');
    assert.equal(stored.scope.root,ROOT);
    assert.equal(inspectDurableOwnerAudit({directory:f.paths.provisioning}).events.at(-1).outcome,'applied');
  });

test('grant revocation crash reconciles the exact policy event without reapplying it',
  {skip:!linuxUnprivileged&&'requires nonroot Linux durable stores'},async t=>{
    const f=fixture(t,{testHooks:{afterPhase(stage){if(stage==='grant-revoked')throw Error('injected grant revoke crash');}}});
    const device=pairDevice(f,t);await bindDevice(f,device);const grant=issueGrant(f,device);
    const expectedRevision=f.grantStore.revision();
    const target={realmId:REALM,ownerDigest:f.principal.ownerDigest,
      deviceId:device.challenge.deviceId,fingerprint:device.challenge.fingerprint,
      grantId:grant.grantId,policyRevision:expectedRevision};
    const approval=f.makeApproval({operation:'grant.revoke',expectedRevision,target});
    assert.throws(()=>f.provisioner.revokeReadFileGrant({accessToken:f.tokenFor(),approval,
      deviceId:device.challenge.deviceId,grantId:grant.grantId,expectedRevision}),/injected grant revoke crash/);
    f.auditWriter.close();
    const recovered=f.provisioner.reconcile({operatorConfirmedNoActiveWriters:true});
    assert.equal(recovered.state,'RECONCILED_APPLIED');
    const stored=f.grantStore.inspect().grants.find(value=>value.grantId===grant.grantId);
    assert.equal(stored.active,false);
    assert.equal(stored.revokedEventId,approval.eventId);
    assert.equal(inspectDurableOwnerAudit({directory:f.paths.provisioning}).events.at(-1).outcome,'applied');
  });

test('device revocation crash reconciles its exact trust event without restoring trust',
  {skip:!linuxUnprivileged&&'requires nonroot Linux durable stores'},async t=>{
    const f=fixture(t,{testHooks:{afterPhase(stage){if(stage==='device-revoked')throw Error('injected device revoke crash');}}});
    const device=pairDevice(f,t);await bindDevice(f,device);issueGrant(f,device);
    const expectedRevision=f.trustStore.revision();
    const target={realmId:REALM,ownerDigest:f.principal.ownerDigest,
      deviceId:device.challenge.deviceId,fingerprint:device.challenge.fingerprint,
      trustRevision:expectedRevision};
    const approval=f.makeApproval({operation:'device.revoke',expectedRevision,target});
    assert.throws(()=>f.provisioner.revokeDevice({accessToken:f.tokenFor(),approval,
      deviceId:device.challenge.deviceId,expectedRevision}),/injected device revoke crash/);
    f.auditWriter.close();
    const recovered=f.provisioner.reconcile({operatorConfirmedNoActiveWriters:true});
    assert.equal(recovered.state,'RECONCILED_APPLIED');
    const trust=inspectDurableDeviceTrust({directory:f.paths.trust});
    assert.equal(trust.revision,expectedRevision+1);
    assert.equal(trust.devices.some(value=>value.deviceId===device.challenge.deviceId),false);
    assert.equal(inspectDurableOwnerAudit({directory:f.paths.provisioning}).events.at(-1).outcome,'applied');
  });

test('Owner read_file grant roots must match the paired device platform',
  {skip:!linuxUnprivileged&&'requires nonroot Linux durable stores'},async t=>{
    const f=fixture(t);
    const linux=pairDevice(f,t);await bindDevice(f,linux,'i8i-linux-client');
    assert.throws(()=>issueGrant(f,linux,'C:\\Users\\synthetic\\approved'),
      error=>error.code==='GRANT_DENIED');
    assert.equal(f.grantStore.revision(),0,'platform mismatch cannot write grant state');
    const windows=pairDevice(f,t,{platform:'win32'});
    await bindDevice(f,windows,'i8i-windows-client');
    const windowsGrant=issueGrant(f,windows,'C:\\Users\\synthetic\\approved');
    assert.equal(f.grantStore.list().find(value=>value.grantId===windowsGrant.grantId).scope.root,
      'C:\\Users\\synthetic\\approved');
    assert.throws(()=>issueGrant(f,windows,ROOT),error=>error.code==='GRANT_DENIED');
    assert.equal(f.grantStore.revision(),1,'reverse platform mismatch cannot write grant state');
  });

test('native Windows I8 worker uses private authenticated forwarding to an isolated Linux Gateway',{
  skip:!(process.platform==='linux'&&linuxUnprivileged&&
    process.env.VPSC_I8I_WINDOWS_TO_LINUX_E2E==='1')&&
      'set VPSC_I8I_WINDOWS_TO_LINUX_E2E=1 in nonroot WSL to run native cross-platform E2E',
},async t=>{
  const f=fixture(t,{realtime:true});
  const runId=randomUUID();
  const controller=startNativeWindowsController(runId);
  let gateway=null,forwarder=null,i7Pilot=null;
  const relaySecret=randomBytes(32);
  try{
    i7Pilot=await startI7SyntheticPilot();
    await i7Pilot.waitForMarker('two independent device agents connected');
    const identity=await controller.waitFor(value=>value.type==='identity','DPAPI identity');
    const proofDiagnostics=await controller.send({op:'proof-diagnostics'});
    assert.equal(proofDiagnostics.diskBytes,identity.proofBytes);
    assert.equal(proofDiagnostics.diskSha256,identity.proofSha256);
    assert.equal(proofDiagnostics.secureBytes,identity.proofBytes);
    assert.equal(proofDiagnostics.secureSha256,identity.proofSha256);
    let windowsLedger=await controller.send({op:'ledger'});
    assert.equal(windowsLedger.status,'consistent');
    assert.equal(windowsLedger.automaticReplay,false);
    const clientId=`i8i-windows-${randomUUID()}`;
    const clientSecret=randomUUID()+randomUUID();
    const hostname='g7-i8i-windows.example.test';
    const port=await unusedLoopbackPort();
    assert.notEqual(port,18443,'isolated listener must not reuse the I7 staging port');
    f.realmConfig.listen.port=port;

    const tls=makeTlsCertificate(f.paths.runtime,hostname,'i8-windows-gateway');
    const machineKey=generateKeyPairSync('rsa',{modulusLength:2048});
    const machine={issuer:'https://g7-i8i-machine.cloudflareaccess.com',audience:'d'.repeat(64),
      jwks:[{...machineKey.publicKey.export({format:'jwk'}),kid:'i8i-windows-machine-test',
        alg:'RS256',use:'sig'}],signingKey:machineKey.privateKey,
      clients:[{clientId,serviceSecret:clientSecret}]};
    const policy=generateKeyPairSync('ed25519');

    const challenge=f.provisioner.startPairing({name:'Synthetic native Windows I8',platform:'win32',
      publicKeyPem:identity.publicKeyPem});
    const proof=await controller.send({op:'prove',challenge});
    assert.equal(f.provisioner.provePairing(challenge.requestId,proof.proof),true);
    const approvalTarget={realmId:REALM,deviceId:challenge.deviceId,requestId:challenge.requestId,
      fingerprint:challenge.fingerprint,trustRevision:f.trustStore.revision()};
    const pairingApproval=f.makeApproval({operation:'device.approve',
      expectedRevision:approvalTarget.trustRevision,target:approvalTarget});
    f.provisioner.approveDevice({accessToken:f.tokenFor(),approval:pairingApproval,
      requestId:challenge.requestId,deviceId:challenge.deviceId,fingerprint:challenge.fingerprint});
    const binding=await bindDevice(f,{challenge,approval:pairingApproval},clientId);
    assert.equal((await controller.send({op:'bind',machineBinding:binding.binding})).bound,true);
    const device={challenge:{deviceId:challenge.deviceId,fingerprint:challenge.fingerprint}};
    let activeGrant=issueGrant(f,device,identity.allowedRoot);
    const approvalReader=createDurableOwnerDeviceApprovalReader({
      auditDirectory:f.paths.audit,trustDirectory:f.paths.trust});
    // Native Windows durable boundaries each verify NTFS ACLs through a PowerShell helper.
    const routerDiagnostics=[];
    const baseRouter=createDeviceRouter({registry:f.trustStore.registry,timeoutMs:30_000,
      onDiagnostic:event=>routerDiagnostics.push(event)});
    const dispatches=[],resultSubmissions=[],dispatchOutcomes=[];
    let revokeAfterResult=false,lateRevocation=null;
    const lateRevocationTrigger={armed:false,toolMatches:null,pathMatches:null};
    const router={
      attachTransport:value=>baseRouter.attachTransport(value),
      detachTransport:value=>baseRouter.detachTransport(value),
      acceptResponse:value=>{
        const accepted=baseRouter.acceptResponse(value);
        resultSubmissions.push({requestId:value.requestId,accepted});return accepted;
      },
      acceptCancellation:value=>baseRouter.acceptCancellation(value),
      rejectBeforeDelivery:value=>baseRouter.rejectBeforeDelivery(value),
      callDevice:async value=>{
        dispatches.push({requestId:value.requestId,deviceId:value.deviceId,name:value.name,
          startedAt:Date.now()});
        let result;
        try{result=await baseRouter.callDevice(value);dispatchOutcomes.push({requestId:value.requestId,
          outcomeCode:'ACCEPTED'});}
        catch(error){dispatchOutcomes.push({requestId:value.requestId,
          outcomeCode:/^[A-Z_]{1,48}$/.test(error?.code??'')?error.code:'UNKNOWN'});throw error;}
        if(revokeAfterResult){
          lateRevocationTrigger.armed=true;
          lateRevocationTrigger.toolMatches=value.name==='read_file';
          lateRevocationTrigger.pathMatches=value.arguments.path===identity.proofFile;
          if(lateRevocationTrigger.toolMatches&&lateRevocationTrigger.pathMatches){
            revokeAfterResult=false;
            lateRevocation=revokeReadGrant(f,challenge.deviceId,activeGrant.grantId);
          }
        }
        return result;
      },close:()=>baseRouter.close(),
    };
    const inspectors={
      audit:()=>{const value=f.auditWriter.inspect();return {healthy:value.pending===0,pending:value.pending,revision:value.sequence};},
      binding:()=>{const value=inspectDurableMachineBindingSnapshot({directory:f.paths.binding});
        return {healthy:!value.lockPresent,pending:0,revision:value.revision};},
      grant:()=>{const value=f.grantStore.inspect();return {healthy:value.locks.every(lock=>lock.status==='absent'),
        pending:0,revision:value.revision};},
      ledger:()=>({healthy:windowsLedger.status==='consistent',
        pending:windowsLedger.unresolvedCount+windowsLedger.ambiguousCount,revision:windowsLedger.recordCount}),
      policy:()=>{const value=f.grantStore.inspect();return {healthy:value.locks.every(lock=>lock.status==='absent'),
        pending:0,revision:value.revision};},
      provisioning:()=>f.provisioner.inspect(),
      trust:()=>{const value=inspectDurableDeviceTrust({directory:f.paths.trust});
        return {healthy:!value.lockPresent&&!value.operationGatePresent&&value.dispatchPermits.length===0&&
          value.temporaryFiles.length===0,pending:0,revision:value.revision};},
    };
    const realm=createIsolatedG7Realm({config:f.realmConfig,ownerAuthority:f.authority,
      storeInspectors:inspectors,startLoopback:async options=>{
        const baseConfig={hostname,listen:{host:options.host,port:options.port},machine,
          tls:{certificate:tls.certificate,key:tls.key}};
        await assert.rejects(startIsolatedG7AgentGateway({config:{...baseConfig,
          listen:{host:options.host,port:options.port+1}},realmConfig:f.realmConfig,
          ownerAuthority:f.authority,trustStore:f.trustStore,machineBindingStore:f.machineBindingStore,
          grantStore:f.grantStore,router:{callDevice(){},close(){}},policySigningKey:policy.privateKey,
          getTrustRevision:()=>f.trustStore.revision(),getDeviceApprovalReceipt:approvalReader}),
          error=>error.code==='REALM_LISTENER_MISMATCH');
        gateway=await startIsolatedG7AgentGateway({config:baseConfig,realmConfig:f.realmConfig,
          ownerAuthority:f.authority,trustStore:f.trustStore,machineBindingStore:f.machineBindingStore,
          grantStore:f.grantStore,router,policySigningKey:policy.privateKey,
          getTrustRevision:()=>f.trustStore.revision(),getDeviceApprovalReceipt:approvalReader});
        return gateway;
      }});
    assert.equal(realm.inspectActivation().ready,true);
    gateway=await realm.activate();
    assert.equal(gateway.host,'127.0.0.1');
    assert.equal(gateway.port,f.realmConfig.listen.port);

    forwarder=await startAuthenticatedGatewayForwarder(gateway.port,relaySecret);
    assert.equal(forwarder.allowedPeer,privateWslAddresses().allowedPeer);
    assert.notEqual(forwarder.host,'0.0.0.0');
    await controller.send({op:'start',deviceId:challenge.deviceId,clientId,clientSecret,hostname,
      caPem:tls.certificate.toString('utf8'),policyPublicKeyPem:policy.publicKey.export({type:'spki',format:'pem'}),
      mcpEntrypoint:path.win32.join(controller.windowsRoot,'packages','vpsc-agent','test',
        'fixtures-readonly-mcp.mjs'),forwardHost:forwarder.host,forwardPort:forwarder.port,
      hmacSecret:relaySecret.toString('base64url')});
    const ready=await controller.waitFor(value=>value.type==='worker'&&value.event.event==='READY',
      'worker READY',35_000);
    assert.equal(ready.event.deviceId,challenge.deviceId);
    await controller.waitFor(value=>value.type==='worker'&&value.event.event==='ONLINE','worker ONLINE');
    const identityAfter=await controller.send({op:'identity'});
    assert.equal(identityAfter.fingerprint,identity.fingerprint);
    assert.equal(identityAfter.deviceId,challenge.deviceId);
    assert.equal(identityAfter.clientId,clientId);
    assert.equal(identityAfter.bindingRevision,binding.binding.bindingRevision);

    const wrongHost=await controller.send({op:'probe',kind:'hostname'});
    const wrongCaCertificate=makeTlsCertificate(f.paths.runtime,'wrong-i8i.example.test','wrong-i8i-ca');
    const wrongCa=await controller.send({op:'probe',kind:'ca',caPem:wrongCaCertificate.certificate.toString('utf8')});
    const wrongCredentials=await controller.send({op:'probe',kind:'credentials'});
    assert.equal(wrongHost.tls,'rejected');
    assert.equal(wrongCa.tls,'rejected');
    assert.equal(wrongCredentials.status,403);

    const ownerHeaders={authorization:`Bearer ${f.tokenFor('g7.read')}`};
    const ownerCall=(id,name,args,signal)=>httpsJson({port:gateway.port,hostname,ca:tls.certificate,
      pathname:'/mcp',payload:{jsonrpc:'2.0',id,method:'tools/call',params:{name,arguments:args}},
      headers:ownerHeaders,timeoutMs:35_000,...(signal?{signal}:{})});
    const assertSingleDelivery=requestId=>{
      const diagnostics=controller.events.filter(value=>value.type==='worker'&&
        value.event.event==='REQUEST_DIAGNOSTIC'&&value.event.requestId===requestId);
      assert.equal(diagnostics.filter(value=>value.event.phase==='execution'&&
        value.event.outcomeCode==='STARTED').length,1);
      assert.equal(diagnostics.filter(value=>value.event.route==='/agent/result'&&
        value.event.phase==='submission'&&value.event.outcomeCode==='STARTED').length,1);
      assert.equal(resultSubmissions.filter(value=>value.requestId===requestId&&value.accepted).length,1);
    };
    const list=await httpsJson({port:gateway.port,hostname,ca:tls.certificate,pathname:'/mcp',
      payload:{jsonrpc:'2.0',id:'windows-tools-list',method:'tools/list'},headers:ownerHeaders});
    assert.equal(list.status,200);
    assert.deepEqual(list.body.result.tools.map(tool=>tool.name),['read_file']);
    const securityEventOffset=controller.events.length;
    const first=await ownerCall('windows-read-1','read_file',{deviceId:challenge.deviceId,
      path:identity.proofFile,length:100});
    const firstRequest=dispatches.at(-1)?.requestId;
    const firstElapsedMs=Date.now()-(dispatches.at(-1)?.startedAt??Date.now());
    const firstLedger=await controller.send({op:'ledger',requestId:firstRequest});
    const firstDiagnostics=controller.events.filter(value=>value.type==='worker'&&
      value.event.event==='REQUEST_DIAGNOSTIC'&&value.event.requestId===firstRequest)
      .map(value=>({phase:value.event.phase,route:value.event.route,outcomeCode:value.event.outcomeCode}));
    assert.equal(first.status,200,JSON.stringify({mcpError:first.body?.error&&{
      code:first.body.error.code,dataCode:first.body.error.data?.code,message:first.body.error.message},
      firstRequest,firstElapsedMs,firstLedger,firstDiagnostics}));
    assert.ok(firstElapsedMs<30_000,`Windows read exceeded the 30-second route budget (${firstElapsedMs} ms)`);
    const firstText=first.body.result.content[0].text;
    const firstBytes=Buffer.byteLength(firstText,'utf8');
    const firstSha256=createHash('sha256').update(firstText,'utf8').digest('hex');
    const expectedText=`I8 native Windows proof ${runId}\n`;
    assert.equal(firstBytes,identity.proofBytes,JSON.stringify({firstBytes,firstSha256,
      expectedBytes:identity.proofBytes,expectedSha256:identity.proofSha256,proofDiagnostics,
      firstLedger,firstDiagnostics,isError:first.body.result.isError===true,
      matchesExpectedPrefix:firstText===expectedText.slice(0,firstText.length),
      startsWithFixturePrefix:firstText.startsWith('I8 native Windows proof '),
      includesRunId:firstText.includes(runId)}));
    assert.equal(firstSha256,identity.proofSha256);
    const firstAck=await controller.waitFor(value=>value.type==='worker'&&
      value.event.event==='REQUEST_DIAGNOSTIC'&&value.event.requestId===firstRequest&&
      value.event.route==='/agent/result'&&value.event.phase==='acknowledgement'&&
      value.event.outcomeCode==='ACCEPTED','first result acknowledgement');
    assert.equal(firstAck.event.deviceId,challenge.deviceId);
    assert.equal(dispatches.filter(value=>value.requestId===firstRequest).length,1);
    assertSingleDelivery(firstRequest);
    try{
      await controller.waitFor(value=>controller.events.indexOf(value)>=securityEventOffset&&
        value.type==='worker'&&value.event.event==='FIXTURE_CLIENT_CALL'&&
          value.event.method==='pollControl'&&value.event.outcome==='success'&&
          value.event.hasFrame===false&&value.event.hasCancel===false,
        'worker idle poll after first result');
    }catch(error){
      const recentDiagnostics=controller.events.filter(value=>value.type==='worker'&&
        value.event.event==='REQUEST_DIAGNOSTIC').slice(-20).map(value=>({requestId:value.event.requestId,
          phase:value.event.phase,route:value.event.route,outcomeCode:value.event.outcomeCode}));
      const recentDispatches=dispatches.slice(-8).map(({requestId,name})=>({requestId,name}));
      const state=await controller.send({op:'ledger'});
      throw Error(JSON.stringify({waitError:error.message,state,recentDispatches,
        recentDiagnostics}));
    }
    windowsLedger=await controller.send({op:'ledger',requestId:firstRequest});
    assert.equal(windowsLedger.status,'consistent');
    assert.equal(windowsLedger.automaticReplay,false);
    assert.deepEqual(windowsLedger.requestRecords.map(value=>value.type),['intent','outcome']);

    const outside=await ownerCall('windows-outside-root','read_file',{deviceId:challenge.deviceId,
      path:identity.outsideFile,length:100});
    assert.equal(outside.status,403);
    const escalated=await ownerCall('windows-tool-escalation','run_command',{
      deviceId:challenge.deviceId,command:'whoami'});
    assert.equal(escalated.status,400);

    const cancellation=new AbortController();
    const cancelDispatchOffset=dispatches.length;
    let cancelResponse=null;
    const cancelCall=ownerCall('windows-cancel-before-execution','read_file',{
      deviceId:challenge.deviceId,path:identity.cancelFile,length:100},cancellation.signal).then(value=>{
      cancelResponse={status:value.status,errorCode:/^[A-Z_]{1,48}$/.test(value.body?.error?.data?.code??'')
        ?value.body.error.data.code:null,jsonRpcCode:Number.isInteger(value.body?.error?.code)
          ?value.body.error.code:null};
      return value;
    });
    let cancelReceived;
    try{
      cancelReceived=await controller.waitFor(value=>value.type==='worker'&&
        value.event.event==='FIXTURE_OPERATION_RECEIVED','cancelled operation delivery');
    }catch(error){
      cancellation.abort();
      const cancelCallResult=await cancelCall.then(()=>({status:'resolved'}),failure=>({
        status:'rejected',code:/^[A-Z_]{1,48}$/.test(failure?.code??'')?failure.code:'UNKNOWN'}));
      const cancelRequest=dispatches.slice(cancelDispatchOffset).at(-1)?.requestId;
      const cancelLedger=cancelRequest?await controller.send({op:'ledger',requestId:cancelRequest}):null;
      const cancelDiagnostics=cancelRequest?controller.events.filter(value=>value.type==='worker'&&
        value.event.event==='REQUEST_DIAGNOSTIC'&&value.event.requestId===cancelRequest)
        .map(value=>({phase:value.event.phase,route:value.event.route,outcomeCode:value.event.outcomeCode})):[];
      const matchingDispatch=dispatches.find(value=>value.requestId===cancelRequest);
      throw Error(JSON.stringify({waitError:error.message,cancelCallResult,http:cancelResponse,
        cancelRequest,cancelLedger,cancelDiagnostics,matchingDispatch:matchingDispatch&&{
          deviceId:matchingDispatch.deviceId,name:matchingDispatch.name},
        dispatchOutcome:dispatchOutcomes.filter(value=>value.requestId===cancelRequest),
        routerDiagnostics:routerDiagnostics.filter(value=>value.requestId===cancelRequest)}));
    }
    const cancelledRequest=cancelReceived.event.requestId;
    cancellation.abort();
    await assert.rejects(cancelCall,error=>['ABORT_ERR','ECONNRESET'].includes(error.code));
    await controller.waitFor(value=>value.type==='worker'&&
      value.event.event==='FIXTURE_CANCEL_BEFORE_EXECUTION'&&value.event.requestId===cancelledRequest,
      'cancellation before executor start');
    const cancelAck=await controller.waitFor(value=>value.type==='worker'&&
      value.event.event==='FIXTURE_CANCEL_ACK'&&value.event.requestId===cancelledRequest,
      'cancellation acknowledgement');
    assert.equal(cancelAck.event.accepted,true);
    const cancelledLedger=await controller.send({op:'ledger',requestId:cancelledRequest});
    assert.equal(cancelledLedger.requestRecords.filter(value=>value.type==='intent').length,0);
    const afterCancel=await ownerCall('windows-read-after-cancel','read_file',{
      deviceId:challenge.deviceId,path:identity.proofFile,length:100});
    assert.equal(afterCancel.status,200);
    const afterCancelRequest=dispatches.at(-1).requestId;
    assertSingleDelivery(afterCancelRequest);

    const beforeRestart=await controller.send({op:'ledger'});
    const identityBeforeRestart=await controller.send({op:'identity'});
    const restartEventOffset=controller.events.length;
    const stopped=await controller.send({op:'stop_worker'});
    assert.equal(stopped.stopped,true);
    const restarted=await controller.send({op:'restart_worker'});
    assert.equal(restarted.started,true);
    await controller.waitFor(value=>controller.events.indexOf(value)>=restartEventOffset&&
      value.type==='worker'&&value.event.event==='READY'&&
      value.event.pid===restarted.pid,'worker restart READY',35_000);
    await controller.waitFor(value=>controller.events.indexOf(value)>=restartEventOffset&&
      value.type==='worker'&&value.event.event==='ONLINE'&&value.event.deviceId===challenge.deviceId,
      'worker restart ONLINE');
    await controller.waitFor(value=>controller.events.indexOf(value)>=restartEventOffset&&
      value.type==='worker'&&value.event.event==='FIXTURE_CLIENT_CALL'&&
      value.event.method==='pollControl'&&value.event.outcome==='success'&&
      value.event.hasFrame===false&&value.event.hasCancel===false,
      'worker restart idle poll');
    const identityAfterRestart=await controller.send({op:'identity'});
    for(const key of ['fingerprint','deviceId','clientId','bindingRevision']){
      assert.equal(identityAfterRestart[key],identityBeforeRestart[key],
        `Windows identity field changed across restart: ${key}`);
    }
    const afterRestart=await controller.send({op:'ledger'});
    assert.equal(afterRestart.status,'consistent');
    assert.equal(afterRestart.automaticReplay,false);
    assert.equal(afterRestart.recordCount,beforeRestart.recordCount);
    const restartedRead=await ownerCall('windows-read-after-restart','read_file',{
      deviceId:challenge.deviceId,path:identity.proofFile,length:100});
    const restartedRequest=dispatches.at(-1).requestId;
    const restartedLedger=await controller.send({op:'ledger',requestId:restartedRequest});
    const restartedDiagnostics=controller.events.filter(value=>value.type==='worker'&&
      value.event.event==='REQUEST_DIAGNOSTIC'&&value.event.requestId===restartedRequest)
      .map(value=>({phase:value.event.phase,route:value.event.route,outcomeCode:value.event.outcomeCode}));
    assert.equal(restartedRead.status,200,JSON.stringify({status:restartedRead.status,
      errorCode:restartedRead.body?.error?.data?.code,restartedRequest,restartedLedger,restartedDiagnostics}));
    assertSingleDelivery(restartedRequest);

    revokeAfterResult=true;
    const late=await ownerCall('windows-late-grant-revocation','read_file',{
      deviceId:challenge.deviceId,path:identity.proofFile,length:100});
    const lateRequest=dispatches.at(-1)?.requestId;
    const lateLedgerSnapshot=await controller.send({op:'ledger',requestId:lateRequest});
    const lateDiagnostics=controller.events.filter(value=>value.type==='worker'&&
      value.event.event==='REQUEST_DIAGNOSTIC'&&value.event.requestId===lateRequest)
      .map(value=>({phase:value.event.phase,route:value.event.route,outcomeCode:value.event.outcomeCode}));
    assert.equal(lateRevocation?.active,false,JSON.stringify({lateStatus:late.status,
      lateErrorCode:late.body?.error?.data?.code,lateRequest,lateRevocationTrigger,
      lateGrantState:lateRevocation&&{active:lateRevocation.active,
        revokedRevision:lateRevocation.revokedRevision},lateLedgerSnapshot,lateDiagnostics}));
    assert.equal(lateRevocation.revokedRevision,f.grantStore.revision());
    assert.equal(late.status,503);
    assert.equal(late.body.error.data.code,'AMBIGUOUS_GRANT_REVOCATION');
    assert.equal(dispatches.filter(value=>value.requestId===lateRequest).length,1);
    assertSingleDelivery(lateRequest);
    const lateAck=await controller.waitFor(value=>value.type==='worker'&&
      value.event.event==='REQUEST_DIAGNOSTIC'&&value.event.requestId===lateRequest&&
      value.event.route==='/agent/result'&&value.event.phase==='acknowledgement'&&
      value.event.outcomeCode==='ACCEPTED','late result accepted before Owner fence');
    assert.equal(lateAck.event.outcomeCode,'ACCEPTED');
    const lateLedger=await controller.send({op:'ledger',requestId:lateRequest});
    assert.equal(lateLedger.requestRecords.filter(value=>value.type==='intent').length,1);
    assert.equal(lateLedger.requestRecords.filter(value=>value.type==='outcome').length,1);

    activeGrant=issueGrant(f,device,identity.allowedRoot);
    const restoredActivation=realm.inspectActivation();
    assert.equal(restoredActivation.ready,true,JSON.stringify(restoredActivation.blockers));
    const originalRelayPort=forwarder.port;
    await forwarder.close();forwarder=null;
    const unavailable=await ownerCall('windows-transport-offline','read_file',{
      deviceId:challenge.deviceId,path:identity.proofFile,length:100});
    assert.equal(unavailable.status,503);
    assert.ok(['CANCELLED','AMBIGUOUS_TIMEOUT'].includes(unavailable.body.error.data.code));
    const offlineRequest=dispatches.at(-1).requestId;
    await new Promise(resolve=>setTimeout(resolve,200));
    assert.equal(controller.events.some(value=>value.type==='worker'&&
      value.event.event==='FIXTURE_OPERATION_DELIVERED'&&value.event.requestId===offlineRequest),false);
    assert.equal(controller.events.some(value=>value.type==='worker'&&
      value.event.event==='REQUEST_DIAGNOSTIC'&&value.event.requestId===offlineRequest&&
      value.event.phase==='execution'),false);
    const offlineState=await controller.send({op:'ledger',requestId:offlineRequest});
    assert.equal(offlineState.requestRecords.length,0);

    const reconnectEventOffset=controller.events.length;
    forwarder=await startAuthenticatedGatewayForwarder(gateway.port,relaySecret,originalRelayPort);
    await controller.waitFor(value=>controller.events.indexOf(value)>=reconnectEventOffset&&
      value.type==='worker'&&value.event.event==='RECONNECTED',
      'new worker reconnect after tunnel recovery',30_000);
    await controller.waitFor(value=>controller.events.indexOf(value)>=reconnectEventOffset&&
      value.type==='worker'&&value.event.event==='FIXTURE_CLIENT_CALL'&&
      value.event.method==='pollControl'&&value.event.outcome==='success'&&
      value.event.hasFrame===false&&value.event.hasCancel===false,
      'worker idle poll after tunnel recovery',30_000);
    const afterTunnelRestore=await ownerCall('windows-read-after-tunnel-recovery','read_file',{
      deviceId:challenge.deviceId,path:identity.proofFile,length:100});
    const recoveredRequest=dispatches.at(-1).requestId;
    const recoveryLedger=await controller.send({op:'ledger',requestId:recoveredRequest});
    const recoveryDiagnostics=controller.events.filter(value=>value.type==='worker'&&
      value.event.event==='REQUEST_DIAGNOSTIC'&&value.event.requestId===recoveredRequest)
      .map(value=>({phase:value.event.phase,route:value.event.route,outcomeCode:value.event.outcomeCode}));
    assert.equal(afterTunnelRestore.status,200,JSON.stringify({status:afterTunnelRestore.status,
      errorCode:afterTunnelRestore.body?.error?.data?.code,recoveredRequest,recoveryLedger,recoveryDiagnostics}));
    assertSingleDelivery(recoveredRequest);
    assert.equal(controller.events.some(value=>value.type==='worker'&&
      value.event.event==='FIXTURE_OPERATION_DELIVERED'&&value.event.requestId===offlineRequest),false);

    const expectedRevision=f.trustStore.revision();
    const trusted=f.trustStore.registry.snapshotTrustedDevices().find(value=>value.deviceId===challenge.deviceId);
    const revokeTarget={realmId:REALM,ownerDigest:f.principal.ownerDigest,deviceId:challenge.deviceId,
      fingerprint:trusted.fingerprint,trustRevision:expectedRevision};
    const deviceApproval=f.makeApproval({operation:'device.revoke',expectedRevision,
      target:revokeTarget});
    f.provisioner.revokeDevice({accessToken:f.tokenFor(),approval:deviceApproval,
      deviceId:challenge.deviceId,expectedRevision});
    const deniedAfterRevoke=await ownerCall('windows-device-revoked','read_file',{
      deviceId:challenge.deviceId,path:identity.proofFile,length:100});
    assert.equal(deniedAfterRevoke.status,403);

    const finalLedger=await controller.send({op:'ledger'});
    assert.equal(finalLedger.status,'consistent');
    assert.equal(finalLedger.unresolvedCount,0);
    assert.equal(finalLedger.ambiguousCount,0);
    assert.equal(finalLedger.automaticReplay,false);
    const i7Report=await i7Pilot.result();
    assert.equal(i7Report.agent.processIndependent,true);
    assert.equal(i7Report.devices.routingIsolation,true);
    assert.equal(i7Report.cleanup.temporaryStateRemoved,true);
  }finally{
    await controller.close().catch(()=>{});
    await forwarder?.close().catch(()=>{});
    await gateway?.close().catch(()=>{});
    await i7Pilot?.stop().catch(()=>{});
  }
});
