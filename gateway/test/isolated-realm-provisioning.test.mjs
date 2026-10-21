import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPublicKey, generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import { execFileSync, spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { createServer as createNetServer } from 'node:net';
import { request as httpsRequest } from 'node:https';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
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

function fixture(t,{testHooks,bindingTestHooks}={}){
  let currentTime=initialNow;
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
  const verifier=createAuth0OwnerVerifier(verifierConfig,{now:()=>currentTime});
  const payload={iss:ISSUER,sub:'google-oauth2|synthetic-i8h-owner',aud:RESOURCE,
    client_id:CLIENT,iat:seconds,exp:seconds+600};
  const tokenFor=(scope='g7.owner',sub=payload.sub)=>{
    const header=b64({alg:'RS256',kid:authJwk.kid,typ:'JWT'});
    const claims=b64({...payload,sub,scope});
    const input=`${header}.${claims}`;
    return `${input}.${sign('RSA-SHA256',Buffer.from(input),auth.privateKey).toString('base64url')}`;
  };
  const principal=verifier.verifyAdminPrincipal(tokenFor());
  const authority=createDurableOwnerAuthority({directory:paths.authority,realmId:REALM,
    issuer:ISSUER,verifier,approvalJwks:[signerJwk],now:()=>currentTime});
  const makeApproval=({operation,eventId=randomUUID(),expectedRevision,target,
    realmId=REALM,ownerDigest=principal.ownerDigest,key=signer.privateKey,
    issuedAt=Math.floor(currentTime/1000),expiresAt=Math.floor(currentTime/1000)+120}={})=>{
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
  const trustStore=createDurableDeviceTrustStore({directory:paths.trust,now:()=>currentTime});
  const pairingCoordinator=createPairingCoordinator({registry:trustStore,now:()=>currentTime,
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
    machineBindingStore,now:()=>new Date(currentTime),testHooks:bindingTestHooks});
  const grantStore=createDurableToolGrantStore({directory:paths.grant,now:()=>currentTime});
  const provisioner=createIsolatedRealmProvisioning({realmId:REALM,realmConfig,ownerAuthority:authority,
    provisioningDirectory:paths.provisioning,auditDirectory:paths.audit,bindingDirectory:paths.binding,
    trustDirectory:paths.trust,trustStore,pairingCoordinator,auditWriter,
    machineBindingStore,bindingService,grantStore,readApprovalById,testHooks});
  t.after(()=>{try{auditWriter.close();}catch{};try{trustStore.close();}catch{};
    try{machineBindingStore.close();}catch{};rmSync(home,{recursive:true,force:true});});
  return {home,paths,protectedRoot,realmConfig,authority,principal,tokenFor,makeApproval,trustStore,
    pairingCoordinator,auditWriter,machineBindingStore,grantStore,readApprovalById,
    bindingService,provisioner,advanceTime:ms=>{currentTime+=ms;}};
}

function pairDevice(f,t,{testHooks}={}){
  const key=generateKeyPairSync('ed25519');
  const publicKeyPem=key.publicKey.export({type:'spki',format:'pem'});
  const challenge=f.provisioner.startPairing({name:'Synthetic Gui-PC',platform:'win32',publicKeyPem});
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

function httpsJson({port,hostname,ca,pathname,payload,headers={}}){
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
    request.once('error',reject);request.setTimeout(10_000,()=>request.destroy(Error('HTTPS test request timeout')));
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
    const f=fixture(t);
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
        const baseRouter=createDeviceRouter({registry:f.trustStore.registry,timeoutMs:15_000});
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
    assert.equal(recoveredRead.body.result.content[0].text,profiles[0].contents);
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
