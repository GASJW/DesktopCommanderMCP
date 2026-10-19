import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer as createHttpServer } from 'node:http';
import { createServer as createHttpsServer, request as httpsRequest } from 'node:https';
import { execFileSync, spawn } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createInterface } from 'node:readline';
import { createHash, generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import { createAccessVerifier } from '../../../gateway/access-auth.mjs';
import { createDurableOwnerAudit, inspectDurableOwnerAudit,
  readDurableOwnerMachineBindingDecision,readDurableOwnerMachineBindingHistory } from '../../../gateway/dashboard/durable-owner-audit.mjs';
import { createOwnerPairingHttp } from '../../../gateway/dashboard/owner-pairing-http.mjs';
import { analyzeOwnerPairingRecovery } from '../../../gateway/dashboard/owner-pairing-reconciliation.mjs';
import { createDurableOwnerDeviceApprovalByIdReader, createDurableOwnerDeviceApprovalReader,
  createDurableOwnerDeviceAuthorizer } from '../../../gateway/dashboard/durable-owner-device-authorization.mjs';
import { createOwnerMachineBindingService } from '../../../gateway/dashboard/owner-machine-binding.mjs';
import { createDurableDeviceTrustStore, inspectDurableDeviceTrust } from '../../../gateway/devices/durable-trust.mjs';
import { createPairingCoordinator } from '../../../gateway/devices/pairing.mjs';
import { createMachineAccessVerifier } from '../../../gateway/devices/machine-access.mjs';
import { startMachineIngressLoopback } from '../../../gateway/devices/machine-ingress-loopback.mjs';
import { createDeviceRouter } from '../../../gateway/devices/router.mjs';
import { createRemoteDeviceMcpHandler } from '../../../gateway/devices/remote-mcp-handler.mjs';
import { createDurableToolGrantStore } from '../../../gateway/devices/durable-tool-grants.mjs';
import { bindApprovedDeviceIdentity, loadOrCreateDeviceIdentity } from '../src/identity-store.mjs';
import { createLocalReadonlyMcp } from '../src/local-mcp-readonly.mjs';
import { createHttpsAgentClient } from '../src/https-client.mjs';
import { createAgentWorker } from '../src/worker.mjs';
import { createGovernedAgentExecutor } from '../src/governed-executor.mjs';
import { createDurableMachineBindingStore } from '../../../gateway/devices/durable-machine-bindings.mjs';

const HOST='devices.example.test';
const CLIENT='i3-agent-test.access';
const SERVICE_SECRET='synthetic-i3-machine-secret-only';
const OWNER_ISSUER='https://i3-owner-test.cloudflareaccess.com';
const MACHINE_ISSUER='https://i3-machine-test.cloudflareaccess.com';
const OWNER_AUD='e'.repeat(64);
const MACHINE_AUD='f'.repeat(64);
const OWNER='i3-owner@example.com';
const OWNER_ORIGIN='https://commander.example.test';
const MCP_FIXTURE=fileURLToPath(new URL('./fixtures-readonly-mcp.mjs',import.meta.url));
const PAIRING_AGENT_FIXTURE=fileURLToPath(new URL('./fixtures-agent-pairing-process.mjs',import.meta.url));
const LOCAL_MCP_ENTRY=process.env.VPSC_TEST_REAL_MCP_ENTRY??MCP_FIXTURE;

function keyMaterial(kid){
  const {publicKey,privateKey}=generateKeyPairSync('rsa',{modulusLength:2048});
  return {privateKey,jwk:{...publicKey.export({format:'jwk'}),kid,alg:'RS256'}};
}
function makeJwt(privateKey,kid,claims){
  const header=Buffer.from(JSON.stringify({alg:'RS256',kid})).toString('base64url');
  const body=Buffer.from(JSON.stringify(claims)).toString('base64url');
  return header+'.'+body+'.'+sign('RSA-SHA256',Buffer.from(header+'.'+body),privateKey).toString('base64url');
}
function listen(server){
  return new Promise((resolve,reject)=>{
    server.once('error',reject);
    server.listen(0,'127.0.0.1',()=>resolve(`http://127.0.0.1:${server.address().port}`));
  });
}
async function closeServer(server){
  if(!server?.listening)return;
  server.closeAllConnections?.();
  await new Promise(resolve=>server.close(resolve));
}
function startPairingIngress(coordinator){
  const server=createHttpServer(async(req,res)=>{
    if(req.method!=='POST'||!['/pairing/start','/pairing/prove'].includes(req.url)){
      res.writeHead(404);res.end();return;
    }
    let size=0;const chunks=[];
    for await(const chunk of req){size+=chunk.length;if(size>4096){
      res.writeHead(413);res.end();return;
    }chunks.push(chunk);}
    let body;
    try{body=JSON.parse(Buffer.concat(chunks,size).toString('utf8'));}
    catch{res.writeHead(400);res.end();return;}
    try{
      if(req.url==='/pairing/start'&&body&&Object.keys(body).sort().join(',')===
          'name,platform,publicKeyPem'){
        const request=coordinator.startPairing(body);
        res.writeHead(201,{'content-type':'application/json','cache-control':'no-store'});
        res.end(JSON.stringify(request));return;
      }
      if(req.url==='/pairing/prove'&&body&&Object.keys(body).sort().join(',')===
          'proof,requestId'){
        const proved=coordinator.provePossession(body.requestId,body.proof);
        res.writeHead(proved?200:403,{'content-type':'application/json','cache-control':'no-store'});
        res.end(JSON.stringify({proved}));return;
      }
    }catch{}
    res.writeHead(400);res.end();
  });
  server.requestTimeout=5000;
  return {server,ready:listen(server),close:()=>closeServer(server)};
}
async function startPairingAgentProcess(directory){
  const child=spawn(process.execPath,[PAIRING_AGENT_FIXTURE],{cwd:path.dirname(PAIRING_AGENT_FIXTURE),
    shell:false,stdio:['pipe','pipe','ignore'],env:{PATH:process.env.PATH??'',
      HOME:process.env.HOME??'',TMPDIR:process.env.TMPDIR??'',
      VPSC_TEST_IDENTITY_DIR:directory}});
  const lines=createInterface({input:child.stdout,crlfDelay:Infinity});
  const queued=[],waiters=[];
  lines.on('line',line=>{
    let message;try{message=JSON.parse(line);}catch{return;}
    const waiter=waiters.shift();
    if(waiter){clearTimeout(waiter.timer);waiter.resolve(message);}else queued.push(message);
  });
  child.once('error',error=>{
    for(const waiter of waiters.splice(0)){clearTimeout(waiter.timer);waiter.reject(error);}
  });
  function next(){
    if(queued.length)return Promise.resolve(queued.shift());
    return new Promise((resolve,reject)=>{
      const waiter={resolve,reject,timer:setTimeout(()=>{
        const index=waiters.indexOf(waiter);if(index>=0)waiters.splice(index,1);
        reject(Error('Pairing agent process timed out'));
      },5000)};
      waiters.push(waiter);
    });
  }
  const identity=await next();
  assert.equal(identity.kind,'identity');
  return {identity,prove:async challenge=>{
    child.stdin.write(JSON.stringify({kind:'prove',challenge})+'\n');
    const result=await next();
    if(result.kind!=='proof')throw Error('Pairing agent proof failed');
    return result.proof;
  },close:async()=>{
    lines.close();child.kill('SIGTERM');
    if(child.exitCode===null)await new Promise(resolve=>child.once('exit',resolve));
  }};
}
async function jsonPost(url,payload,{headers={},method='POST',signal}={}){
  const response=await fetch(url,{method,headers:{'content-type':'application/json',...headers},
    ...(payload===undefined?{}:{body:JSON.stringify(payload)}),...(signal?{signal}:{})});
  const text=await response.text();
  return {status:response.status,headers:response.headers,
    body:text?JSON.parse(text):null};
}
async function waitFor(predicate,label){
  const deadline=Date.now()+5000;
  while(Date.now()<deadline){
    const value=await predicate();
    if(value)return value;
    await new Promise(resolve=>setTimeout(resolve,10));
  }
  throw Error('Timed out waiting for '+label);
}
function createOwnerJwt(identity,overrides={}){
  const now=Math.floor(Date.now()/1000);
  return makeJwt(identity.privateKey,'owner-i3',{iss:OWNER_ISSUER,aud:OWNER_AUD,
    email:OWNER,sub:'owner-subject-i3',iat:now-5,exp:now+3600,...overrides});
}
function createMachineJwt(identity){
  const now=Math.floor(Date.now()/1000);
  return makeJwt(identity.privateKey,'machine-i3',{type:'app',sub:'',common_name:CLIENT,
    iss:MACHINE_ISSUER,aud:MACHINE_AUD,iat:now-5,exp:now+3600});
}
function createTlsFetch({port,ca,observed}){
  return (input,options)=>new Promise((resolve,reject)=>{
    const url=new URL(input);
    if(url.protocol!=='https:'||url.hostname!==HOST||url.port||url.pathname==='/'){
      reject(new Error('Unexpected test TLS destination'));
      return;
    }
    const headers={...options.headers,host:HOST};
    const observation={url:input,headers:{...headers},redirect:options.redirect,
      credentials:options.credentials,cache:options.cache};
    observed.push(observation);
    const request=httpsRequest({hostname:'127.0.0.1',port,servername:HOST,
      method:options.method,path:url.pathname,headers,ca,rejectUnauthorized:true},response=>{
      const chunks=[];let bytes=0;
      response.on('data',chunk=>{bytes+=chunk.length;chunks.push(chunk);});
      response.on('end',()=>{
        observation.status=response.statusCode;
        resolve(new Response(Buffer.concat(chunks,bytes),{
          status:response.statusCode,headers:response.headers,
        }));
      });
    });
    const abort=()=>request.destroy(new Error('test HTTPS request aborted'));
    if(options.signal?.aborted)abort();
    else options.signal?.addEventListener('abort',abort,{once:true});
    request.once('error',reject);
    request.once('close',()=>options.signal?.removeEventListener('abort',abort));
    request.end(options.body);
  });
}
function makeTlsCertificate(directory,name){
  const key=path.join(directory,name+'.key'),cert=path.join(directory,name+'.crt');
  execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-days','1',
    '-subj',`/CN=${HOST}`,'-addext',`subjectAltName=DNS:${HOST}`,
    '-keyout',key,'-out',cert],{stdio:'ignore'});
  chmodSync(key,0o600);
  return {key:readFileSync(key),cert:readFileSync(cert)};
}
function makeGateway({trustStore,ownerAccess,machineAccess,bindings,ingressRef,
  auditDirectory,trustDirectory,toolGrantStore,policySigningKey,machineBindingStore}){
  const router=createDeviceRouter({registry:trustStore.registry,timeoutMs:15_000});
  const approvalReceiptReads=[];
  const dispatchAuthorizationChecks=[];
  const durableReadDeviceApproval=createDurableOwnerDeviceApprovalReader({auditDirectory,trustDirectory});
  const readDeviceApproval=(...args)=>{
    const recovery=analyzeOwnerPairingRecovery({auditDirectory,trustDirectory});
    const trustEvidence=inspectDurableDeviceTrust({directory:trustDirectory});
    const receipt=durableReadDeviceApproval(...args);
    approvalReceiptReads.push({receipt,recoveryState:recovery.state,
      trustWriterActive:recovery.trustWriterActive,operationGateStatus:trustEvidence.operationGateStatus});
    return receipt;
  };
  const shouldCancelOperation=frame=>{
    const claims=frame?.authorization?.claims;
    if(!claims||claims.deviceId!==frame.deviceId||claims.requestId!==frame.requestId||
       claims.policyRevision===undefined){dispatchAuthorizationChecks.push({allowed:false,reason:'bad-claims'});return false;}
    try{
      const allowed=toolGrantStore.withCurrentAuthorization({grantId:claims.grantId,
        ownerDigest:claims.ownerDigest,deviceId:claims.deviceId,fingerprint:claims.fingerprint,
        tool:claims.tool,policyRevision:claims.policyRevision},()=>
          trustStore.registry.isLiveSession(frame.deviceId,frame.sessionId))===true;
      dispatchAuthorizationChecks.push({allowed,reason:allowed?'allowed':'session-not-live'});
      return allowed;
    }catch(error){dispatchAuthorizationChecks.push({allowed:false,reason:error?.code??'authorization-error'});return false;}
  };
  const ingressPromise=startMachineIngressLoopback({registry:trustStore.registry,router,
    verifyMachineToken:machineAccess,machineBindingStore,getTrustRevision:()=>trustStore.revision(),
    shouldCancelOperation,
    ...(bindings?{machineBindings:bindings}:{}),enableTestIngress:true});
  const mcpServer=createHttpServer(createRemoteDeviceMcpHandler({
    accessVerifier:ownerAccess,deviceRegistry:trustStore.registry,trustStore,router,
    authorizeDevice:createDurableOwnerDeviceAuthorizer({auditDirectory,trustDirectory}),
    grantStore:toolGrantStore,policySigningKey,
    getTrustRevision:()=>trustStore.revision(),getDeviceApprovalReceipt:readDeviceApproval,
  }));
  const ownerTransportEvents=[];
  mcpServer.on('request',(req,res)=>{
    req.once('aborted',()=>ownerTransportEvents.push({event:'request-aborted',url:req.url}));
    res.once('close',()=>ownerTransportEvents.push({event:'response-close',url:req.url,
      writableEnded:res.writableEnded,destroyed:res.destroyed,requestComplete:req.complete,
      requestAborted:req.aborted}));
  });
  let ownerMcpUrl;
  const ownerMcpReady=listen(mcpServer).then(url=>{ownerMcpUrl=url+'/mcp';return ownerMcpUrl;});
  return {
    router,mcpServer,ownerMcpReady,approvalReceiptReads,dispatchAuthorizationChecks,ownerTransportEvents,
    ready:ingressPromise.then(ingress=>{ingressRef.current=ingress;return ingress;}),
    close:async()=>{
      await closeServer(mcpServer);
      const ingress=await ingressPromise.catch(()=>null);
      if(ingress){if(ingressRef.current===ingress)ingressRef.current=null;await ingress.close();}
      router.close();
    },
  };
}
function createTlsEdge({certificate,ingressRef,expectedClientId,expectedSecret,machineJwt,observed}){
  let requestCount=0;
  const server=createHttpsServer({key:certificate.key,cert:certificate.cert},async(req,res)=>{
    requestCount++;
    const edgeRequest={path:req.url,status:null,denial:null};
    observed.edgeRequests??=[];observed.edgeRequests.push(edgeRequest);
    const seen={...req.headers};observed.edge.push(seen);
    if(seen['cf-access-client-id']!==expectedClientId||
       seen['cf-access-client-secret']!==expectedSecret){
      edgeRequest.status=403;edgeRequest.denial='service-token';
      res.writeHead(403,{'content-type':'application/json'});res.end('{"error":"service token denied"}');return;
    }
    if(seen['cf-access-jwt-assertion']||seen.cookie||!ingressRef.current){
      edgeRequest.status=403;edgeRequest.denial='identity-boundary';
      res.writeHead(403,{'content-type':'application/json'});res.end('{"error":"identity boundary denied"}');return;
    }
    const chunks=[];let size=0;
    for await(const chunk of req){size+=chunk.length;if(size>256*1024){
      res.writeHead(413);res.end();return;
    }chunks.push(chunk);}
    const forward={'content-type':'application/json','cf-access-jwt-assertion':machineJwt};
    for(const name of ['x-vpsc-device-id','x-vpsc-session-id','x-vpsc-sequence','x-vpsc-signature']){
      if(typeof seen[name]==='string')forward[name]=seen[name];
    }
    observed.forwarded.push({...forward});
    try{
      const upstream=await fetch(ingressRef.current.url+req.url,{method:'POST',headers:forward,
        body:Buffer.concat(chunks,size),redirect:'error',signal:AbortSignal.timeout(8000)});
      const body=Buffer.from(await upstream.arrayBuffer());
      edgeRequest.status=upstream.status;edgeRequest.denial=upstream.status>=400?'machine-ingress':null;
      if(upstream.status>=400){try{edgeRequest.upstreamError=JSON.parse(body.toString('utf8')).error;}catch{}}
      res.writeHead(upstream.status,{'content-type':'application/json',
        'cache-control':'no-store','x-content-type-options':'nosniff'});
      res.end(body);
    }catch{
      res.writeHead(502,{'content-type':'application/json'});res.end('{"error":"upstream unavailable"}');
    }
  });
  return {server,ready:listen(server).then(url=>({url,port:server.address().port})),
    get requestCount(){return requestCount;},close:()=>closeServer(server)};
}
function agentClient({identity,deviceId,clientSecret,fetchFn}){
  return createHttpsAgentClient({gatewayUrl:`https://${HOST}/`,expectedHostname:HOST,
    identity,deviceId,clientId:CLIENT,clientSecret,fetchFn});
}
function makeExecutor(root,ledgerDirectory,{deviceId,fingerprint,gatewayPolicyPublicKey,testHooks}){
  if(ledgerDirectory)return createGovernedAgentExecutor({allowedRoot:root,
    entrypoint:LOCAL_MCP_ENTRY,ledgerDirectory,deviceId,fingerprint,gatewayPolicyPublicKey,testHooks});
  return createLocalReadonlyMcp({allowedRoot:root,entrypoint:LOCAL_MCP_ENTRY,timeoutMs:5000,
  });
}
async function startWorker(client,deviceId,root,ledgerDirectory,identity,policyPublicKey,testHooks){
  const controller=new AbortController();
  const worker=createAgentWorker({deviceId,client,executor:makeExecutor(root,ledgerDirectory,{
    deviceId,fingerprint:identity.fingerprint,gatewayPolicyPublicKey:policyPublicKey,testHooks,
  }),pollIntervalMs:25});
  const done=worker.run({signal:controller.signal});
  // A later authorization revocation intentionally makes the worker reject on
  // its next heartbeat. Observe that promise immediately so teardown/assertion
  // failures remain the test result instead of an unhandled-rejection event.
  let terminalError=null;
  done.catch(error=>{terminalError={code:error?.code??null,message:String(error?.message??error)};});
  return {worker,controller,done,get terminalError(){return terminalError;}};
}
async function stopWorker(active){
  active.controller.abort();
  await active.done;
}
async function ownerCall(url,method,id,params,token,signal){
  return jsonPost(url,{jsonrpc:'2.0',id,method,params},{headers:{
    'cf-access-jwt-assertion':token,
  },...(signal?{signal}:{})});
}
async function approveDevice({home,pairingIdentity,provePairing,ownerAccess,ownerKeys,
  trustStore,audit,ownerToken}){
  const coordinator=createPairingCoordinator({registry:trustStore});
  const pairingIngress=startPairingIngress(coordinator);
  const pairingBase=await pairingIngress.ready;
  let pairing;
  try{
    const pairingRequest=await jsonPost(pairingBase+'/pairing/start',{
      name:'i3-fixture-device',platform:process.platform==='win32'?'win32':'linux',
      publicKeyPem:pairingIdentity.publicKeyPem,
    });
    assert.equal(pairingRequest.status,201);
    pairing=pairingRequest.body;
    assert.equal(pairing.fingerprint,pairingIdentity.fingerprint);
    const proof=await provePairing(pairing);
    const proofResponse=await jsonPost(pairingBase+'/pairing/prove',{
      requestId:pairing.requestId,proof,
    });
    assert.equal(proofResponse.status,200);
    assert.equal(proofResponse.body.proved,true);
  }finally{await pairingIngress.close();}
  const ownerHandler=createOwnerPairingHttp({coordinator,accessVerifier:ownerAccess,
    expectedOrigin:OWNER_ORIGIN,auditWrite:audit.auditWrite});
  const ownerServer=createHttpServer((req,res)=>ownerHandler(req,res).catch(()=>{
    if(!res.writableEnded){res.statusCode=503;res.end();}
  }));
  const base=await listen(ownerServer)+'/dashboard/api/g7/pairing/';
  try{
    const pending=await jsonPost(base+'pending',undefined,{method:'GET',headers:{
      'cf-access-jwt-assertion':ownerToken,
    }});
    assert.equal(pending.status,200);
    assert.equal(pending.body.pending.length,1);
    assert.equal(JSON.stringify(pending.body).includes(pairing.displayCode),false);
    assert.equal(JSON.stringify(pending.body).includes(pairing.nonce),false);
    const decision=await jsonPost(base+'approve',{requestId:pairing.requestId,
      code:pairing.displayCode,expectedFingerprint:pairing.fingerprint},{headers:{
      'cf-access-jwt-assertion':ownerToken,origin:OWNER_ORIGIN,
      'x-vpsc-csrf':pending.body.csrf,
    }});
    assert.equal(decision.status,200,JSON.stringify(decision.body));
    assert.equal(decision.body.status,'approved_offline');
    return {deviceId:decision.body.deviceId,requestId:pairing.requestId,
      fingerprint:pairing.fingerprint,displayCode:pairing.displayCode,nonce:pairing.nonce};
  }finally{await closeServer(ownerServer);}
}

test('I3/I4 E2E: Owner approval, durable trust, verified TLS, governed operations, restart and revoke',async t=>{
  const home=mkdtempSync(path.join(tmpdir(),'g7-i3-e2e-'));
  let trustStore=null,audit=null,toolGrantStore=null,machineBindingStore=null,gateway=null,edge=null,active=null;
  t.after(async()=>{
    if(active){active.controller.abort();await active.done.catch(()=>{});}
    await gateway?.close().catch(()=>{});
    await edge?.close().catch(()=>{});
    try{audit?.close();}catch{}
    try{toolGrantStore?.close?.();}catch{}
    try{machineBindingStore?.close?.();}catch{}
    try{trustStore?.close();}catch{}
    rmSync(home,{recursive:true,force:true});
  });
  const trustDirectory=path.join(home,'trust'),auditDirectory=path.join(home,'audit');
  const policyDirectory=path.join(home,'tool-policy');
  const machineBindingDirectory=path.join(home,'machine-bindings');
  const identityDirectory=path.join(home,'agent-identity');
  const executionDirectory=path.join(home,'agent-execution');
  const cancellationExecutionDirectory=path.join(home,'agent-cancellation-execution');
  const revokeExecutionDirectory=path.join(home,'agent-revoke-execution');
  const allowedRoot=path.join(home,'approved-files');
  mkdirSync(allowedRoot,{mode:0o700});
  mkdirSync(policyDirectory,{mode:0o700});
  mkdirSync(machineBindingDirectory,{mode:0o700});
  mkdirSync(identityDirectory,{mode:0o700});
  mkdirSync(executionDirectory,{mode:0o700});
  mkdirSync(cancellationExecutionDirectory,{mode:0o700});
  mkdirSync(revokeExecutionDirectory,{mode:0o700});
  const file=path.join(allowedRoot,'approved.txt');
  writeFileSync(file,'durable-owner-approved-real-mcp-read\n',{mode:0o600});
  const ownerKeys=keyMaterial('owner-i3'),machineKeys=keyMaterial('machine-i3');
  const policyKeys=generateKeyPairSync('ed25519');
  const ownerAccess=createAccessVerifier({issuer:OWNER_ISSUER,audience:OWNER_AUD,
    allowedEmails:OWNER,keyProvider:async()=>({keys:[ownerKeys.jwk]})});
  const now=Date.now();
  const machineAccess=createMachineAccessVerifier({issuer:MACHINE_ISSUER,audience:MACHINE_AUD,
    allowedClientIds:[CLIENT],keyProvider:async()=>({keys:[machineKeys.jwk]}),now:()=>now});
  const pairingAgent=await startPairingAgentProcess(identityDirectory);
  let identity=null;
  t.after(async()=>pairingAgent.close());
  identity=loadOrCreateDeviceIdentity({directory:identityDirectory,platform:process.platform});
  assert.equal(pairingAgent.identity.fingerprint,identity.fingerprint);
  const ownerToken=createOwnerJwt(ownerKeys);
  const machineJwt=createMachineJwt(machineKeys);
  const certificate=makeTlsCertificate(home,'edge');
  const wrongCertificate=makeTlsCertificate(home,'untrusted-edge');
  trustStore=createDurableDeviceTrustStore({directory:trustDirectory});
  audit=createDurableOwnerAudit({directory:auditDirectory});
  assert.equal(trustStore.registry.listDevices().length,0,'device has no trust before requesting pairing');
  const approved=await approveDevice({home,pairingIdentity:pairingAgent.identity,
    provePairing:pairingAgent.prove,ownerAccess,ownerKeys,trustStore,audit,ownerToken});
  assert.equal(trustStore.revision(),1);
  const ownerPrincipal={issuer:OWNER_ISSUER,subject:'owner-subject-i3'};
  const readDeviceApproval=createDurableOwnerDeviceApprovalReader({auditDirectory,trustDirectory});
  const approvalReceipt=readDeviceApproval(ownerPrincipal,approved.deviceId);
  assert.ok(approvalReceipt,'the stable device identity is backed by the I2 approval receipt');
  const ownerDigest=createHash('sha256').update('VPSC-I4-OWNER-v1\n')
    .update(JSON.stringify([OWNER_ISSUER,'owner-subject-i3'])).digest('hex');
  const readDeviceApprovalById=createDurableOwnerDeviceApprovalByIdReader({auditDirectory,trustDirectory});
  machineBindingStore=createDurableMachineBindingStore({directory:machineBindingDirectory,
    verifyApprovalReceipt:binding=>binding.ownerDigest===ownerDigest
      ?readDeviceApprovalById(binding.ownerId,binding.deviceId):null,
    readBindingDecision:binding=>readDurableOwnerMachineBindingDecision({directory:auditDirectory,
      eventId:binding.bindingEventId}),
    readBindingHistory:()=>readDurableOwnerMachineBindingHistory({directory:auditDirectory})});
  const bindingService=createOwnerMachineBindingService({accessVerifier:ownerAccess,
    auditWrite:audit.auditWrite,readApprovalReceipt:readDeviceApproval,
    machineBindingStore});
  const machineBinding=await bindingService.bind({ownerAssertion:ownerToken,clientId:CLIENT,
    deviceId:approved.deviceId,expectedRevision:0});
  assert.equal(machineBinding.revision,1);
  identity=bindApprovedDeviceIdentity({directory:identityDirectory,machineBinding:machineBinding.binding});
  assert.deepEqual(identity.deviceBinding,machineBinding.binding);
  const bindingDecision=readDurableOwnerMachineBindingDecision({directory:auditDirectory,
    eventId:machineBinding.binding.bindingEventId});
  assert.equal(bindingDecision.state,'COMPLETE');
  assert.equal(bindingDecision.outcome.deviceId,approved.deviceId);
  assert.equal(bindingDecision.outcome.clientId,CLIENT);
  assert.equal(bindingDecision.outcome.fingerprint,identity.fingerprint);
  toolGrantStore=createDurableToolGrantStore({directory:policyDirectory});
  const grants={};
  const grantDefinitions=[
    ['read_file',{root:allowedRoot},{maxBytes:64*1024,maxLength:1000,maxOffset:100_000}],
    ['list_directory',{root:allowedRoot},{maxDepth:2,maxEntries:200}],
    ['write_file',{root:allowedRoot},{maxBytes:64*1024}],
    ['list_processes',{}, {maxJobs:32}],
    ['run_command',{root:allowedRoot,profile:'count_lines'},
      {maxOutputBytes:16*1024,maxRuntimeMs:10_000,profile:'count_lines'}],
  ];
  let grantRevision=0;
  for(const [tool,scope,constraints] of grantDefinitions){
    const result=toolGrantStore.grant({ownerDigest,deviceId:approved.deviceId,
      fingerprint:approved.fingerprint,tool,scope,constraints},
      {expectedRevision:grantRevision,eventId:randomUUID()});
    grantRevision=result.revision;grants[tool]=result.grantId;
  }
  const recoveryWhileAuditWriterOpen=analyzeOwnerPairingRecovery({auditDirectory,trustDirectory});
  assert.equal(recoveryWhileAuditWriterOpen.state,'ACTIVE_WRITER');
  assert.equal(recoveryWhileAuditWriterOpen.underlyingState,'CONSISTENT');
  assert.equal(recoveryWhileAuditWriterOpen.auditWriterActive,true);
  assert.equal(recoveryWhileAuditWriterOpen.trustWriterActive,false);

  const auditEvidence=inspectDurableOwnerAudit({directory:auditDirectory});
  const trustEvidence=inspectDurableDeviceTrust({directory:trustDirectory});
  const pairingEvents=auditEvidence.events.filter(event=>event.event==='g7_owner_pairing');
  assert.equal(pairingEvents.length,2);
  const [intent,outcome]=pairingEvents;
  assert.equal(intent.phase,'intent');assert.equal(outcome.phase,'outcome');
  assert.equal(intent.eventId,outcome.eventId);
  assert.equal(intent.requestId,approved.requestId);
  assert.equal(intent.fingerprint,approved.fingerprint);
  assert.equal(outcome.deviceId,approved.deviceId);
  assert.equal(outcome.trustRevisionBefore,0);assert.equal(outcome.trustRevisionAfter,1);
  assert.equal(trustEvidence.revision,1);
  assert.deepEqual(trustEvidence.transitions.map(x=>({eventId:x.eventId,requestId:x.requestId,
    fingerprint:x.fingerprint,deviceId:x.deviceId,previousRevision:x.previousRevision,
    revision:x.revision})),[{eventId:intent.eventId,requestId:approved.requestId,
    fingerprint:approved.fingerprint,deviceId:approved.deviceId,previousRevision:0,revision:1}]);
  const machineEvents=auditEvidence.events.filter(event=>event.event==='g7_owner_machine_binding');
  assert.deepEqual(machineEvents.map(event=>({phase:event.phase,eventId:event.eventId,
    deviceId:event.deviceId,clientId:event.clientId,fingerprint:event.fingerprint,
    bindingRevisionBefore:event.bindingRevisionBefore,
    ...(event.phase==='outcome'?{bindingRevisionAfter:event.bindingRevisionAfter}:{})})),[
    {phase:'intent',eventId:machineBinding.binding.bindingEventId,deviceId:approved.deviceId,
      clientId:CLIENT,fingerprint:approved.fingerprint,bindingRevisionBefore:0},
    {phase:'outcome',eventId:machineBinding.binding.bindingEventId,deviceId:approved.deviceId,
      clientId:CLIENT,fingerprint:approved.fingerprint,bindingRevisionBefore:0,bindingRevisionAfter:1},
  ]);
  const persisted=readFileSync(path.join(auditDirectory,'owner-decisions-v1.jsonl'),'utf8')+
    readFileSync(path.join(trustDirectory,'trusted-devices-v1.json'),'utf8');
  for(const secret of [SERVICE_SECRET,machineJwt,ownerToken,approved.displayCode,approved.nonce]){
    assert.equal(persisted.includes(secret),false);
  }
  assert.equal(trustEvidence.devices.some(item=>item.publicKeyPem===identity.publicKeyPem),true,
    'public key is the approved trust material');
  assert.equal(persisted.includes(identity.fingerprint),true,'fingerprint is bound to the durable decision');

  const ingressRef={current:null};
  const forwarded={edge:[],forwarded:[]};
  edge=createTlsEdge({certificate,ingressRef,expectedClientId:CLIENT,
    expectedSecret:SERVICE_SECRET,machineJwt,observed:forwarded});
  const edgeInfo=await edge.ready;
  const tlsFetch=createTlsFetch({port:edgeInfo.port,ca:certificate.cert,observed:[]});
  const wrongTlsFetch=createTlsFetch({port:edgeInfo.port,ca:wrongCertificate.cert,observed:[]});
  const gatewayFactory=()=>makeGateway({trustStore,ownerAccess,machineAccess,
    machineBindingStore,ingressRef,auditDirectory,trustDirectory,
    toolGrantStore,policySigningKey:policyKeys.privateKey});
  gateway=gatewayFactory();await gateway.ready;const mcpUrl=await gateway.ownerMcpReady;
  const invalidTls=agentClient({identity,deviceId:approved.deviceId,clientSecret:SERVICE_SECRET,
    fetchFn:wrongTlsFetch});
  const requestsBefore=edge.requestCount;
  await assert.rejects(invalidTls.connect(),error=>error.code==='AMBIGUOUS_TRANSPORT');
  invalidTls.close();
  assert.equal(edge.requestCount,requestsBefore,'invalid certificate must fail before HTTP request dispatch');

  let tlsObserved=[];
  const fetchFn=createTlsFetch({port:edgeInfo.port,ca:certificate.cert,observed:tlsObserved});
  let client=agentClient({identity,deviceId:approved.deviceId,clientSecret:SERVICE_SECRET,fetchFn});
  active=await startWorker(client,approved.deviceId,allowedRoot,executionDirectory,identity,
    policyKeys.publicKey);
  await waitFor(()=>trustStore.registry.listDevices()[0]?.online,'authenticated device heartbeat');
  const init=await ownerCall(mcpUrl,'initialize',1,{protocolVersion:'2025-03-26',
    capabilities:{},clientInfo:{name:'i3-loopback-client',version:'1'}},ownerToken);
  assert.equal(init.status,200);assert.equal(init.body.result.serverInfo.name,'vpsc-g7-device-gateway');
  const machineAsOwner=await ownerCall(mcpUrl,'tools/call',10,{name:'read_file',arguments:{
    deviceId:approved.deviceId,path:file,
  }},machineJwt);
  assert.equal(machineAsOwner.status,401,'machine Access cannot impersonate the owner');
  const tools=await ownerCall(mcpUrl,'tools/list',2,{},ownerToken);
  assert.equal(tools.status,200);assert.deepEqual(tools.body.result.tools.map(tool=>tool.name),[
    'read_file','list_directory','write_file','list_processes','run_command',
  ]);
  const read=await ownerCall(mcpUrl,'tools/call',3,{name:'read_file',arguments:{
    deviceId:approved.deviceId,path:file,
  }},ownerToken);
  assert.equal(read.status,200,JSON.stringify({body:read.body,
    ownerTransportEvents:gateway.ownerTransportEvents,
    approvalReceiptReads:gateway.approvalReceiptReads,
    dispatchAuthorizationChecks:gateway.dispatchAuthorizationChecks,
    agentRequests:tlsObserved.map(item=>({path:new URL(item.url).pathname,status:item.status,
      deviceId:item.headers['x-vpsc-device-id'],sessionId:item.headers['x-vpsc-session-id'],
      sequence:item.headers['x-vpsc-sequence'],clientId:item.headers['cf-access-client-id'],
      secretValid:item.headers['cf-access-client-secret']===SERVICE_SECRET,
      ownerJwt:item.headers['cf-access-jwt-assertion']!==undefined,
      cookie:item.headers.cookie!==undefined})),
    edgeRequests:forwarded.edgeRequests,
    workerError:active.terminalError}));
  assert.equal(gateway.approvalReceiptReads.length,2,
    'the response fence re-reads approval from the durable I2 audit/trust reader');
  assert.ok(gateway.approvalReceiptReads.every(read=>read.receipt?.eventId===intent.eventId),
    'the durable I2 receipt remains verifiable inside the response fence: '+
      JSON.stringify(gateway.approvalReceiptReads));
  assert.match(JSON.stringify(read.body),/durable-owner-approved-real-mcp-read/);
  assert.ok(tlsObserved.every(item=>item.headers['cf-access-client-id']===CLIENT&&
    item.headers['cf-access-client-secret']===SERVICE_SECRET&&
    item.headers['cf-access-jwt-assertion']===undefined&&item.redirect==='error'&&
    item.credentials==='omit'&&item.cache==='no-store'));
  assert.ok(forwarded.edge.every(headers=>headers['cf-access-client-secret']===SERVICE_SECRET));
  assert.ok(forwarded.forwarded.every(headers=>headers['cf-access-client-secret']===undefined&&
    headers['cf-access-client-id']===undefined&&headers.cookie===undefined));

  await stopWorker(active);active=null;
  assert.equal(trustStore.registry.listDevices()[0]?.online,false,'explicit disconnect invalidates the device session');
  client=agentClient({identity,deviceId:approved.deviceId,clientSecret:SERVICE_SECRET,
    fetchFn:createTlsFetch({port:edgeInfo.port,ca:certificate.cert,observed:[]})});
  active=await startWorker(client,approved.deviceId,allowedRoot,executionDirectory,identity,
    policyKeys.publicKey);
  await waitFor(()=>trustStore.registry.listDevices()[0]?.online,'governed I4 device heartbeat');
  const directoryCall=await ownerCall(mcpUrl,'tools/call',30,{name:'list_directory',arguments:{
    deviceId:approved.deviceId,path:allowedRoot,depth:1,
  }},ownerToken);
  assert.equal(directoryCall.status,200,JSON.stringify(directoryCall.body));
  assert.match(directoryCall.body.result.content[0].text,/approved\.txt/);
  const createdPath=path.join(allowedRoot,'i4-created.txt');
  const writeCall=await ownerCall(mcpUrl,'tools/call',31,{name:'write_file',arguments:{
    deviceId:approved.deviceId,path:createdPath,content:'durable I4 write\n',mode:'create',
  }},ownerToken);
  assert.equal(writeCall.status,200,JSON.stringify(writeCall.body));
  assert.equal(readFileSync(createdPath,'utf8'),'durable I4 write\n');
  const duplicateWrite=await ownerCall(mcpUrl,'tools/call',31,{name:'write_file',arguments:{
    deviceId:approved.deviceId,path:createdPath,content:'durable I4 write\n',mode:'create',
  }},ownerToken);
  assert.equal(duplicateWrite.body.result.isError,true);
  assert.equal(readFileSync(createdPath,'utf8'),'durable I4 write\n');
  const revokeWrite=toolGrantStore.revoke(grants.write_file,{expectedRevision:grantRevision,
    eventId:randomUUID()});
  grantRevision=revokeWrite.revision;
  const deniedWrite=await ownerCall(mcpUrl,'tools/call',34,{name:'write_file',arguments:{
    deviceId:approved.deviceId,path:path.join(allowedRoot,'after-revoke.txt'),
    content:'must not be dispatched',mode:'create',
  }},ownerToken);
  assert.equal(deniedWrite.status,403);
  assert.equal(readFileSync(path.join(executionDirectory,'i4-execution.jsonl'),'utf8')
    .includes('must not be dispatched'),false);
  const commandCall=await ownerCall(mcpUrl,'tools/call',32,{name:'run_command',arguments:{
    deviceId:approved.deviceId,path:file,profile:'count_lines',
  }},ownerToken);
  assert.equal(commandCall.status,200,JSON.stringify(commandCall.body));
  assert.equal(commandCall.body.result.structuredContent.exitCode,0);
  assert.match(commandCall.body.result.structuredContent.stdout,/1/);
  const processesCall=await ownerCall(mcpUrl,'tools/call',33,{name:'list_processes',arguments:{
    deviceId:approved.deviceId,
  }},ownerToken);
  assert.equal(processesCall.status,200);
  assert.ok(processesCall.body.result.structuredContent.jobs.some(job=>job.profile==='count_lines'&&
    job.exitCode===0));
  const executionLedger=readFileSync(path.join(executionDirectory,'i4-execution.jsonl'),'utf8');
  const executionRecords=executionLedger.trim().split('\n').map(line=>JSON.parse(line));
  const governedIntent=executionRecords.find(record=>record.type==='intent');
  const firstCapability=governedIntent.authorization.claims;
  assert.equal(governedIntent.deviceId,approved.deviceId);
  assert.equal(firstCapability.approvalEventId,intent.eventId);
  assert.equal(firstCapability.deviceId,approved.deviceId);
  assert.equal(firstCapability.fingerprint,approved.fingerprint);
  assert.equal(firstCapability.approvalTrustRevisionBefore,0);
  assert.equal(firstCapability.approvalTrustRevisionAfter,1);
  assert.equal(firstCapability.scope.root,allowedRoot);
  assert.ok(executionRecords.every(record=>record.authorization.claims.approvalEventId===intent.eventId));
  assert.doesNotMatch(executionLedger,/created by I4|durable I4 write|durable-owner-approved-real-mcp-read|owner-i3/);
  const secondRead=await ownerCall(mcpUrl,'tools/call',4,{name:'read_file',arguments:{
    deviceId:approved.deviceId,path:file,
  }},ownerToken);
  assert.equal(secondRead.status,200);

  // A real command child is held active and cancelled through the authenticated
  // poll control channel. The agent commits an ambiguous outcome and never
  // reports rollback or replays the request.
  await stopWorker(active);active=null;
  let commandPid;
  client=agentClient({identity,deviceId:approved.deviceId,clientSecret:SERVICE_SECRET,
    fetchFn:createTlsFetch({port:edgeInfo.port,ca:certificate.cert,observed:[]})});
  active=await startWorker(client,approved.deviceId,allowedRoot,cancellationExecutionDirectory,
    identity,policyKeys.publicKey,{sleepCommandForTimeout:true,onCommandSpawn:pid=>{
      commandPid=pid;
    }});
  await waitFor(()=>trustStore.registry.listDevices()[0]?.online,'cancellable command device session');
  const cancelOwner=new AbortController();
  const canceledResponse=ownerCall(mcpUrl,'tools/call',70,{name:'run_command',arguments:{
    deviceId:approved.deviceId,path:file,profile:'count_lines',
  }},ownerToken,cancelOwner.signal).then(value=>({value}),error=>({error}));
  await waitFor(()=>Number.isSafeInteger(commandPid),'cancellable command process spawn');
  assert.ok(Number.isSafeInteger(commandPid));
  const cancelledIntent=await waitFor(()=>{
    try{
      const records=readFileSync(path.join(cancellationExecutionDirectory,'i4-execution.jsonl'),'utf8')
        .trim().split('\n').map(line=>JSON.parse(line));
      return records.find(record=>record.type==='intent'&&record.tool==='run_command');
    }catch{return false;}
  },'durable cancellation intent');
  assert.equal(ingressRef.current.operationState(cancelledIntent.requestId).state,'delivered');
  cancelOwner.abort();
  const ownerCancellation=await canceledResponse;
  assert.ok(ownerCancellation.error,'owner disconnect is not converted to a successful response');
  await waitFor(()=>ingressRef.current.operationState(cancelledIntent.requestId)?.state==='ambiguous',
    'agent cancellation acknowledgement');
  const cancellationRecords=readFileSync(path.join(cancellationExecutionDirectory,'i4-execution.jsonl'),'utf8')
    .trim().split('\n').map(line=>JSON.parse(line));
  assert.equal(cancellationRecords.find(record=>record.type==='outcome'&&
    record.requestId===cancelledIntent.requestId)?.status,'ambiguous');
  assert.equal(cancellationRecords.filter(record=>record.type==='intent'&&
    record.requestId===cancelledIntent.requestId).length,1,'ambiguous execution is never replayed');
  await stopWorker(active);active=null;

  // Revoking the exact command grant while a process is running causes the
  // Gateway poll fence to request cooperative cancellation; no success crosses
  // the now-revoked authorization boundary.
  commandPid=undefined;
  client=agentClient({identity,deviceId:approved.deviceId,clientSecret:SERVICE_SECRET,
    fetchFn:createTlsFetch({port:edgeInfo.port,ca:certificate.cert,observed:[]})});
  active=await startWorker(client,approved.deviceId,allowedRoot,revokeExecutionDirectory,
    identity,policyKeys.publicKey,{sleepCommandForTimeout:true,onCommandSpawn:pid=>{
      commandPid=pid;
    }});
  await waitFor(()=>trustStore.registry.listDevices()[0]?.online,'grant-revocation device session');
  const revokedCall=ownerCall(mcpUrl,'tools/call',71,{name:'run_command',arguments:{
    deviceId:approved.deviceId,path:file,profile:'count_lines',
  }},ownerToken);
  await waitFor(()=>Number.isSafeInteger(commandPid),'grant-revocation command process spawn');
  const revokeIntent=await waitFor(()=>{
    try{
      return readFileSync(path.join(revokeExecutionDirectory,'i4-execution.jsonl'),'utf8')
        .trim().split('\n').map(line=>JSON.parse(line))
        .find(record=>record.type==='intent'&&record.tool==='run_command');
    }catch{return false;}
  },'durable grant revocation intent');
  assert.ok(Number.isSafeInteger(commandPid));
  grantRevision=toolGrantStore.revoke(grants.run_command,{expectedRevision:grantRevision,
    eventId:randomUUID()}).revision;
  const revokedResponse=await revokedCall;
  assert.equal(revokedResponse.status,503);
  await waitFor(()=>ingressRef.current.operationState(revokeIntent.requestId)?.state==='ambiguous',
    'grant revocation cancellation acknowledgement');
  const revokeRecords=readFileSync(path.join(revokeExecutionDirectory,'i4-execution.jsonl'),'utf8')
    .trim().split('\n').map(line=>JSON.parse(line));
  assert.equal(revokeRecords.find(record=>record.type==='outcome'&&
    record.requestId===revokeIntent.requestId)?.status,'ambiguous');
  await stopWorker(active);active=null;

  // Simulate a Gateway process restart. An old signed session must not survive
  // reload even though the approved public identity and trust revision do.
  let oldClient=agentClient({identity,deviceId:approved.deviceId,clientSecret:SERVICE_SECRET,
    fetchFn:createTlsFetch({port:edgeInfo.port,ca:certificate.cert,observed:[]})});
  await oldClient.connect();await oldClient.heartbeat();
  await gateway.close();gateway=null;
  audit.close();audit=null;
  trustStore.close();trustStore=null;
  trustStore=createDurableDeviceTrustStore({directory:trustDirectory});
  assert.equal(trustStore.revision(),1);
  assert.equal(trustStore.registry.listDevices()[0]?.online,false);
  audit=createDurableOwnerAudit({directory:auditDirectory});
  assert.equal(audit.inspect().pending,0);
  audit.close();audit=null;
  const reloadedIdentity=loadOrCreateDeviceIdentity({directory:identityDirectory,platform:process.platform});
  assert.equal(reloadedIdentity.fingerprint,identity.fingerprint,'agent Ed25519 identity survives its own restart');
  assert.deepEqual(reloadedIdentity.deviceBinding,identity.deviceBinding,
    'approved device and M2M Client-ID binding survive the agent restart');
  gateway=gatewayFactory();await gateway.ready;
  const restartedMcp=await gateway.ownerMcpReady;
  await assert.rejects(oldClient.heartbeat(),error=>error.code==='REJECTED');
  oldClient.close();
  client=agentClient({identity,deviceId:approved.deviceId,clientSecret:SERVICE_SECRET,
    fetchFn:createTlsFetch({port:edgeInfo.port,ca:certificate.cert,observed:[]})});
  active=await startWorker(client,approved.deviceId,allowedRoot,executionDirectory,identity,
    policyKeys.publicKey);
  await waitFor(()=>trustStore.registry.listDevices()[0]?.online,'post-restart authenticated heartbeat');
  const afterRestart=await ownerCall(restartedMcp,'tools/call',5,{name:'read_file',arguments:{
    deviceId:approved.deviceId,path:file,
  }},ownerToken);
  assert.equal(afterRestart.status,200);
  assert.match(JSON.stringify(afterRestart.body),/durable-owner-approved-real-mcp-read/);

  await stopWorker(active);active=null;
  // Regrant the fixed command profile, then revoke device trust while its
  // process is active. The operation may have taken effect, so the Gateway
  // returns an ambiguous result and never converts revocation into rollback.
  const renewedCommandGrant=toolGrantStore.grant({ownerDigest,deviceId:approved.deviceId,
    fingerprint:identity.fingerprint,tool:'run_command',
    scope:{root:allowedRoot,profile:'count_lines'},
    constraints:{maxOutputBytes:16*1024,maxRuntimeMs:10_000,profile:'count_lines'}},
    {expectedRevision:grantRevision,eventId:randomUUID()});
  grantRevision=renewedCommandGrant.revision;grants.run_command=renewedCommandGrant.grantId;
  const trustRevokeExecutionDirectory=path.join(home,'trust-revoke-execution');
  mkdirSync(trustRevokeExecutionDirectory,{mode:0o700});
  let trustRevokePid;
  client=agentClient({identity,deviceId:approved.deviceId,clientSecret:SERVICE_SECRET,
    fetchFn:createTlsFetch({port:edgeInfo.port,ca:certificate.cert,observed:[]})});
  active=await startWorker(client,approved.deviceId,allowedRoot,trustRevokeExecutionDirectory,
    identity,policyKeys.publicKey,{sleepCommandForTimeout:true,onCommandSpawn:pid=>{
      trustRevokePid=pid;
    }});
  const trustRevokeWorkerDone=active.done.then(()=>null,error=>error);
  await waitFor(()=>trustStore.registry.listDevices()[0]?.online,'trust-revocation command device session');
  const trustRevokedCall=ownerCall(restartedMcp,'tools/call',72,{name:'run_command',arguments:{
    deviceId:approved.deviceId,path:file,profile:'count_lines',
  }},ownerToken);
  await waitFor(()=>Number.isSafeInteger(trustRevokePid),'trust-revocation command process spawn');
  const trustRevokeIntent=await waitFor(()=>{
    try{return readFileSync(path.join(trustRevokeExecutionDirectory,'i4-execution.jsonl'),'utf8')
      .trim().split('\n').map(line=>JSON.parse(line))
      .find(record=>record.type==='intent'&&record.tool==='run_command');}catch{return false;}
  },'durable trust-revocation execution intent');
  assert.ok(Number.isSafeInteger(trustRevokePid));
  assert.equal(ingressRef.current.operationState(trustRevokeIntent.requestId).state,'delivered');
  assert.equal(trustStore.revokeDevice(approved.deviceId),true);
  const trustRevokedResponse=await trustRevokedCall;
  assert.equal(trustRevokedResponse.status,503);
  assert.match(trustRevokedResponse.body.error.data.code,/AMBIGUOUS/);
  assert.equal(trustStore.revision(),2);
  assert.equal(analyzeOwnerPairingRecovery({auditDirectory,trustDirectory}).state,'CONSISTENT');
  active.controller.abort();
  const postRevokeWorkerError=await trustRevokeWorkerDone;
  assert.ok(postRevokeWorkerError===null||['REJECTED','AMBIGUOUS_TRANSPORT','CLOSED']
    .includes(postRevokeWorkerError.code));
  active=null;
  const trustRevokeRecords=readFileSync(path.join(trustRevokeExecutionDirectory,'i4-execution.jsonl'),'utf8')
    .trim().split('\n').map(line=>JSON.parse(line));
  assert.equal(trustRevokeRecords.filter(record=>record.type==='intent'&&
    record.requestId===trustRevokeIntent.requestId).length,1,'revoked execution is never replayed');
  assert.ok(!trustRevokeRecords.some(record=>record.type==='outcome'&&
    record.requestId===trustRevokeIntent.requestId&&record.status==='success'),
    'a result from the revoked session is never recorded as an authorized success');
  const deniedRead=await ownerCall(restartedMcp,'tools/call',6,{name:'read_file',arguments:{
    deviceId:approved.deviceId,path:file,
  }},ownerToken);
  assert.equal(deniedRead.status,403);
  assert.equal(trustStore.registry.listDevices().length,0);
  assert.equal(edge.requestCount>requestsBefore,true);
  assert.equal(approved.deviceId.length,36);
  assert.equal(ownerKeys.jwk.kty,'RSA');
});
