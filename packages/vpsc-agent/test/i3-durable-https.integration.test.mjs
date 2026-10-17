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
import { generateKeyPairSync, sign } from 'node:crypto';
import { createAccessVerifier } from '../../../gateway/access-auth.mjs';
import { createDurableOwnerAudit, inspectDurableOwnerAudit } from '../../../gateway/dashboard/durable-owner-audit.mjs';
import { createOwnerPairingHttp } from '../../../gateway/dashboard/owner-pairing-http.mjs';
import { analyzeOwnerPairingRecovery } from '../../../gateway/dashboard/owner-pairing-reconciliation.mjs';
import { createDurableOwnerDeviceAuthorizer } from '../../../gateway/dashboard/durable-owner-device-authorization.mjs';
import { createDurableDeviceTrustStore, inspectDurableDeviceTrust } from '../../../gateway/devices/durable-trust.mjs';
import { createPairingCoordinator } from '../../../gateway/devices/pairing.mjs';
import { createMachineAccessVerifier } from '../../../gateway/devices/machine-access.mjs';
import { startMachineIngressLoopback } from '../../../gateway/devices/machine-ingress-loopback.mjs';
import { createDeviceRouter } from '../../../gateway/devices/router.mjs';
import { createRemoteDeviceMcpHandler } from '../../../gateway/devices/remote-mcp-handler.mjs';
import { loadOrCreateDeviceIdentity } from '../src/identity-store.mjs';
import { createLocalReadonlyMcp } from '../src/local-mcp-readonly.mjs';
import { createHttpsAgentClient } from '../src/https-client.mjs';
import { createAgentWorker } from '../src/worker.mjs';

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
async function jsonPost(url,payload,{headers={},method='POST'}={}){
  const response=await fetch(url,{method,headers:{'content-type':'application/json',...headers},
    ...(payload===undefined?{}:{body:JSON.stringify(payload)})});
  const text=await response.text();
  return {status:response.status,headers:response.headers,
    body:text?JSON.parse(text):null};
}
async function waitFor(predicate,label){
  const deadline=Date.now()+5000;
  while(Date.now()<deadline){
    if(await predicate())return;
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
    observed.push({url:input,headers:{...headers},redirect:options.redirect,
      credentials:options.credentials,cache:options.cache});
    const request=httpsRequest({hostname:'127.0.0.1',port,servername:HOST,
      method:options.method,path:url.pathname,headers,ca,rejectUnauthorized:true},response=>{
      const chunks=[];let bytes=0;
      response.on('data',chunk=>{bytes+=chunk.length;chunks.push(chunk);});
      response.on('end',()=>resolve(new Response(Buffer.concat(chunks,bytes),{
        status:response.statusCode,headers:response.headers,
      })));
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
  auditDirectory,trustDirectory}){
  const router=createDeviceRouter({registry:trustStore.registry,timeoutMs:3000});
  const ingressPromise=startMachineIngressLoopback({registry:trustStore.registry,router,
    verifyMachineToken:machineAccess,machineBindings:bindings,enableTestIngress:true});
  const mcpServer=createHttpServer(createRemoteDeviceMcpHandler({
    accessVerifier:ownerAccess,deviceRegistry:trustStore.registry,router,
    authorizeDevice:createDurableOwnerDeviceAuthorizer({auditDirectory,trustDirectory}),
  }));
  let ownerMcpUrl;
  const ownerMcpReady=listen(mcpServer).then(url=>{ownerMcpUrl=url+'/mcp';return ownerMcpUrl;});
  return {
    router,mcpServer,ownerMcpReady,
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
    const seen={...req.headers};observed.edge.push(seen);
    if(seen['cf-access-client-id']!==expectedClientId||
       seen['cf-access-client-secret']!==expectedSecret){
      res.writeHead(403,{'content-type':'application/json'});res.end('{"error":"service token denied"}');return;
    }
    if(seen['cf-access-jwt-assertion']||seen.cookie||!ingressRef.current){
      res.writeHead(403,{'content-type':'application/json'});res.end('{"error":"identity boundary denied"}');return;
    }
    const chunks=[];let size=0;
    for await(const chunk of req){size+=chunk.length;if(size>16*1024){
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
function makeExecutor(root){
  return createLocalReadonlyMcp({allowedRoot:root,entrypoint:LOCAL_MCP_ENTRY,timeoutMs:5000,
  });
}
async function startWorker(client,deviceId,root){
  const controller=new AbortController();
  const worker=createAgentWorker({deviceId,client,executor:makeExecutor(root),pollIntervalMs:25});
  const done=worker.run({signal:controller.signal});
  return {worker,controller,done};
}
async function stopWorker(active){
  active.controller.abort();
  await active.done;
}
async function ownerCall(url,method,id,params,token){
  return jsonPost(url,{jsonrpc:'2.0',id,method,params},{headers:{
    'cf-access-jwt-assertion':token,
  }});
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

test('I3 E2E: Owner approval, durable trust, verified TLS, device route, local MCP read, restart and revoke',async t=>{
  const home=mkdtempSync(path.join(tmpdir(),'g7-i3-e2e-'));
  let trustStore=null,audit=null,gateway=null,edge=null,active=null;
  t.after(async()=>{
    if(active){active.controller.abort();await active.done.catch(()=>{});}
    await gateway?.close().catch(()=>{});
    await edge?.close().catch(()=>{});
    try{audit?.close();}catch{}
    try{trustStore?.close();}catch{}
    rmSync(home,{recursive:true,force:true});
  });
  const trustDirectory=path.join(home,'trust'),auditDirectory=path.join(home,'audit');
  const identityDirectory=path.join(home,'agent-identity');
  const allowedRoot=path.join(home,'approved-files');
  mkdirSync(allowedRoot,{mode:0o700});
  mkdirSync(identityDirectory,{mode:0o700});
  const file=path.join(allowedRoot,'approved.txt');
  writeFileSync(file,'durable-owner-approved-real-mcp-read\n',{mode:0o600});
  const ownerKeys=keyMaterial('owner-i3'),machineKeys=keyMaterial('machine-i3');
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
  const recoveryWhileAuditWriterOpen=analyzeOwnerPairingRecovery({auditDirectory,trustDirectory});
  assert.equal(recoveryWhileAuditWriterOpen.state,'ACTIVE_WRITER');
  assert.equal(recoveryWhileAuditWriterOpen.underlyingState,'CONSISTENT');
  assert.equal(recoveryWhileAuditWriterOpen.auditWriterActive,true);
  assert.equal(recoveryWhileAuditWriterOpen.trustWriterActive,false);

  const auditEvidence=inspectDurableOwnerAudit({directory:auditDirectory});
  const trustEvidence=inspectDurableDeviceTrust({directory:trustDirectory});
  assert.equal(auditEvidence.events.length,2);
  const [intent,outcome]=auditEvidence.events;
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
    bindings:new Map([[CLIENT,approved.deviceId]]),ingressRef,auditDirectory,trustDirectory});
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
  active=await startWorker(client,approved.deviceId,allowedRoot);
  await waitFor(()=>trustStore.registry.listDevices()[0]?.online,'authenticated device heartbeat');
  const init=await ownerCall(mcpUrl,'initialize',1,{protocolVersion:'2025-03-26',
    capabilities:{},clientInfo:{name:'i3-loopback-client',version:'1'}},ownerToken);
  assert.equal(init.status,200);assert.equal(init.body.result.serverInfo.name,'vpsc-g7-device-gateway');
  const machineAsOwner=await ownerCall(mcpUrl,'tools/call',10,{name:'read_file',arguments:{
    deviceId:approved.deviceId,path:file,
  }},machineJwt);
  assert.equal(machineAsOwner.status,401,'machine Access cannot impersonate the owner');
  const tools=await ownerCall(mcpUrl,'tools/list',2,{},ownerToken);
  assert.equal(tools.status,200);assert.deepEqual(tools.body.result.tools.map(tool=>tool.name),['read_file']);
  const read=await ownerCall(mcpUrl,'tools/call',3,{name:'read_file',arguments:{
    deviceId:approved.deviceId,path:file,
  }},ownerToken);
  assert.equal(read.status,200,JSON.stringify(read.body));
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
  active=await startWorker(client,approved.deviceId,allowedRoot);
  await waitFor(()=>trustStore.registry.listDevices()[0]?.online,'reconnected device heartbeat');
  const secondRead=await ownerCall(mcpUrl,'tools/call',4,{name:'read_file',arguments:{
    deviceId:approved.deviceId,path:file,
  }},ownerToken);
  assert.equal(secondRead.status,200);
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
  assert.equal(loadOrCreateDeviceIdentity({directory:identityDirectory,platform:process.platform}).fingerprint,
    identity.fingerprint,'agent Ed25519 identity survives its own restart');
  gateway=gatewayFactory();await gateway.ready;
  const restartedMcp=await gateway.ownerMcpReady;
  await assert.rejects(oldClient.heartbeat(),error=>error.code==='REJECTED');
  oldClient.close();
  client=agentClient({identity,deviceId:approved.deviceId,clientSecret:SERVICE_SECRET,
    fetchFn:createTlsFetch({port:edgeInfo.port,ca:certificate.cert,observed:[]})});
  active=await startWorker(client,approved.deviceId,allowedRoot);
  await waitFor(()=>trustStore.registry.listDevices()[0]?.online,'post-restart authenticated heartbeat');
  const afterRestart=await ownerCall(restartedMcp,'tools/call',5,{name:'read_file',arguments:{
    deviceId:approved.deviceId,path:file,
  }},ownerToken);
  assert.equal(afterRestart.status,200);
  assert.match(JSON.stringify(afterRestart.body),/durable-owner-approved-real-mcp-read/);

  await stopWorker(active);active=null;
  // Revocation advances the durable trust revision and fences the live key.
  const revocationClient=agentClient({identity,deviceId:approved.deviceId,clientSecret:SERVICE_SECRET,
    fetchFn:createTlsFetch({port:edgeInfo.port,ca:certificate.cert,observed:[]})});
  await revocationClient.connect();await revocationClient.heartbeat();
  assert.equal(trustStore.revokeDevice(approved.deviceId),true);
  assert.equal(trustStore.revision(),2);
  assert.equal(analyzeOwnerPairingRecovery({auditDirectory,trustDirectory}).state,'CONSISTENT');
  await assert.rejects(revocationClient.heartbeat(),error=>error.code==='REJECTED');
  revocationClient.close();
  const deniedRead=await ownerCall(restartedMcp,'tools/call',6,{name:'read_file',arguments:{
    deviceId:approved.deviceId,path:file,
  }},ownerToken);
  assert.equal(deniedRead.status,403);
  assert.equal(trustStore.registry.listDevices().length,0);
  assert.equal(edge.requestCount>requestsBefore,true);
  assert.equal(approved.deviceId.length,36);
  assert.equal(ownerKeys.jwk.kty,'RSA');
});
