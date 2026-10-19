import { createServer as createHttpsServer } from 'node:https';
import { Readable } from 'node:stream';
import { createPrivateKey, createPublicKey, randomUUID, sign, timingSafeEqual } from 'node:crypto';
import path from 'node:path';
import { createAccessVerifier } from '../access-auth.mjs';
import { createDurableOwnerAudit, readDurableOwnerMachineBindingDecision,
  readDurableOwnerMachineBindingHistory } from '../dashboard/durable-owner-audit.mjs';
import { createOwnerPairingHttp } from '../dashboard/owner-pairing-http.mjs';
import { createDurableOwnerDeviceApprovalReader, createDurableOwnerDeviceApprovalByIdReader,
  createDurableOwnerDeviceAuthorizer } from '../dashboard/durable-owner-device-authorization.mjs';
import { createOwnerMachineBindingService } from '../dashboard/owner-machine-binding.mjs';
import { ownerIdentityDigest, ownerPrincipalId, isOwnerPrincipal } from '../dashboard/owner-identity.mjs';
import { createDurableDeviceTrustStore } from '../devices/durable-trust.mjs';
import { createPairingCoordinator } from '../devices/pairing.mjs';
import { createMachineAccessVerifier } from '../devices/machine-access.mjs';
import { createAuthenticatedMachineIngress } from '../devices/persistent-machine-ingress.mjs';
import { createDeviceRouter } from '../devices/router.mjs';
import { createRemoteDeviceMcpHandler } from '../devices/remote-mcp-handler.mjs';
import { createDurableToolGrantStore } from '../devices/durable-tool-grants.mjs';
import { createDurableMachineBindingStore } from '../devices/durable-machine-bindings.mjs';
import { readPrivateStagingFile } from './private-file.mjs';

const HOST='127.0.0.1';
const OWNER_ORIGIN=/^https:\/\/[a-z0-9.-]+$/;
const OWNER_TEST_ISSUER='https://g7-owner-staging.cloudflareaccess.com';
const MACHINE_TEST_ISSUER='https://g7-machine-staging.cloudflareaccess.com';
export function isValidStagingIssuer(value,role){
  if(role==='owner')return value===OWNER_TEST_ISSUER;
  if(role==='machine')return value===MACHINE_TEST_ISSUER;
  return false;
}
const CLIENT=/^[A-Za-z0-9_.-]{8,256}$/;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HEX64=/^[a-f0-9]{64}$/;
const AGENT_PATHS=new Set(['/agent/challenge','/agent/connect','/agent/heartbeat',
  '/agent/poll','/agent/result','/agent/cancel-ack','/agent/disconnect']);
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&
  Object.getPrototypeOf(value)===Object.prototype&&Object.keys(value).sort().join(',')===keys;
const reply=(res,status,body)=>{
  if(res.writableEnded||res.destroyed)return;
  res.writeHead(status,{'content-type':'application/json; charset=utf-8','cache-control':'no-store',
    'x-content-type-options':'nosniff','referrer-policy':'no-referrer'});
  res.end(JSON.stringify(body));
};
function assertPrivateFile(filename,{privateOnly=true}={}){
  return readPrivateStagingFile(filename,{privateOnly});
}
function validateConfig(c){
  const paths=c?.storage;
  if(process.platform!=='linux'||typeof process.getuid!=='function'||process.getuid()===0)
    throw new Error('G7 staging runtime requires a nonroot Linux user');
  const machineV1=exact(c?.machine,'audience,clientId,issuer,jwks,serviceSecret,signingKeyPath');
  const machineV2=exact(c?.machine,'audience,clients,issuer,jwks,signingKeyPath');
  if(!exact(c,'hostname,listen,machine,owner,policy,storage,tls,version')||
     !(c.version===1&&machineV1||c.version===2&&machineV2)||
     typeof c.hostname!=='string'||!/^[a-z0-9.-]{6,255}$/.test(c.hostname)||
     !c.hostname.includes('.')||c.hostname==='localhost'||c.hostname.endsWith('.local')||
     !exact(c.listen,'host,port')||c.listen.host!==HOST||!Number.isSafeInteger(c.listen.port)||
     c.listen.port<0||c.listen.port>65535||
     !exact(c.tls,'certificatePath,keyPath')||
     !exact(c.owner,'audience,controlToken,email,issuer,jwks,origin,subject')||
     !exact(c.policy,'directory,privateKeyPem,publicKeyPem')||
     !exact(paths,'auditDirectory,bindingDirectory,grantDirectory,trustDirectory')||
     ![paths.auditDirectory,paths.bindingDirectory,paths.grantDirectory,paths.trustDirectory,
       c.policy.directory].every(p=>typeof p==='string'&&path.isAbsolute(p)&&path.normalize(p)===p)||
     new Set([paths.auditDirectory,paths.bindingDirectory,paths.grantDirectory,
       paths.trustDirectory,c.policy.directory]).size!==5||
     !isValidStagingIssuer(c.owner.issuer,'owner')||
     !isValidStagingIssuer(c.machine.issuer,'machine')||
     c.owner.issuer===c.machine.issuer||!HEX64.test(c.owner.audience)||!HEX64.test(c.machine.audience)||
     c.owner.audience===c.machine.audience||!OWNER_ORIGIN.test(c.owner.origin)||
     c.owner.origin!==`https://${c.hostname}`||
     typeof c.owner.email!=='string'||!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(c.owner.email)||
     typeof c.owner.subject!=='string'||c.owner.subject.length<1||c.owner.subject.length>1024||
     typeof c.owner.controlToken!=='string'||!/^[a-f0-9]{64}$/.test(c.owner.controlToken)||
     !Array.isArray(c.owner.jwks)||c.owner.jwks.length!==1||
     !Array.isArray(c.machine.jwks)||c.machine.jwks.length!==1||
     !c.owner.jwks[0]||!c.machine.jwks[0])throw new Error('Invalid or incomplete staging configuration');
  const machineClients=c.version===1
    ?[{clientId:c.machine.clientId,serviceSecret:c.machine.serviceSecret}]
    :c.machine.clients;
  if(!Array.isArray(machineClients)||machineClients.length<(c.version===2?2:1)||
     machineClients.length>64||machineClients.some(item=>!exact(item,'clientId,serviceSecret')||
       typeof item.clientId!=='string'||!CLIENT.test(item.clientId)||
       typeof item.serviceSecret!=='string'||item.serviceSecret.length<24||
       /[\r\n\0]/.test(item.serviceSecret))||
     new Set(machineClients.map(item=>item.clientId)).size!==machineClients.length||
     new Set(machineClients.map(item=>item.serviceSecret)).size!==machineClients.length){
    throw new Error('Staging machine identities must use distinct Client-IDs and secrets');
  }
  for(const jwk of [c.owner.jwks[0],c.machine.jwks[0]]){
    if(jwk.kty!=='RSA'||jwk.alg!=='RS256'||typeof jwk.kid!=='string'||
       typeof jwk.n!=='string'||typeof jwk.e!=='string'||'d' in jwk)throw new Error('Staging JWKS must contain public RSA keys only');
  }
  const tlsKey=assertPrivateFile(c.tls.keyPath);
  const tlsCert=assertPrivateFile(c.tls.certificatePath,{privateOnly:false});
  const machineSigningKey=assertPrivateFile(c.machine.signingKeyPath);
  const signer=createPrivateKey(machineSigningKey);
  const signedPublic=createPublicKey(signer).export({format:'jwk'});
  if(signer.asymmetricKeyType!=='rsa'||signedPublic.n!==c.machine.jwks[0].n||signedPublic.e!==c.machine.jwks[0].e)
    throw new Error('Machine signing key does not match its public verifier key');
  const policyPrivate=createPrivateKey(c.policy.privateKeyPem);
  const policyPublic=createPublicKey(c.policy.publicKeyPem);
  if(policyPrivate.asymmetricKeyType!=='ed25519'||policyPublic.asymmetricKeyType!=='ed25519'||
     !createPublicKey(policyPrivate).export({type:'spki',format:'der'}).equals(
       policyPublic.export({type:'spki',format:'der'})))throw new Error('Gateway policy key pair is inconsistent');
  return {tls:{key:tlsKey,cert:tlsCert},machineSigner:signer,policyPrivate,policyPublic,
    machineClients};
}
async function readJson(req,maxBytes=32*1024){
  const chunks=[];let size=0;
  for await(const chunk of req){size+=chunk.length;if(size>maxBytes)throw Error('request too large');chunks.push(chunk);}
  return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks,size)));
}
function mintMachineJwt(config,privateKey,clientId){
  // This short-lived assertion is internal to the TLS Gateway composition;
  // the external edge rejects client-supplied assertions. Replay defense for
  // agent operations is the one-use challenge plus signed monotonic frame sequence.
  const now=Math.floor(Date.now()/1000),head=Buffer.from(JSON.stringify({alg:'RS256',kid:config.machine.jwks[0].kid})).toString('base64url');
  const body=Buffer.from(JSON.stringify({type:'app',sub:'',common_name:clientId,
    iss:config.machine.issuer,aud:config.machine.audience,iat:now,exp:now+60})).toString('base64url');
  return `${head}.${body}.${sign('RSA-SHA256',Buffer.from(`${head}.${body}`),privateKey).toString('base64url')}`;
}
function secretMatches(expected,actual){
  if(typeof actual!=='string'||actual.length!==expected.length)return false;
  return timingSafeEqual(Buffer.from(expected),Buffer.from(actual));
}
async function bodyBuffer(req,maxBytes){
  const chunks=[];let size=0;
  for await(const chunk of req){size+=chunk.length;if(size>maxBytes)throw Error('request too large');chunks.push(chunk);}
  return Buffer.concat(chunks,size);
}

// Explicit staging composition. This module is never imported by gateway/server.mjs.
export async function startG7StagingGateway(config){
  const keys=validateConfig(config);
  const ownerBase=createAccessVerifier({issuer:config.owner.issuer,audience:config.owner.audience,
    allowedEmails:config.owner.email,keyProvider:async()=>({keys:config.owner.jwks})});
  const ownerAccess={verifyPrincipal:async token=>{
    const principal=await ownerBase.verifyPrincipal(token);
    return principal?.subject===config.owner.subject?principal:null;
  }};
  const machineAccess=createMachineAccessVerifier({issuer:config.machine.issuer,
    audience:config.machine.audience,allowedClientIds:keys.machineClients.map(item=>item.clientId),
    keyProvider:async()=>({keys:config.machine.jwks})});
  const storage=config.storage;
  const trustStore=createDurableDeviceTrustStore({directory:storage.trustDirectory});
  let audit,machineBindingStore,ingress,server,router,grantStore;
  try{
    audit=createDurableOwnerAudit({directory:storage.auditDirectory});
    const coordinator=createPairingCoordinator({registry:trustStore});
    const readApprovalReceipt=createDurableOwnerDeviceApprovalReader({
      auditDirectory:storage.auditDirectory,trustDirectory:storage.trustDirectory});
    const readApprovalById=createDurableOwnerDeviceApprovalByIdReader({
      auditDirectory:storage.auditDirectory,trustDirectory:storage.trustDirectory});
    const expectedOwner={issuer:config.owner.issuer,subject:config.owner.subject};
    const expectedOwnerId=ownerPrincipalId(expectedOwner);
    const expectedOwnerDigest=ownerIdentityDigest(expectedOwner);
    const bindingForDevice=deviceId=>keys.machineClients.map(item=>
      machineBindingStore.resolve(item.clientId)).find(binding=>binding?.deviceId===deviceId)??null;
    machineBindingStore=createDurableMachineBindingStore({directory:storage.bindingDirectory,
      verifyApprovalReceipt:binding=>binding.ownerId===expectedOwnerId&&
        binding.ownerDigest===expectedOwnerDigest?readApprovalById(binding.ownerId,binding.deviceId):null,
      readBindingDecision:binding=>readDurableOwnerMachineBindingDecision({
        directory:storage.auditDirectory,eventId:binding.bindingEventId}),
      readBindingHistory:()=>readDurableOwnerMachineBindingHistory({directory:storage.auditDirectory})});
    const bindingService=createOwnerMachineBindingService({accessVerifier:ownerAccess,
      auditWrite:audit.auditWrite,readApprovalReceipt,machineBindingStore});
    grantStore=createDurableToolGrantStore({directory:storage.grantDirectory});
    router=createDeviceRouter({registry:trustStore.registry,timeoutMs:30_000});
    const shouldCancelOperation=frame=>{
      const claims=frame?.authorization?.claims;
      if(!claims||claims.deviceId!==frame.deviceId||claims.requestId!==frame.requestId)return false;
      try{return grantStore.withCurrentAuthorization({grantId:claims.grantId,
        ownerDigest:claims.ownerDigest,deviceId:claims.deviceId,fingerprint:claims.fingerprint,
        tool:claims.tool,policyRevision:claims.policyRevision},()=>
          trustStore.registry.isLiveSession(frame.deviceId,frame.sessionId))===true;}catch{return false;}
    };
    ingress=createAuthenticatedMachineIngress({registry:trustStore.registry,router,
      verifyMachineToken:machineAccess,machineBindingStore,
      getTrustRevision:()=>trustStore.revision(),shouldCancelOperation});
    const pairingHandler=createOwnerPairingHttp({coordinator,accessVerifier:ownerAccess,
      expectedOrigin:config.owner.origin,auditWrite:audit.auditWrite});
    const mcpHandler=createRemoteDeviceMcpHandler({accessVerifier:ownerAccess,
      deviceRegistry:trustStore.registry,trustStore,router,
      authorizeDevice:createDurableOwnerDeviceAuthorizer({auditDirectory:storage.auditDirectory,
        trustDirectory:storage.trustDirectory}),grantStore,policySigningKey:keys.policyPrivate,
      getTrustRevision:()=>trustStore.revision(),getDeviceApprovalReceipt:readApprovalReceipt});
    const handle=async(req,res)=>{
      try{
        const url=new URL(req.url,'https://'+config.hostname);
        if(url.pathname==='/healthz'&&req.method==='GET'){
          return reply(res,200,{status:'ready',runtime:'g7-staging',pid:process.pid,
            trustRevision:trustStore.revision(),policyRevision:grantStore.revision(),
            bindingRevision:machineBindingStore.revision()});
        }
        if(url.pathname==='/pairing/start'&&req.method==='POST'){
          const input=await readJson(req,4096);
          if(!exact(input,'name,platform,publicKeyPem'))return reply(res,400,{error:'Invalid pairing request'});
          const challenge=coordinator.startPairing(input);
          return reply(res,201,challenge);
        }
        if(url.pathname==='/pairing/prove'&&req.method==='POST'){
          const input=await readJson(req,4096);
          if(!exact(input,'proof,requestId'))return reply(res,400,{error:'Invalid pairing proof'});
          const proved=coordinator.provePossession(input.requestId,input.proof);
          return reply(res,proved?200:403,{proved});
        }
        if(url.pathname.startsWith('/dashboard/api/g7/pairing/'))
          return await pairingHandler(req,res);
        if(url.pathname==='/mcp')return await mcpHandler(req,res);
        if(AGENT_PATHS.has(url.pathname)){
          const machineClient=keys.machineClients.find(item=>item.clientId===
            req.headers['cf-access-client-id']);
          if(req.method!=='POST'||req.headers.origin||req.headers.cookie||
             req.headers['cf-access-jwt-assertion']||
             !machineClient||!secretMatches(machineClient.serviceSecret,
               req.headers['cf-access-client-secret']))
            return reply(res,403,{error:'Machine service token denied'});
          let body;try{body=await bodyBuffer(req,256*1024);}catch{return reply(res,413,{error:'Request too large'});}
          const headers={'content-type':'application/json','cf-access-jwt-assertion':
            mintMachineJwt(config,keys.machineSigner,machineClient.clientId)};
          for(const name of ['x-vpsc-device-id','x-vpsc-session-id','x-vpsc-sequence','x-vpsc-signature']){
            if(typeof req.headers[name]==='string')headers[name]=req.headers[name];
          }
          const machineRequest=Readable.from([body]);
          machineRequest.url=url.pathname;machineRequest.method=req.method;machineRequest.headers=headers;
          return await ingress.handle(machineRequest,res);
        }
        if(url.pathname.startsWith('/stage/')){
          if(req.method!=='POST'||req.headers.origin!==config.owner.origin||
             !secretMatches(config.owner.controlToken,req.headers['x-vpsc-stage-control']))
            return reply(res,403,{error:'Staging control denied'});
          let owner;
          try{owner=await ownerAccess.verifyPrincipal(req.headers['cf-access-jwt-assertion']);}catch{}
          if(!isOwnerPrincipal(owner))return reply(res,401,{error:'Owner authentication required'});
          const input=await readJson(req,64*1024);
          if(url.pathname==='/stage/bind'){
            if(!exact(input,'clientId,deviceId,expectedRevision')||
               !keys.machineClients.some(item=>item.clientId===input.clientId))
              return reply(res,400,{error:'Invalid binding request'});
            const result=await bindingService.bind({ownerAssertion:req.headers['cf-access-jwt-assertion'],
              clientId:input.clientId,deviceId:input.deviceId,expectedRevision:input.expectedRevision});
            return reply(res,200,{revision:result.revision,binding:result.binding,alreadyBound:result.alreadyBound===true});
          }
          const deviceId=input.deviceId;
          if(!UUID.test(deviceId??''))return reply(res,400,{error:'Invalid device'});
          const receipt=readApprovalReceipt(owner,deviceId);
          const binding=bindingForDevice(deviceId);
          if(!receipt||!binding||binding.deviceId!==deviceId||binding.ownerId!==ownerPrincipalId(owner)||
             binding.ownerDigest!==ownerIdentityDigest(owner)||binding.fingerprint!==receipt.fingerprint)
            return reply(res,403,{error:'Owner device binding is not current'});
          if(url.pathname==='/stage/grant'){
            if(!exact(input,'constraints,deviceId,expectedRevision,scope,tool')||
               typeof input.tool!=='string')return reply(res,400,{error:'Invalid tool grant'});
            const created=grantStore.grant({ownerDigest:ownerIdentityDigest(owner),deviceId,
              fingerprint:receipt.fingerprint,tool:input.tool,scope:input.scope,
              constraints:input.constraints},{expectedRevision:input.expectedRevision,eventId:randomUUID()});
            return reply(res,201,{revision:grantStore.revision(),grant:{grantId:created.grantId,
              deviceId:created.deviceId,tool:created.tool,scope:created.scope,
              constraints:created.constraints,revision:created.revision}});
          }
          if(url.pathname==='/stage/revoke-grant'){
            if(!exact(input,'deviceId,expectedRevision,grantId')||!UUID.test(input.grantId??''))
              return reply(res,400,{error:'Invalid grant revocation'});
            const grant=grantStore.list().find(item=>item.grantId===input.grantId&&
              item.ownerDigest===ownerIdentityDigest(owner)&&item.deviceId===deviceId);
            if(!grant)return reply(res,404,{error:'Grant not found'});
            const revoked=grantStore.revoke(input.grantId,{expectedRevision:input.expectedRevision,eventId:randomUUID()});
            return reply(res,200,{revision:grantStore.revision(),grantId:revoked.grantId,active:revoked.active});
          }
          if(url.pathname==='/stage/revoke-device'){
            if(!exact(input,'clientId,deviceId')||input.clientId!==binding.clientId)
              return reply(res,400,{error:'Invalid device revocation'});
            const revoked=trustStore.revokeDevice(deviceId);
            return reply(res,200,{deviceId,revoked,trustRevision:trustStore.revision()});
          }
          return reply(res,404,{error:'Not found'});
        }
        return reply(res,404,{error:'Not found'});
      }catch(error){
        const status=error?.code==='OWNER_AUTH_REQUIRED'?401:error?.code==='REVISION_CONFLICT'?409:503;
        return reply(res,status,{error:status===503?'Staging operation unavailable':'Staging request denied'});
      }
    };
    server=createHttpsServer(keys.tls,handle);
    server.requestTimeout=15_000;server.headersTimeout=10_000;server.maxHeadersCount=64;
    await new Promise((resolve,reject)=>{
      server.once('error',reject);server.listen(config.listen.port,HOST,resolve);
    });
    return Object.freeze({url:`https://${config.hostname}:${server.address().port}/`,port:server.address().port,
      close:async()=>{
        server?.closeAllConnections?.();
        if(server?.listening)await new Promise(resolve=>server.close(resolve));
        router?.close();await ingress?.close();
        try{machineBindingStore?.close();}finally{
          try{audit?.close();}finally{trustStore.close();}
        }
      }});
  }catch(error){
    server?.closeAllConnections?.();
    if(server?.listening)await new Promise(resolve=>server.close(resolve));
    router?.close();await ingress?.close().catch(()=>{});
    try{machineBindingStore?.close();}catch{}
    try{audit?.close();}catch{}
    trustStore.close();
    throw error;
  }
}

export function readStagingConfig(filename){
  const configBytes=assertPrivateFile(filename);
  const config=JSON.parse(configBytes.toString('utf8'));
  return config;
}
