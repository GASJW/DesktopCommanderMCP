import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createAuth0OwnerVerifier } from '../owner/auth0-owner-auth.mjs';
import { createDurableOwnerAuthority, ownerAuthorityApprovalSigningBytes,
  ownerAuthorityTargetDigest } from '../owner/durable-owner-authority.mjs';
import { createIsolatedRealmProvisioning } from '../owner/isolated-realm-provisioning.mjs';
import { createDurableOwnerAudit, inspectDurableOwnerAudit,
  readDurableOwnerMachineBindingDecision, readDurableOwnerMachineBindingHistory }
  from '../dashboard/durable-owner-audit.mjs';
import { createDurableOwnerDeviceApprovalByIdReader }
  from '../dashboard/durable-owner-device-authorization.mjs';
import { createOwnerMachineBindingService } from '../dashboard/owner-machine-binding.mjs';
import { createDurableDeviceTrustStore } from '../devices/durable-trust.mjs';
import { inspectDurableDeviceTrust } from '../devices/durable-trust.mjs';
import { createDurableMachineBindingStore } from '../devices/durable-machine-bindings.mjs';
import { inspectDurableMachineBindingSnapshot } from '../devices/durable-machine-bindings.mjs';
import { createDurableToolGrantStore } from '../devices/durable-tool-grants.mjs';
import { createPairingCoordinator, pairingProofMessage } from '../devices/pairing.mjs';

const linuxUnprivileged=process.platform==='linux'&&typeof process.getuid==='function'&&process.getuid()!==0;
const ISSUER='https://auth.example.test/';
const RESOURCE='https://g7.example.test/chatgpt/mcp';
const CLIENT='chatgpt-cimd-test';
const REALM='8ef7e14e-6291-4a58-bd25-1707d1f2067f';
const ROOT='/srv/g7-read';
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
  return {home,paths,realmConfig,authority,principal,tokenFor,makeApproval,trustStore,
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

function bindDevice(f,device){
  const target={realmId:REALM,ownerDigest:f.principal.ownerDigest,clientId:'i8h-synthetic-client',
    deviceId:device.challenge.deviceId,fingerprint:device.challenge.fingerprint,
    bindingRevision:f.machineBindingStore.revision(),pairingEventId:device.approval.eventId};
  const approval=f.makeApproval({operation:'binding.create',expectedRevision:target.bindingRevision,target});
  return f.provisioner.bindDevice({accessToken:f.tokenFor(),approval,clientId:target.clientId,
    deviceId:target.deviceId,fingerprint:target.fingerprint,expectedRevision:target.bindingRevision});
}

function issueGrant(f,device){
  const expectedRevision=f.grantStore.revision();
  const grant={ownerDigest:f.principal.ownerDigest,deviceId:device.challenge.deviceId,
    fingerprint:device.challenge.fingerprint,tool:'read_file',scope:{root:ROOT},constraints:CONSTRAINTS};
  const target={realmId:REALM,...grant,policyRevision:expectedRevision};
  const approval=f.makeApproval({operation:'grant.issue',expectedRevision,target});
  return f.provisioner.issueReadFileGrant({accessToken:f.tokenFor(),approval,
    deviceId:grant.deviceId,fingerprint:grant.fingerprint,root:ROOT,
    constraints:CONSTRAINTS,expectedRevision});
}

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
