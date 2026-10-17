import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { generateKeyPairSync } from 'node:crypto';
import { signToolGrantCapability, toolArgumentsDigest,
  verifyToolGrantCapability } from '../../../gateway/devices/tool-grant-capability.mjs';

const DEVICE='b7e92caf-f591-44c4-8fb7-6c489ea573f4';
const REQUEST='b7e92caf-f591-44c4-8fb7-6c489ea573f5';
const APPROVAL='b7e92caf-f591-44c4-8fb7-6c489ea573f6';
const GRANT='b7e92caf-f591-44c4-8fb7-6c489ea573f7';
const DECISION='b7e92caf-f591-44c4-8fb7-6c489ea573f8';
const FINGERPRINT='b'.repeat(64),OWNER='a'.repeat(64);
const now=1_800_000_000_000;

function fixture(){
  const {privateKey,publicKey}=generateKeyPairSync('ed25519');
  const root=path.resolve('/tmp/i4-approved');
  const args={path:path.join(root,'file.txt'),offset:0,length:10};
  const claims={version:1,grantId:GRANT,decisionId:DECISION,requestId:REQUEST,
    ownerDigest:OWNER,deviceId:DEVICE,fingerprint:FINGERPRINT,tool:'read_file',
    argumentsDigest:toolArgumentsDigest('read_file',args),policyRevision:3,
    approvalEventId:APPROVAL,trustRevision:7,approvalTrustRevisionBefore:6,
    approvalTrustRevisionAfter:7,scope:{root},constraints:{maxBytes:65536,maxLength:100,maxOffset:1000},
    issuedAt:now,expiresAt:now+30_000};
  return {privateKey,publicKey,root,args,claims,authorization:signToolGrantCapability(claims,privateKey)};
}

test('signed grant capability binds exact device, request, tool, arguments and approved path',()=>{
  const f=fixture();
  assert.deepEqual(verifyToolGrantCapability(f.authorization,f.publicKey,{now,
    deviceId:DEVICE,requestId:REQUEST,fingerprint:FINGERPRINT,tool:'read_file',
    arguments:f.args,allowedRoot:f.root}),f.claims);
});

test('grant capability rejects unsigned, altered, expired or mismatched authorization data',()=>{
  const f=fixture();
  const check=overrides=>assert.throws(()=>verifyToolGrantCapability(
    overrides?.authorization??f.authorization,overrides?.publicKey??f.publicKey,{now:overrides?.now??now,
      deviceId:overrides?.deviceId??DEVICE,requestId:overrides?.requestId??REQUEST,
      fingerprint:overrides?.fingerprint??FINGERPRINT,tool:overrides?.tool??'read_file',
      arguments:overrides?.arguments??f.args,allowedRoot:overrides?.allowedRoot??f.root}),
  /capability|authorization|scope|expired/i);
  check({deviceId:'00000000-0000-4000-8000-000000000000'});
  check({requestId:'00000000-0000-4000-8000-000000000000'});
  check({fingerprint:'c'.repeat(64)});
  check({tool:'write_file'});
  check({arguments:{...f.args,offset:1}});
  check({arguments:{path:'/outside/secret.txt',offset:0,length:10}});
  check({allowedRoot:'/different/root'});
  check({now:now+31_000});
  check({authorization:{...f.authorization,signature:'A'.repeat(86)}});
  check({publicKey:generateKeyPairSync('ed25519').publicKey});
});

test('grant capability enforces per-tool resource restrictions independently on the agent',()=>{
  const f=fixture();
  const tooMuch={...f.args,length:101};
  const authorization=signToolGrantCapability({...f.claims,
    argumentsDigest:toolArgumentsDigest('read_file',tooMuch)},f.privateKey);
  assert.throws(()=>verifyToolGrantCapability(authorization,f.publicKey,{now,
    deviceId:DEVICE,requestId:REQUEST,fingerprint:FINGERPRINT,tool:'read_file',
    arguments:tooMuch,allowedRoot:f.root}),/scope|constraint|authorization/i);
});
