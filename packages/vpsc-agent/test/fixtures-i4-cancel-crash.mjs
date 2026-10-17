import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { createGovernedAgentExecutor } from '../src/governed-executor.mjs';
import { signToolGrantCapability, toolArgumentsDigest } from '../../../gateway/devices/tool-grant-capability.mjs';

const [root,state,target,requestId,deviceId,entrypoint]=process.argv.slice(2);
const fingerprint='b'.repeat(64),{privateKey,publicKey}=generateKeyPairSync('ed25519');
const args={path:target,content:'effect-before-cancel-crash\n',mode:'create'};
const claims={version:1,grantId:randomUUID(),decisionId:randomUUID(),requestId,
  ownerDigest:'a'.repeat(64),deviceId,fingerprint,tool:'write_file',
  argumentsDigest:toolArgumentsDigest('write_file',args),policyRevision:1,
  approvalEventId:'b7e92caf-f591-44c4-8fb7-6c489ea573f5',trustRevision:3,
  approvalTrustRevisionBefore:2,approvalTrustRevisionAfter:3,scope:{root},
  constraints:{maxBytes:64*1024},issuedAt:Date.now(),expiresAt:Date.now()+30_000};
const cancellation=new AbortController();
process.once('SIGUSR1',()=>cancellation.abort());
const executor=createGovernedAgentExecutor({allowedRoot:root,ledgerDirectory:state,entrypoint,
  gatewayPolicyPublicKey:publicKey,deviceId,fingerprint,
  testHooks:{afterOperationBeforeOutcome:async()=>{
    await new Promise(()=>{
      cancellation.signal.addEventListener('abort',()=>{
        process.stdout.write('CANCELLATION_OBSERVED\n');
      },{once:true});
      process.stdout.write('EFFECT_DURABLE\n');
    });
  }}});
await executor.start();
await executor.handle({version:1,method:'tools/call',deviceId,
  sessionId:'b12837a6-d89d-4ae1-b2de-30e9710d21c0',requestId,
  authorization:signToolGrantCapability(claims,privateKey),
  params:{name:'write_file',arguments:args}},{signal:cancellation.signal});
