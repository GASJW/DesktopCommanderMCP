import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { createGovernedAgentExecutor } from '../src/governed-executor.mjs';
import { signToolGrantCapability, toolArgumentsDigest } from '../../../gateway/devices/tool-grant-capability.mjs';

const [root,state,target,requestId,deviceId,fixture]=process.argv.slice(2);
const fingerprint='b'.repeat(64),{privateKey,publicKey}=generateKeyPairSync('ed25519');
const args={path:target,content:'same durable write\n',mode:'create'};
const claims={version:1,grantId:randomUUID(),decisionId:randomUUID(),requestId,
  ownerDigest:'a'.repeat(64),deviceId,fingerprint,tool:'write_file',
  argumentsDigest:toolArgumentsDigest('write_file',args),policyRevision:1,
  approvalEventId:'b7e92caf-f591-44c4-8fb7-6c489ea573f5',trustRevision:3,
  approvalTrustRevisionBefore:2,approvalTrustRevisionAfter:3,scope:{root},
  constraints:{maxBytes:64*1024},issuedAt:Date.now(),expiresAt:Date.now()+30_000};
const executor=createGovernedAgentExecutor({allowedRoot:root,ledgerDirectory:state,entrypoint:fixture,
  gatewayPolicyPublicKey:publicKey,deviceId,fingerprint});
try{
  await executor.start();
  await executor.handle({version:1,method:'tools/call',deviceId,
    sessionId:'f1a2b3c4-d5e6-4a9f-8abc-1bb9b99c0002',requestId,
    authorization:signToolGrantCapability(claims,privateKey),
    params:{name:'write_file',arguments:args}});
  process.stdout.write(JSON.stringify({status:'success'})+'\n');
}catch(error){
  process.stdout.write(JSON.stringify({status:'rejected',code:error?.code??'ERROR'})+'\n');
}finally{await executor.close();}
