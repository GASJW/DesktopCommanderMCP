import { createGovernedAgentExecutor } from '../src/governed-executor.mjs';

const [root,state,target,requestId,deviceId,entrypoint]=process.argv.slice(2);
const executor=createGovernedAgentExecutor({allowedRoot:root,ledgerDirectory:state,entrypoint,
  testHooks:{afterOperationBeforeOutcome:async()=>{
    process.stdout.write('AFTER_EFFECT_DURABLE\n');
    await new Promise(()=>{});
  }}});
await executor.start();
await executor.handle({version:1,method:'tools/call',deviceId,
  sessionId:'b12837a6-d89d-4ae1-b2de-30e9710d21c0',requestId,
  authorization:{approvalEventId:'b7e92caf-f591-44c4-8fb7-6c489ea573f5',
    approvalTrustRevisionBefore:2,approvalTrustRevisionAfter:3,fingerprint:'b'.repeat(64),
    ownerDigest:'a'.repeat(64),trustRevision:3,policyRevision:'i4-crash-test-v1'},
  params:{name:'write_file',arguments:{path:target,content:'committed-before-crash\n',mode:'create'}}});
