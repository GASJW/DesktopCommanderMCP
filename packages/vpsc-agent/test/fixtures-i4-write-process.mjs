import { createGovernedAgentExecutor } from '../src/governed-executor.mjs';

const [root,state,target,requestId,deviceId,fixture]=process.argv.slice(2);
const executor=createGovernedAgentExecutor({allowedRoot:root,ledgerDirectory:state,entrypoint:fixture});
try{
  await executor.start();
  await executor.handle({version:1,method:'tools/call',deviceId,
    sessionId:'f1a2b3c4-d5e6-4a9f-8abc-1bb9b99c0002',requestId,
    authorization:{approvalEventId:'b7e92caf-f591-44c4-8fb7-6c489ea573f5',
      approvalTrustRevisionBefore:2,approvalTrustRevisionAfter:3,fingerprint:'b'.repeat(64),
      ownerDigest:'a'.repeat(64),trustRevision:3,policyRevision:'i4-race-test-v1'},
    params:{name:'write_file',arguments:{path:target,content:'same durable write\n',mode:'create'}}});
  process.stdout.write(JSON.stringify({status:'success'})+'\n');
}catch(error){
  process.stdout.write(JSON.stringify({status:'rejected',code:error?.code??'ERROR'})+'\n');
}finally{await executor.close();}
