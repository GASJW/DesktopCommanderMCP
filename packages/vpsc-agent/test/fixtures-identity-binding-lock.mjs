import { createDurableProcessLock } from '../../../gateway/common/durable-process-lock.mjs';

const directory=process.env.VPSC_TEST_IDENTITY_DIR;
if(typeof directory!=='string')throw new Error('Missing isolated identity test directory');
createDurableProcessLock(directory,'identity-binding.lock','device-identity-binding');
process.stdout.write(JSON.stringify({ready:true})+'\n');
setInterval(()=>{},1000);
