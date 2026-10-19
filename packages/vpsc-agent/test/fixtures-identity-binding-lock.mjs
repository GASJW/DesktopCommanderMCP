import { createDurableProcessLock } from '../../../gateway/common/durable-process-lock.mjs';
import { createWindowsFileLock } from '../src/windows-security.mjs';

const directory=process.env.VPSC_TEST_IDENTITY_DIR;
if(typeof directory!=='string')throw new Error('Missing isolated identity test directory');
if(process.platform==='win32')createWindowsFileLock(directory,'identity-binding.lock','device-identity-binding');
else createDurableProcessLock(directory,'identity-binding.lock','device-identity-binding');
process.stdout.write(JSON.stringify({ready:true})+'\n');
setInterval(()=>{},1000);
