import { createDurableProcessLock } from '../common/durable-process-lock.mjs';
createDurableProcessLock(process.env.VPSC_TEST_BINDING_DIR,
  '.machine-bindings-writer.lock','machine-bindings-writer');
process.stdout.write(JSON.stringify({ready:true})+'\n');
setInterval(()=>{},60_000);
