import { existsSync, readlinkSync, writeSync } from 'node:fs';
import fs from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { createDurableProcessLock, inspectDurableProcessLock,
  removeOwnedDurableProcessLock } from '../common/durable-process-lock.mjs';
import { createDurableDeviceTrustStore } from '../devices/durable-trust.mjs';

const [mode,directory,resumeFile,publicKeyPem]=process.argv.slice(2);
const WRITER='.trusted-devices-writer.lock';
const line=value=>writeSync(1,Buffer.from(JSON.stringify(value)+'\n'));

if(mode==='hold-writer-lock'){
  const owner=createDurableProcessLock(directory,WRITER,'trust-writer');
  line({phase:'writer-lock-active',pid:process.pid});
  let input='';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data',chunk=>{
    input+=chunk;
    if(!input.includes('\n'))return;
    if(input.trim()!=='release')process.exitCode=2;
    else{
      removeOwnedDurableProcessLock({directory,name:WRITER,owner});
      line({phase:'writer-lock-released'});
    }
    process.stdin.destroy();
  });
}else if(mode==='commit-trust-change'){
  const store=createDurableDeviceTrustStore({directory});
  const original=fs.fsyncSync;
  let paused=false;
  fs.fsyncSync=fd=>{
    let target='';
    try{target=readlinkSync(`/proc/self/fd/${fd}`);}catch{}
    const lock=target===directory?inspectDurableProcessLock(directory,WRITER):null;
    if(!paused&&target===directory&&lock?.present&&lock.status==='active'){
      paused=true;
      line({phase:'writer-lock-active',pid:process.pid,target,
        lockPresent:lock.present,lockStatus:lock.status});
      const wait=new Int32Array(new SharedArrayBuffer(4));
      while(!existsSync(resumeFile))Atomics.wait(wait,0,0,20);
    }
    return original(fd);
  };
  syncBuiltinESMExports();
  try{
    store.trustDevice({name:'Cross-process writer',platform:'linux',publicKeyPem});
    line({phase:'commit-complete',revision:store.revision()});
  }finally{
    fs.fsyncSync=original;
    syncBuiltinESMExports();
    store.close();
  }
}else{
  throw new TypeError('Unknown trust writer contention fixture mode');
}
