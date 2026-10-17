import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createPublicKey, generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createDurableDeviceTrustStore } from '../devices/durable-trust.mjs';
import { inspectDurableProcessLock } from '../common/durable-process-lock.mjs';

const CHILD=new URL('./fixtures-trust-writer-contention.mjs',import.meta.url);
function fixture(t){
  const root=mkdtempSync(path.join(tmpdir(),'g7-trust-writer-contention-'));
  const directory=path.join(root,'store');
  t.after(()=>rmSync(root,{recursive:true,force:true}));
  return {root,directory};
}
function start(mode,f,{resumeFile='',publicKeyPem=''}={}){
  return spawn(process.execPath,[CHILD.pathname,mode,f.directory,resumeFile,publicKeyPem],
    {stdio:['pipe','pipe','pipe']});
}
async function waitForPhase(child,phase){
  let output='',stderr='';
  return new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>reject(Error(`timed out waiting for ${phase}; stderr=${stderr}`)),10000);
    child.stdout.setEncoding('utf8');child.stderr.setEncoding('utf8');
    child.stderr.on('data',chunk=>{stderr+=chunk;});
    child.stdout.on('data',chunk=>{
      output+=chunk;
      for(;;){
        const newline=output.indexOf('\n');
        if(newline<0)return;
        const line=output.slice(0,newline);output=output.slice(newline+1);
        let message;
        try{message=JSON.parse(line);}catch(error){clearTimeout(timer);reject(error);return;}
        if(message.phase===phase){clearTimeout(timer);resolve(message);return;}
      }
    });
    child.once('error',error=>{clearTimeout(timer);reject(error);});
    child.once('exit',(code,signal)=>{
      clearTimeout(timer);
      reject(Error(`child exited before ${phase}: ${code}/${signal}; stderr=${stderr}`));
    });
  });
}
async function stop(child){
  if(child.exitCode!==null||child.signalCode!==null)return;
  const exited=once(child,'exit');child.kill('SIGKILL');await exited;
}
function waitForExit(child){
  if(child.exitCode!==null||child.signalCode!==null){
    return Promise.resolve([child.exitCode,child.signalCode]);
  }
  return once(child,'exit');
}

test('active verified writer contention is transient when revision stays unchanged',async t=>{
  const f=fixture(t),store=createDurableDeviceTrustStore({directory:f.directory});
  const child=start('hold-writer-lock',f);
  try{
    const phase=await waitForPhase(child,'writer-lock-active');
    const lock=inspectDurableProcessLock(f.directory,'.trusted-devices-writer.lock');
    assert.equal(lock.status,'active',JSON.stringify({phase,lock}));
    assert.throws(()=>store.registry.listDevices(),error=>error?.code==='TRUST_BUSY');
    child.stdin.write('release\n');
    await waitForPhase(child,'writer-lock-released');
    const [code,signal]=await waitForExit(child);
    assert.equal(code,0);assert.equal(signal,null);
    assert.deepEqual(store.registry.listDevices(),[]);
    assert.equal(store.revision(),0);
  }finally{
    await stop(child);
    store.close();
  }
});

test('active writer is retryable, but a committed revision change fences the stale facade',async t=>{
  const f=fixture(t),store=createDurableDeviceTrustStore({directory:f.directory});
  const {publicKey}=generateKeyPairSync('ed25519');
  const publicKeyPem=publicKey.export({type:'spki',format:'pem'});
  const resumeFile=path.join(f.root,'resume-writer');
  const child=start('commit-trust-change',f,{resumeFile,publicKeyPem});
  try{
    const phase=await waitForPhase(child,'writer-lock-active');
    const lock=inspectDurableProcessLock(f.directory,'.trusted-devices-writer.lock');
    assert.equal(lock.status,'active',JSON.stringify({phase,lock}));
    assert.throws(()=>store.registry.listDevices(),error=>error?.code==='TRUST_BUSY');
    writeFileSync(resumeFile,'continue\n',{mode:0o600});
    await waitForPhase(child,'commit-complete');
    const [code,signal]=await waitForExit(child);
    assert.equal(code,0);assert.equal(signal,null);
    assert.throws(()=>store.registry.listDevices(),
      /Trust store changed by another process; restart required/);
    assert.throws(()=>store.registry.listDevices(),/Trust store unavailable/);
    const reopened=createDurableDeviceTrustStore({directory:f.directory});
    assert.equal(reopened.registry.listDevices().length,1);
    assert.equal(reopened.revision(),1);
    reopened.close();
  }finally{
    await stop(child);
    store.close();
  }
});
