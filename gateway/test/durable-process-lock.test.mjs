import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { mkdtempSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createDurableProcessLock, inspectDurableProcessLock,
  removeDeadDurableProcessLock } from '../common/durable-process-lock.mjs';

test('process lock refuses a live owner and becomes removable after SIGKILL',async t=>{
  const root=mkdtempSync(path.join(tmpdir(),'g7-process-lock-'));
  t.after(()=>rmSync(root,{recursive:true,force:true}));
  const directory=path.join(root,'records');
  mkdirSync(directory,{mode:0o700});
  const helperUrl=new URL('../common/durable-process-lock.mjs',import.meta.url).href;
  const source=`
    import {createDurableProcessLock} from ${JSON.stringify(helperUrl)};
    createDurableProcessLock(process.argv[1],'.lock','test-writer');
    process.stdout.write('ready\\n');
    setInterval(()=>{},1000);
  `;
  const child=spawn(process.execPath,['--input-type=module','-e',source,directory],
    {stdio:['ignore','pipe','pipe']});
  t.after(()=>{if(child.exitCode===null)child.kill('SIGKILL');});
  let ready='';
  child.stdout.setEncoding('utf8');
  child.stdout.on('data',chunk=>{ready+=chunk;});
  let timeout;
  try{
    await Promise.race([
      new Promise((resolve,reject)=>{
        const check=()=>ready.includes('ready\n')?resolve():setTimeout(check,5);
        check();
        child.once('error',reject);
      }),
      new Promise((_,reject)=>{timeout=setTimeout(()=>reject(Error('lock owner child did not start')),3000);}),
    ]);
  }finally{clearTimeout(timeout);}
  const active=inspectDurableProcessLock(directory,'.lock');
  assert.equal(active.status,'active');
  assert.throws(()=>removeDeadDurableProcessLock({directory,name:'.lock',
    expectedDigest:active.digest}),/active|alive/i);

  child.kill('SIGKILL');
  await once(child,'exit');
  const stale=inspectDurableProcessLock(directory,'.lock');
  assert.equal(stale.status,'dead');
  assert.equal(removeDeadDurableProcessLock({directory,name:'.lock',
    expectedDigest:stale.digest}),true);
  assert.equal(inspectDurableProcessLock(directory,'.lock').present,false);
});

test('legacy empty locks are unknown and cannot be cleared by an operator boolean',t=>{
  const root=mkdtempSync(path.join(tmpdir(),'g7-legacy-lock-'));
  t.after(()=>rmSync(root,{recursive:true,force:true}));
  const directory=path.join(root,'records');
  mkdirSync(directory,{mode:0o700});
  mkdirSync(path.join(directory,'.lock'),{mode:0o700});
  const lock=inspectDurableProcessLock(directory,'.lock');
  assert.equal(lock.status,'unknown');
  assert.throws(()=>removeDeadDurableProcessLock({directory,name:'.lock',
    expectedDigest:lock.digest}),/unknown|identity/i);
  assert.equal(inspectDurableProcessLock(directory,'.lock').present,true);
});

test('new process locks carry versioned owner identity and can be removed by their owner',t=>{
  const root=mkdtempSync(path.join(tmpdir(),'g7-owned-lock-'));
  t.after(()=>rmSync(root,{recursive:true,force:true}));
  const directory=path.join(root,'records');
  mkdirSync(directory,{mode:0o700});
  const owner=createDurableProcessLock(directory,'.lock','test-writer');
  const lock=inspectDurableProcessLock(directory,'.lock');
  assert.equal(lock.status,'active');
  assert.equal(lock.owner.version,1);
  assert.equal(lock.owner.kind,'test-writer');
  assert.equal(lock.owner.pid,process.pid);
  assert.equal(lock.owner.token,owner.token);
});

test('concurrent stale clearers cannot erase a replacement live owner',async t=>{
  const root=mkdtempSync(path.join(tmpdir(),'g7-lock-reclaim-race-'));
  t.after(()=>rmSync(root,{recursive:true,force:true}));
  const directory=path.join(root,'records');
  mkdirSync(directory,{mode:0o700});
  const helperUrl=new URL('../common/durable-process-lock.mjs',import.meta.url).href;
  const staleSource=`
    import {createDurableProcessLock} from ${JSON.stringify(helperUrl)};
    createDurableProcessLock(process.argv[1],'.lock','test-writer');
  `;
  const clearSource=`
    import {removeDeadDurableProcessLock} from ${JSON.stringify(helperUrl)};
    process.stdout.write('ready\\n');
    process.stdin.once('data',()=>{
      try{removeDeadDurableProcessLock({directory:process.argv[1],name:'.lock',
        expectedDigest:process.argv[2]});process.exit(0);}
      catch(error){process.stderr.write(String(error.message));process.exit(0);}
    });
  `;
  const createSource=`
    import {createDurableProcessLock} from ${JSON.stringify(helperUrl)};
    process.stdout.write('ready\\n');
    process.stdin.once('data',()=>{
      try{createDurableProcessLock(process.argv[1],'.lock','test-writer');
        process.stdout.write('created\\n');setInterval(()=>{},1000);}
      catch(error){process.stdout.write('refused\\n');process.exit(74);}
    });
  `;
  async function waitReady(child,marker){
    let output='';child.stdout.setEncoding('utf8');
    return new Promise((resolve,reject)=>{
      const timeout=setTimeout(()=>{child.kill('SIGKILL');reject(Error('lock race child did not start'));},5000);
      child.stdout.on('data',chunk=>{output+=chunk;if(output.includes(marker)){
        clearTimeout(timeout);resolve(output);
      }});
      child.once('error',error=>{clearTimeout(timeout);reject(error);});
      child.once('exit',(code,signal)=>{if(!output.includes(marker)){
        clearTimeout(timeout);reject(Error(`lock race child exited early: ${code}/${signal}`));
      }});
    });
  }
  for(let attempt=0;attempt<8;attempt++){
    const stale=spawnSync(process.execPath,['--input-type=module','-e',staleSource,directory],
      {encoding:'utf8',timeout:10000});
    assert.equal(stale.status,0,stale.stderr);
    const digest=inspectDurableProcessLock(directory,'.lock').digest;
    const clearers=[0,1].map(()=>spawn(process.execPath,
      ['--input-type=module','-e',clearSource,directory,digest],
      {stdio:['pipe','pipe','pipe']}));
    const creator=spawn(process.execPath,['--input-type=module','-e',createSource,directory],
      {stdio:['pipe','pipe','pipe']});
    await Promise.all([...clearers,creator].map(child=>waitReady(child,'ready\n')));
    const creatorOutcome=new Promise(resolve=>{
      let output='';
      creator.stdout.on('data',chunk=>{
        output+=chunk;
        if(output.includes('created\n'))resolve(true);
        if(output.includes('refused\n'))resolve(false);
      });
      creator.once('close',()=>resolve(false));
    });
    for(const child of [...clearers,creator])child.stdin.write('go\n');
    const clearerResults=await Promise.all(clearers.map(child=>new Promise(resolve=>
      child.once('close',(code,signal)=>resolve({code,signal})))));
    const createdOrRefused=await creatorOutcome;
    assert.ok(clearerResults.every(result=>result.code===0),JSON.stringify(clearerResults));
    if(createdOrRefused){
      const live=inspectDurableProcessLock(directory,'.lock');
      assert.equal(live.status,'active','a successful creator must retain its lock');
      creator.kill('SIGKILL');
      await once(creator,'close');
      const dead=inspectDurableProcessLock(directory,'.lock');
      assert.equal(dead.status,'dead');
      assert.equal(removeDeadDurableProcessLock({directory,name:'.lock',
        expectedDigest:dead.digest}),true);
    }else{
      assert.equal(inspectDurableProcessLock(directory,'.lock').present,false);
    }
  }
});
