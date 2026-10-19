import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import { chmodSync, mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, symlinkSync, renameSync, linkSync } from 'node:fs';
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { existsSync, statSync } from 'node:fs';
import { analyzeI4ExecutionRecovery } from '../src/governed-executor.mjs';
import { removeDeadDurableProcessLock } from '../../../gateway/common/durable-process-lock.mjs';
import { signToolGrantCapability, toolArgumentsDigest } from '../../../gateway/devices/tool-grant-capability.mjs';
import { removeDeadWindowsFileLock, securePrivateWindowsDirectory,
  verifyPrivateWindowsFile } from '../src/windows-security.mjs';

const FIXTURE=fileURLToPath(new URL('./fixtures-readonly-mcp.mjs',import.meta.url));
const DEVICE='f1a2b3c4-d5e6-4a9f-8abc-1bb9b99c0001';
function replaceWithDecoy(filename,decoy){
  renameSync(filename,filename+'.original');
  if(process.platform==='win32')linkSync(decoy,filename);
  else symlinkSync(decoy,filename);
}
function killFixtureProcessTree(child){
  if(process.platform==='win32'){
    const result=spawnSync('taskkill.exe',['/PID',String(child.pid),'/T','/F'],
      {stdio:'ignore',windowsHide:true,timeout:10_000});
    if(result.error)throw result.error;
  }else process.kill(-child.pid,'SIGKILL');
}
const FINGERPRINT='b'.repeat(64),OWNER='a'.repeat(64);
const APPROVAL_EVENT='b7e92caf-f591-44c4-8fb7-6c489ea573f5';
const POLICY_KEYS=generateKeyPairSync('ed25519');
const roots=new WeakMap();
const configuredExecutor=options=>createGovernedAgentExecutor({...options,
  gatewayPolicyPublicKey:POLICY_KEYS.publicKey,deviceId:DEVICE,fingerprint:FINGERPRINT});
function authorizationFor(root,name,args,requestId){
  const constraints=name==='read_file'?{maxBytes:64*1024,maxLength:1000,maxOffset:100_000}:
    name==='list_directory'?{maxDepth:2,maxEntries:200}:
    name==='write_file'?{maxBytes:64*1024}:
    name==='list_processes'?{maxJobs:32}:{maxOutputBytes:16*1024,maxRuntimeMs:10_000,profile:'count_lines'};
  const scope=name==='list_processes'?{}:name==='run_command'?{root,profile:'count_lines'}:{root};
  const claims={version:1,grantId:randomUUID(),decisionId:randomUUID(),requestId,
    ownerDigest:OWNER,deviceId:DEVICE,fingerprint:FINGERPRINT,tool:name,
    argumentsDigest:toolArgumentsDigest(name,args),policyRevision:1,approvalEventId:APPROVAL_EVENT,
    trustRevision:1,approvalTrustRevisionBefore:0,approvalTrustRevisionAfter:1,scope,constraints,
    issuedAt:Date.now(),expiresAt:Date.now()+30_000};
  return signToolGrantCapability(claims,POLICY_KEYS.privateKey);
}
const imported=await import('../src/governed-executor.mjs').catch(()=>null);
const createGovernedAgentExecutor=imported?.createGovernedAgentExecutor;
const available=typeof createGovernedAgentExecutor==='function';

test('I4 governed executor module is implemented',()=>{
  assert.equal(available,true,'createGovernedAgentExecutor must export the governed executor');
});

async function sandbox(t,fn,{commandTimeoutMs=5000,testHooks}={}){
  if(!available){t.skip('governed executor not implemented');return;}
  const directory=mkdtempSync(path.join(os.tmpdir(),'vpsc-i4-executor-'));
  const root=path.join(directory,'approved'),state=path.join(directory,'state');
  mkdirSync(root,{mode:0o700});mkdirSync(state,{mode:0o700});
  if(process.platform==='win32')securePrivateWindowsDirectory(root);
  const file=path.join(root,'readme.txt');writeFileSync(file,'one\ntwo\nthree\n');
  const executor=configuredExecutor({allowedRoot:root,entrypoint:FIXTURE,
    ledgerDirectory:state,commandTimeoutMs,testHooks,gatewayPolicyPublicKey:POLICY_KEYS.publicKey,
    deviceId:DEVICE,fingerprint:FINGERPRINT});
  roots.set(executor,root);
  try{await executor.start();await fn({directory,root,state,file,executor});}
  finally{await executor.close();rmSync(directory,{recursive:true,force:true});}
}
const call=(executor,name,args,{requestId=randomUUID(),signal}={})=>executor.handle({
  version:1,method:'tools/call',deviceId:DEVICE,sessionId:randomUUID(),requestId,
  authorization:authorizationFor(roots.get(executor),name,args,requestId),params:{name,arguments:args},
},{signal});
const textOf=result=>result?.content?.find(item=>item.type==='text')?.text??'';

test('bounded list_directory iterates only the approved root and stops at the global entry cap',async t=>{
  await sandbox(t,async({root,executor})=>{
    for(let index=0;index<205;index++)writeFileSync(path.join(root,`entry-${index}.txt`),'x');
    const nested=path.join(root,'nested');mkdirSync(nested);writeFileSync(path.join(nested,'child.txt'),'x');
    const result=JSON.parse(textOf(await call(executor,'list_directory',{path:root,depth:1})));
    assert.equal(result.entries.length,200);
    assert.equal(result.truncated,true);
    assert.ok(result.entries.every(entry=>!Object.hasOwn(entry,'absolutePath')));
  });
});

test('write_file is atomic create-only, denies replacement and traversal, and records no file content',async t=>{
  await sandbox(t,async({root,state,executor})=>{
    const target=path.join(root,'created.txt');
    const result=await call(executor,'write_file',{path:target,content:'created safely\n',mode:'create'});
    assert.match(textOf(result),/created/i);
    assert.equal(readFileSync(target,'utf8'),'created safely\n');
    await assert.rejects(call(executor,'write_file',{path:target,content:'replace',mode:'create'}),
      error=>error.code==='ALREADY_EXISTS');
    await assert.rejects(call(executor,'write_file',{path:path.join(root,'..','outside.txt'),
      content:'denied',mode:'create'}),error=>error.code==='DENIED');
    const ledger=readFileSync(path.join(state,'i4-execution.jsonl'),'utf8');
    assert.doesNotMatch(ledger,/created safely|replace|outside\.txt/);
  });
});

test('duplicate request IDs never execute twice and payload reuse is detected',async t=>{
  await sandbox(t,async({root,executor})=>{
    const requestId=randomUUID(),target=path.join(root,'one-shot.txt');
    await call(executor,'write_file',{path:target,content:'once',mode:'create'},{requestId});
    await assert.rejects(call(executor,'write_file',{path:target,content:'once',mode:'create'},
      {requestId}),error=>error.code==='DUPLICATE_EXECUTION');
    await assert.rejects(call(executor,'write_file',{path:target,content:'different',mode:'create'},
      {requestId}),error=>error.code==='REQUEST_ID_REUSE');
    assert.equal(readFileSync(target,'utf8'),'once');
  });
});

test('run_command exposes only fixed count_lines profile and captures bounded output and exit status',async t=>{
  await sandbox(t,async({file,executor})=>{
    const result=JSON.parse(textOf(await call(executor,'run_command',{profile:'count_lines',path:file})));
    assert.equal(result.profile,'count_lines');
    assert.equal(result.exitCode,0);
    assert.match(result.stdout,/3/);
    assert.equal(typeof result.stderr,'string');
    const processes=JSON.parse(textOf(await call(executor,'list_processes',{})));
    assert.ok(processes.jobs.length>=1);
    assert.ok(processes.jobs.every(job=>job.profile==='count_lines'&&Number.isSafeInteger(job.exitCode)));
    await assert.rejects(call(executor,'run_command',{profile:'shell',command:'id',path:file}),
      error=>error.code==='DENIED');
  });
});

test('read_file stays bound to the opened file when its pathname is replaced',async t=>{
  let swapped=false;
  await sandbox(t,async({root,file,executor})=>{
    const decoy=path.join(root,'decoy.txt');writeFileSync(decoy,'decoy\n');
    const result=await call(executor,'read_file',{path:file});
    assert.equal(swapped,true);
    assert.match(textOf(result),/one\ntwo\nthree/);
    assert.doesNotMatch(textOf(result),/decoy/);
  },{testHooks:{afterFileOpen:({tool,path:openedPath})=>{
    if(tool!=='read_file'||swapped)return;
    replaceWithDecoy(openedPath,path.join(path.dirname(openedPath),'decoy.txt'));
    swapped=true;
  }}});
});

test('read_file rejects invalid UTF-8 instead of returning replacement characters',async t=>{
  await sandbox(t,async({root,state,file,executor})=>{
    writeFileSync(file,Buffer.from([0x6f,0x6b,0xff,0x0a]));
    await assert.rejects(call(executor,'read_file',{path:file}),error=>error.code==='INVALID_UTF8');
    const records=readFileSync(path.join(state,'i4-execution.jsonl'),'utf8').trim().split('\n')
      .map(line=>JSON.parse(line));
    assert.equal(records.at(-1).type,'outcome');
    assert.equal(records.at(-1).status,'failed');
    assert.match(records.at(-1).resultHash,/^[a-f0-9]{64}$/);
  });
});

test('run_command reads the opened file when its pathname is replaced before spawn',async t=>{
  let swapped=false;
  await sandbox(t,async({root,file,executor})=>{
    const decoy=path.join(root,'decoy-count.txt');writeFileSync(decoy,'decoy\n');
    const result=JSON.parse(textOf(await call(executor,'run_command',{
      profile:'count_lines',path:file,
    })));
    assert.equal(swapped,true);
    assert.match(result.stdout,/^\s*3\b/);
  },{testHooks:{afterFileOpen:({tool,path:openedPath})=>{
    if(tool!=='run_command'||swapped)return;
    replaceWithDecoy(openedPath,path.join(path.dirname(openedPath),'decoy-count.txt'));
    swapped=true;
  }}});
});

test('nonzero command exit is durably recorded as failed, with its exit code',{
  skip:process.platform!=='win32'&&(typeof process.getuid!=='function'||process.getuid()===0),
},async t=>{
  await sandbox(t,async({file,state,executor})=>{
    const result=JSON.parse(textOf(await call(executor,'run_command',{
      profile:'count_lines',path:file,
    })));
    assert.equal(result.exitCode,1);
    const records=readFileSync(path.join(state,'i4-execution.jsonl'),'utf8').trim().split('\n')
      .map(line=>JSON.parse(line));
    assert.equal(records.at(-1).type,'outcome');
    assert.equal(records.at(-1).status,'failed');
    assert.equal(records.at(-1).exitCode,1);
    assert.match(records.at(-1).resultHash,/^[a-f0-9]{64}$/);
  },{testHooks:{failCommandForTest:true}});
});

test('pre-cancelled operations fail before a filesystem side effect',async t=>{
  await sandbox(t,async({root,executor})=>{
    const controller=new AbortController();controller.abort();
    const target=path.join(root,'cancelled.txt');
    await assert.rejects(call(executor,'write_file',{path:target,content:'x',mode:'create'},
      {signal:controller.signal}),error=>error.code==='CANCELLED');
    assert.equal(await import('node:fs').then(fs=>fs.existsSync(target)),false);
  });
});

test('cancelling a running fixed command records ambiguity and blocks later operations',async t=>{
  let spawnedResolve;
  const spawned=new Promise(resolve=>{spawnedResolve=resolve;});
  let openedResolve;
  const opened=new Promise(resolve=>{openedResolve=resolve;});
  await sandbox(t,async({root,state,executor})=>{
    const large=path.join(root,'count-me.txt');writeFileSync(large,'x'.repeat(1024*1024));
    const controller=new AbortController(),requestId=randomUUID();
    const pending=call(executor,'run_command',{profile:'count_lines',path:large},
      {requestId,signal:controller.signal});
    await (process.platform==='win32'?opened:spawned);
    controller.abort();
    await assert.rejects(pending,error=>error.code==='AMBIGUOUS_CANCELLED');
    const diagnosis=executor.diagnostics();
    assert.equal(diagnosis.status,'ambiguous-outcome');
    assert.equal(diagnosis.ambiguous[0].requestId,requestId);
    await assert.rejects(call(executor,'list_processes',{}),error=>error.code==='RECOVERY_REQUIRED');
    assert.doesNotMatch(readFileSync(path.join(state,'i4-execution.jsonl'),'utf8'),/x{32}/);
  },{testHooks:process.platform==='win32'
    ?{sleepCommandForTimeout:true,afterFileOpen:()=>openedResolve()}
    :{onCommandSpawn:pid=>{process.kill(-pid,'SIGSTOP');spawnedResolve();}}});
});

test('fixed command timeout kills a real test-only process group and records ambiguity',{
  skip:process.platform!=='linux'||!available,
},async t=>{
  let childPid=null;
  await sandbox(t,async({root,executor})=>{
    const large=path.join(root,'timeout-file.txt');writeFileSync(large,'x'.repeat(1024*1024));
    const pending=call(executor,'run_command',{profile:'count_lines',path:large});
    await assert.rejects(pending,error=>error.code==='AMBIGUOUS_TIMEOUT');
    assert.equal(executor.diagnostics().status,'ambiguous-outcome');
    assert.ok(childPid);
    assert.throws(()=>process.kill(childPid,0),error=>error.code==='ESRCH');
  },{commandTimeoutMs:100,testHooks:{sleepCommandForTimeout:true,
    onCommandSpawn:pid=>{childPid=pid;}}});
});

test('truncated execution ledger blocks startup without repairing or truncating evidence',{
  skip:!available,
},async()=>{
  const directory=mkdtempSync(path.join(os.tmpdir(),'vpsc-i4-truncated-'));
  const root=path.join(directory,'approved'),state=path.join(directory,'state');
  mkdirSync(root,{mode:0o700});mkdirSync(state,{mode:0o700});
  if(process.platform==='win32')securePrivateWindowsDirectory(root);
  const ledger=path.join(state,'i4-execution.jsonl');writeFileSync(ledger,'{"version":1',{mode:0o600});
  const executor=configuredExecutor({allowedRoot:root,entrypoint:FIXTURE,ledgerDirectory:state});
  try{
    await assert.rejects(executor.start(),error=>error.code==='LEDGER_CORRUPT');
    assert.equal(readFileSync(ledger,'utf8'),'{"version":1');
  }finally{await executor.close();rmSync(directory,{recursive:true,force:true});}
});

test('create-only write rejects symlink destinations without following them',{
  skip:process.platform==='win32',
},async t=>{
  await sandbox(t,async({root,directory,executor})=>{
    const outside=path.join(directory,'outside.txt');writeFileSync(outside,'private');
    const link=path.join(root,'link.txt');symlinkSync(outside,link);
    await assert.rejects(call(executor,'write_file',{path:link,content:'overwrite',mode:'create'}),
      error=>error.code==='ALREADY_EXISTS'||error.code==='DENIED');
    const outsideDirectory=path.join(directory,'outside-directory');mkdirSync(outsideDirectory,{mode:0o700});
    symlinkSync(outsideDirectory,path.join(root,'linked-directory'),'dir');
    await assert.rejects(call(executor,'write_file',{path:path.join(root,'linked-directory','escape.txt'),
      content:'must stay out',mode:'create'}),error=>error.code==='DENIED');
    assert.equal(readFileSync(outside,'utf8'),'private');
    assert.equal(existsSync(path.join(outsideDirectory,'escape.txt')),false);
  });
});

test('write operations stay anchored to the approved directory inode after its pathname is replaced',{
  skip:!available||process.platform!=='linux',
},async t=>{
  await sandbox(t,async({root,directory,executor})=>{
    const moved=path.join(directory,'approved-original'),outside=path.join(directory,'outside');
    mkdirSync(outside,{mode:0o700});
    const sentinel=path.join(outside,'sentinel.txt');writeFileSync(sentinel,'unchanged');
    const target=path.join(root,'anchored.txt');
    const fs=await import('node:fs');
    fs.renameSync(root,moved);symlinkSync(outside,root,'dir');
    await call(executor,'write_file',{path:target,content:'anchored',mode:'create'});
    assert.equal(readFileSync(path.join(moved,'anchored.txt'),'utf8'),'anchored');
    assert.equal(existsSync(path.join(outside,'anchored.txt')),false);
    assert.equal(readFileSync(sentinel,'utf8'),'unchanged');
  });
});

test('state directory paths with symlink ancestors fail closed',{
  skip:!available||process.platform!=='linux',
},async()=>{
  const directory=mkdtempSync(path.join(os.tmpdir(),'vpsc-i4-state-path-'));
  const real=path.join(directory,'real'),state=path.join(real,'state'),alias=path.join(directory,'alias');
  const root=path.join(directory,'approved');
  mkdirSync(real,{mode:0o700});mkdirSync(state,{mode:0o700});mkdirSync(root,{mode:0o700});
  symlinkSync(real,alias,'dir');
  try{
    assert.throws(()=>configuredExecutor({allowedRoot:root,entrypoint:FIXTURE,
      ledgerDirectory:path.join(alias,'state')}),error=>error.code==='POLICY');
  }finally{rmSync(directory,{recursive:true,force:true});}
});

test('group or world writable operation roots fail closed',{
  skip:!available||process.platform!=='linux'||typeof process.getuid!=='function'||process.getuid()===0,
},async()=>{
  const directory=mkdtempSync(path.join(os.tmpdir(),'vpsc-i4-writable-root-'));
  const root=path.join(directory,'approved'),state=path.join(directory,'state');
  mkdirSync(root,{mode:0o700});mkdirSync(state,{mode:0o700});
  if(process.platform==='win32')securePrivateWindowsDirectory(root);chmodSync(root,0o770);
  assert.throws(()=>configuredExecutor({allowedRoot:root,entrypoint:FIXTURE,
    ledgerDirectory:state}),error=>error.code==='POLICY');
  rmSync(directory,{recursive:true,force:true});
});

test('SIGKILL in the real executor after durable write and intent leaves ambiguity; restart never replays',{
  skip:!available,
},async()=>{
  const directory=mkdtempSync(path.join(os.tmpdir(),'vpsc-i4-crash-'));
  const root=path.join(directory,'approved'),state=path.join(directory,'state');
  mkdirSync(root,{mode:0o700});mkdirSync(state,{mode:0o700});
  if(process.platform==='win32')securePrivateWindowsDirectory(root);
  const target=path.join(root,'committed.txt'),requestId=randomUUID();
  const fixturePath=fileURLToPath(new URL('./fixtures-i4-crash-after-write.mjs',import.meta.url));
  const child=spawn(process.execPath,[fixturePath,root,state,target,requestId,DEVICE,FIXTURE],
    {stdio:['ignore','pipe','pipe'],detached:true,
      env:{...process.env,NODE_TEST_CONTEXT:process.env.NODE_TEST_CONTEXT??'child-v8'}});
  let output='',stderr='';
  child.stderr.on('data',chunk=>stderr+=chunk.toString());
  const ready=new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>reject(Error(`real executor did not reach post-effect crash point: ${output} ${stderr}`)),
      process.platform==='win32'?60_000:5000);
    child.stdout.on('data',chunk=>{
      output+=chunk.toString();
      if(output.includes('AFTER_EFFECT_DURABLE')){clearTimeout(timer);resolve();}
    });
    child.once('error',error=>{clearTimeout(timer);reject(error);});
    child.once('exit',(code,signal)=>{
      if(!output.includes('AFTER_EFFECT_DURABLE')){
        clearTimeout(timer);reject(Error(`crash fixture exited before fault point (${code}, ${signal}): ${stderr}`));
      }
    });
  });
  try{
    await ready;
    assert.equal(readFileSync(target,'utf8'),'committed-before-crash\n');
    const intentOnly=readFileSync(path.join(state,'i4-execution.jsonl'),'utf8').trim().split('\n')
      .map(line=>JSON.parse(line));
    assert.equal(intentOnly.length,1);
    assert.equal(intentOnly[0].version,2);
    assert.equal(intentOnly[0].type,'intent');
    assert.equal(intentOnly[0].requestId,requestId);
    const childExit=new Promise(resolve=>child.once('exit',resolve));
    killFixtureProcessTree(child);
    await childExit;
    assert.equal(existsSync(target),true);
    if(process.platform==='win32')verifyPrivateWindowsFile(path.join(state,'i4-execution.jsonl'));
    else assert.equal((statSync(target).mode&0o777),0o600);
    let diagnosis=analyzeI4ExecutionRecovery({ledgerDirectory:state});
    assert.equal(diagnosis.status,'stale-lock');
    assert.equal(diagnosis.lock.status,'dead');
    assert.equal(diagnosis.automaticLockRemoval,false);
    assert.equal(diagnosis.unresolved.length,1);
    assert.equal(process.platform==='win32'
      ?removeDeadWindowsFileLock({directory:state,name:'i4-execution-lock',expectedDigest:diagnosis.lock.digest})
      :removeDeadDurableProcessLock({directory:state,name:'i4-execution-lock',expectedDigest:diagnosis.lock.digest}),true);
    diagnosis=analyzeI4ExecutionRecovery({ledgerDirectory:state});
    assert.equal(diagnosis.status,'ambiguous-intent');
    const executor=configuredExecutor({allowedRoot:root,entrypoint:FIXTURE,ledgerDirectory:state});
    await assert.rejects(executor.start(),error=>error.code==='RECOVERY_REQUIRED');
    assert.equal(readFileSync(target,'utf8'),'committed-before-crash\n');
    const ledger=readFileSync(path.join(state,'i4-execution.jsonl'),'utf8');
    assert.equal(ledger.trim().split('\n').length,1);
    assert.doesNotMatch(ledger,/type":"outcome/);
  }finally{
    if(child.exitCode===null&&child.signalCode===null){
      const childExit=new Promise(resolve=>child.once('exit',resolve));
      killFixtureProcessTree(child);await childExit;
    }
    rmSync(directory,{recursive:true,force:true});
  }
});

test('SIGKILL after cooperative cancellation but before outcome leaves an ambiguous non-replayable intent',{
  skip:!available||process.platform!=='linux',
},async()=>{
  const directory=mkdtempSync(path.join(os.tmpdir(),'vpsc-i4-cancel-crash-'));
  const root=path.join(directory,'approved'),state=path.join(directory,'state');
  mkdirSync(root,{mode:0o700});mkdirSync(state,{mode:0o700});
  if(process.platform==='win32')securePrivateWindowsDirectory(root);
  const target=path.join(root,'effect.txt'),requestId=randomUUID();
  const fixturePath=fileURLToPath(new URL('./fixtures-i4-cancel-crash.mjs',import.meta.url));
  const child=spawn(process.execPath,[fixturePath,root,state,target,requestId,DEVICE,FIXTURE],
    {stdio:['ignore','pipe','pipe'],detached:true,
      env:{...process.env,NODE_TEST_CONTEXT:process.env.NODE_TEST_CONTEXT??'child-v8'}});
  let output='',stderr='';
  child.stdout.on('data',chunk=>output+=chunk.toString());
  child.stderr.on('data',chunk=>stderr+=chunk.toString());
  const waitForMarker=marker=>new Promise((resolve,reject)=>{
    if(output.includes(marker))return resolve();
    const timer=setTimeout(()=>reject(Error(`cancellation crash fixture missed ${marker}: ${output} ${stderr}`)),5000);
    const onData=()=>{if(output.includes(marker)){clearTimeout(timer);child.stdout.off('data',onData);resolve();}};
    child.stdout.on('data',onData);
    child.once('error',error=>{clearTimeout(timer);reject(error);});
    child.once('exit',(code,signal)=>{
      if(!output.includes(marker)){clearTimeout(timer);reject(Error(`fixture exited before ${marker} (${code}, ${signal}): ${stderr}`));}
    });
  });
  const childExit=new Promise(resolve=>child.once('exit',resolve));
  try{
    await waitForMarker('EFFECT_DURABLE');
    assert.equal(readFileSync(target,'utf8'),'effect-before-cancel-crash\n');
    const cancelSignal=new Promise((resolve,reject)=>{
      try{process.kill(child.pid,'SIGUSR1');resolve();}catch(error){reject(error);}
    });
    await cancelSignal;
    await waitForMarker('CANCELLATION_OBSERVED');
    process.kill(-child.pid,'SIGKILL');
    await childExit;
    const intentOnly=readFileSync(path.join(state,'i4-execution.jsonl'),'utf8').trim().split('\n')
      .map(line=>JSON.parse(line));
    assert.equal(intentOnly.length,1);
    assert.equal(intentOnly[0].type,'intent');
    assert.equal(intentOnly[0].requestId,requestId);
    assert.equal(readFileSync(target,'utf8'),'effect-before-cancel-crash\n');
    let diagnosis=analyzeI4ExecutionRecovery({ledgerDirectory:state});
    assert.equal(diagnosis.status,'stale-lock');
    assert.equal(diagnosis.lock.status,'dead');
    assert.equal(diagnosis.unresolved.length,1);
    assert.equal(removeDeadDurableProcessLock({directory:state,name:'i4-execution-lock',
      expectedDigest:diagnosis.lock.digest}),true);
    diagnosis=analyzeI4ExecutionRecovery({ledgerDirectory:state});
    assert.equal(diagnosis.status,'ambiguous-intent');
    const executor=configuredExecutor({allowedRoot:root,entrypoint:FIXTURE,ledgerDirectory:state});
    await assert.rejects(executor.start(),error=>error.code==='RECOVERY_REQUIRED');
    assert.equal(readFileSync(target,'utf8'),'effect-before-cancel-crash\n');
    assert.equal(readFileSync(path.join(state,'i4-execution.jsonl'),'utf8').trim().split('\n').length,1);
    await executor.close();
  }finally{
    if(child.exitCode===null&&child.signalCode===null){
      try{process.kill(-child.pid,'SIGKILL');}catch{}
      await childExit;
    }
    rmSync(directory,{recursive:true,force:true});
  }
});

test('two agent processes racing one stable request commit at most one filesystem mutation',{
  skip:!available,
},async()=>{
  const directory=mkdtempSync(path.join(os.tmpdir(),'vpsc-i4-race-'));
  const root=path.join(directory,'approved'),state=path.join(directory,'state');
  mkdirSync(root,{mode:0o700});mkdirSync(state,{mode:0o700});
  if(process.platform==='win32')securePrivateWindowsDirectory(root);
  const target=path.join(root,'raced.txt'),requestId=randomUUID();
  const fixturePath=fileURLToPath(new URL('./fixtures-readonly-mcp.mjs',import.meta.url));
  const childPath=fileURLToPath(new URL('./fixtures-i4-write-process.mjs',import.meta.url));
  const run=()=>new Promise((resolve,reject)=>{
    const child=spawn(process.execPath,[childPath,root,state,target,requestId,DEVICE,fixturePath],
      {stdio:['ignore','pipe','pipe']});
    let stdout='',stderr='';
    child.stdout.on('data',chunk=>stdout+=chunk.toString());
    child.stderr.on('data',chunk=>stderr+=chunk.toString());
    child.once('error',reject);
    child.once('exit',code=>{
      if(code!==0)return reject(Error(`child exit ${code}: ${stderr}`));
      try{resolve(JSON.parse(stdout.trim()));}catch{reject(Error(`bad child result: ${stdout} ${stderr}`));}
    });
  });
  try{
    const outcomes=await Promise.all([run(),run()]);
    assert.equal(outcomes.filter(item=>item.status==='success').length,1,JSON.stringify(outcomes));
    assert.equal(outcomes.filter(item=>item.status==='rejected').length,1);
    assert.ok(['BUSY','RECOVERY_REQUIRED','DUPLICATE_EXECUTION'].includes(
      outcomes.find(item=>item.status==='rejected').code));
    assert.equal(readFileSync(target,'utf8'),'same durable write\n');
    assert.equal(readFileSync(path.join(state,'i4-execution.jsonl'),'utf8').trim().split('\n').length,2);
    assert.equal(analyzeI4ExecutionRecovery({ledgerDirectory:state}).status,'consistent');
  }finally{rmSync(directory,{recursive:true,force:true});}
});
