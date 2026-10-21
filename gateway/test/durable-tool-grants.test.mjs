import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { chmodSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { clearStaleDurableToolGrantLocks, createDurableToolGrantStore } from '../devices/durable-tool-grants.mjs';
import { toolArgumentsDigest } from '../devices/tool-grant-capability.mjs';
import { inspectDurableProcessLock } from '../common/durable-process-lock.mjs';

const MODULE_URL=pathToFileURL(fileURLToPath(new URL('../devices/durable-tool-grants.mjs',import.meta.url))).href;
const OWNER='a'.repeat(64);
const OTHER_OWNER='c'.repeat(64);
const DEVICE='b7e92caf-f591-44c4-8fb7-6c489ea573f4';
const OTHER_DEVICE='00000000-0000-4000-8000-000000000099';
const FINGERPRINT='b'.repeat(64);
const OTHER_FINGERPRINT='d'.repeat(64);
const EVENT=()=>randomUUID();

function fixture(t){
  const parent=mkdtempSync(path.join(os.tmpdir(),'vpsc-grant-'));
  const directory=path.join(parent,'policy');
  mkdirSync(directory,{mode:0o700});
  t.after(()=>rmSync(parent,{recursive:true,force:true}));
  return {parent,directory};
}
function grantInput(overrides={}){
  return {ownerDigest:OWNER,deviceId:DEVICE,fingerprint:FINGERPRINT,tool:'read_file',
    scope:{root:'/srv/commander/approved'},
    constraints:{maxBytes:32768,maxLength:100,maxOffset:10000},...overrides};
}
function approvalReceipt(overrides={}){
  return {deviceId:DEVICE,eventId:EVENT(),fingerprint:FINGERPRINT,
    trustRevisionBefore:4,trustRevisionAfter:5,trustRevision:7,...overrides};
}
function authorizeInput(overrides={}){
  return {ownerDigest:OWNER,deviceId:DEVICE,fingerprint:FINGERPRINT,tool:'read_file',
    arguments:{path:'/srv/commander/approved/docs/readme.txt',offset:5,length:50},
    requestId:randomUUID(),approvalReceipt:approvalReceipt(),...overrides};
}
function createStore(directory,now=()=>1_800_000_000_000){
  return createDurableToolGrantStore({directory,now});
}
function signer(claimsSeen){
  return async claims=>{
    claimsSeen?.push(claims);
    return {claims,signature:'test-signature'};
  };
}
function runChild(source,args=[]){
  return spawn(process.execPath,['--input-type=module','-e',source,...args],{
    stdio:['ignore','pipe','pipe'],env:{PATH:process.env.PATH??'',TMPDIR:process.env.TMPDIR??'',
      HOME:process.env.HOME??''},
  });
}
function collect(child){
  return new Promise(resolve=>{
    let stdout='',stderr='';
    child.stdout.setEncoding('utf8').on('data',chunk=>stdout+=chunk);
    child.stderr.setEncoding('utf8').on('data',chunk=>stderr+=chunk);
    child.once('close',(code,signal)=>resolve({code,signal,stdout,stderr}));
  });
}

test('a new versioned store has no implicit grants and denies authorization',async t=>{
  const {directory}=fixture(t),store=createStore(directory);
  assert.equal(store.revision(),0);
  assert.deepEqual(store.list(),[]);
  await assert.rejects(store.authorizeAndPermit(authorizeInput(),{
    signCapability:signer(),
  }),/No active tool grant/);
  assert.equal(store.revision(),0);
  assert.deepEqual(store.list(),[]);
});

test('grant is CAS-versioned, durably represented and survives store restart',t=>{
  const {directory}=fixture(t),store=createStore(directory);
  const eventId=EVENT();
  const granted=store.grant(grantInput(),{expectedRevision:0,eventId});
  assert.equal(granted.revision,1);
  assert.equal(granted.eventId,eventId);
  assert.match(granted.grantId,/^[0-9a-f-]{36}$/i);
  assert.equal(store.revision(),1);
  assert.deepEqual(store.list(),[{...grantInput(),grantId:granted.grantId,revision:1,
    eventId,active:true}]);
  const restarted=createStore(directory);
  assert.equal(restarted.revision(),1);
  assert.deepEqual(restarted.list(),store.list());
  const document=JSON.parse(readFileSync(path.join(directory,'tool-grants-v1.json'),'utf8'));
  assert.equal(document.version,1);
  assert.equal(document.revision,1);
  assert.equal(document.records.length,1);
  assert.equal(document.records[0].event.type,'grant');
  assert.match(document.records[0].hash,/^[a-f0-9]{64}$/);
});

test('stale CAS revisions and reused mutation event IDs are rejected',t=>{
  const {directory}=fixture(t),store=createStore(directory),eventId=EVENT();
  store.grant(grantInput(),{expectedRevision:0,eventId});
  assert.throws(()=>store.grant({...grantInput(),tool:'list_processes',scope:{},
    constraints:{maxJobs:32}},{expectedRevision:0,eventId:EVENT()}),/revision conflict/);
  assert.throws(()=>store.grant({...grantInput(),tool:'list_processes',scope:{},
    constraints:{maxJobs:32}},{expectedRevision:1,eventId}),/event ID/);
  assert.equal(store.revision(),1);
});

test('policy lock persistence failure leaves the durable revision unchanged',t=>{
  const {directory}=fixture(t),store=createStore(directory);
  chmodSync(directory,0o500);
  try{
    assert.throws(()=>store.grant(grantInput(),{expectedRevision:0,eventId:EVENT()}),
      /unsafe|lock|policy/i);
  }finally{chmodSync(directory,0o700);}
  assert.equal(store.revision(),0);
  assert.deepEqual(store.list(),[]);
});

test('grants reject unknown fields, unsafe scopes and unbounded tool constraints',t=>{
  const {directory}=fixture(t),store=createStore(directory);
  const invalid=[
    {...grantInput(),implicit:true},
    {...grantInput(),scope:{root:'/'}},
    {...grantInput(),scope:{root:'/srv/commander/approved',extra:true}},
    {...grantInput(),scope:{root:'/srv/commander/../secret'}},
    {...grantInput(),scope:{root:'C:\\'}},
    {...grantInput(),scope:{root:'\\\\server\\share\\approved'}},
    {...grantInput(),constraints:{maxBytes:65537,maxLength:100,maxOffset:10000}},
    {...grantInput(),constraints:{maxBytes:32768,maxLength:100,maxOffset:10000,extra:1}},
    {...grantInput(),tool:'list_directory',scope:{root:'/srv/commander/approved'},
      constraints:{maxDepth:3,maxEntries:200}},
    {...grantInput(),tool:'write_file',constraints:{maxBytes:65537}},
    {...grantInput(),tool:'run_command',scope:{root:'/srv/commander/approved',profile:'shell'},
      constraints:{maxRuntimeMs:10000,maxOutputBytes:16384,profile:'shell'}},
  ];
  for(const input of invalid){
    assert.throws(()=>store.grant(input,{expectedRevision:0,eventId:EVENT()}));
  }
  assert.equal(store.revision(),0);
});

test('Windows drive grant stays within its canonical root on a Linux Gateway',async t=>{
  const {directory}=fixture(t),store=createStore(directory);
  const root='C:\\Users\\synthetic\\approved';
  const grant=store.grant({...grantInput(),scope:{root}},{expectedRevision:0,eventId:EVENT()});
  const request=authorizeInput({arguments:{path:`${root}\\docs\\readme.txt`,offset:5,length:50}});
  const permit=await store.authorizeAndPermit(request,{signCapability:signer()});
  assert.equal(permit.grantId,grant.grantId);
  assert.equal(permit.authorization.claims.scope.root,root);
  permit.release();
  for(const args of [
    {path:`${root}-outside\\secret.txt`,offset:0,length:10},
    {path:`${root}\\..\\secret.txt`,offset:0,length:10},
    {path:`${root}/docs/readme.txt`,offset:0,length:10},
  ]){
    await assert.rejects(store.authorizeAndPermit(authorizeInput({arguments:args}),{
      signCapability:signer(),
    }));
  }
  assert.equal(store.revision(),1);
  assert.equal(store.inspect().grants[0].scope.root,root);
});

test('Windows grants preserve drive semantics and reject mixed-format or escaping paths',async t=>{
  const {directory}=fixture(t),store=createStore(directory);
  const root='C:\\Users\\synthetic\\approved';
  const created=store.grant({...grantInput(),scope:{root}},
    {expectedRevision:0,eventId:EVENT()});
  const request=authorizeInput({arguments:{path:`${root}\\docs\\readme.txt`,offset:0,length:10}});
  const permit=await store.authorizeAndPermit(request,{signCapability:signer()});
  assert.equal(permit.grantId,created.grantId);
  assert.equal(permit.authorization.claims.scope.root,root);
  permit.release();
  for(const args of [
    {path:`${root}-outside\\secret.txt`,offset:0,length:10},
    {path:`${root}\\..\\secret.txt`,offset:0,length:10},
    {path:`${root}/docs/readme.txt`,offset:0,length:10},
  ]){
    await assert.rejects(store.authorizeAndPermit(authorizeInput({arguments:args}),{
      signCapability:signer(),
    }));
  }
  assert.equal(store.revision(),1);
  assert.equal(store.inspect().grants[0].scope.root,root);
});

test('authorization persists exact scoped claims and holds a permit until release',async t=>{
  const {directory}=fixture(t),store=createStore(directory),seen=[];
  const created=store.grant(grantInput(),{expectedRevision:0,eventId:EVENT()});
  const request=authorizeInput(),permit=await store.authorizeAndPermit(request,{
    signCapability:signer(seen),
  });
  assert.equal(permit.policyRevision,1);
  assert.equal(permit.grantId,created.grantId);
  assert.equal(permit.ownerDigest,OWNER);
  assert.equal(permit.deviceId,DEVICE);
  assert.equal(permit.fingerprint,FINGERPRINT);
  assert.equal(permit.tool,'read_file');
  assert.match(permit.decisionId,/^[0-9a-f-]{36}$/i);
  assert.deepEqual(permit.authorization,{claims:seen[0],signature:'test-signature'});
  assert.equal(permit.capabilityClaims,undefined);
  assert.deepEqual(seen[0],{
    version:1,decisionId:permit.decisionId,requestId:request.requestId,
    ownerDigest:OWNER,deviceId:DEVICE,fingerprint:FINGERPRINT,tool:'read_file',
    argumentsDigest:toolArgumentsDigest('read_file',request.arguments),
    grantId:created.grantId,policyRevision:1,
    scope:{root:'/srv/commander/approved'},
    constraints:{maxBytes:32768,maxLength:100,maxOffset:10000},
    approvalEventId:request.approvalReceipt.eventId,approvalTrustRevisionBefore:4,
    approvalTrustRevisionAfter:5,trustRevision:7,issuedAt:1_800_000_000_000,
    expiresAt:1_800_000_030_000,
  });
  assert.ok(Object.isFrozen(permit));
  assert.ok(Object.isFrozen(seen[0]));
  assert.equal(store.revision(),1,'authorization does not change the policy revision');
  const document=JSON.parse(readFileSync(path.join(directory,'tool-grants-v1.json'),'utf8'));
  assert.equal(document.records.length,2);
  assert.equal(document.records[1].event.type,'authorize');
  assert.deepEqual(document.records[1].event.claims,seen[0]);
  assert.throws(()=>store.revoke(created.grantId,{expectedRevision:1,eventId:EVENT()}),/permit/);
  assert.equal(permit.release(),true);
  assert.equal(permit.release(),false);
  const revoked=store.revoke(created.grantId,{expectedRevision:1,eventId:EVENT()});
  assert.equal(revoked.revision,2);
});

test('authorization fails closed for owner, device, key, approval, scope and parameter mismatches',async t=>{
  const {directory}=fixture(t),store=createStore(directory);
  store.grant(grantInput(),{expectedRevision:0,eventId:EVENT()});
  const invalid=[
    authorizeInput({ownerDigest:OTHER_OWNER}),
    authorizeInput({deviceId:OTHER_DEVICE}),
    authorizeInput({fingerprint:OTHER_FINGERPRINT}),
    authorizeInput({tool:'write_file',arguments:{path:'/srv/commander/approved/a',content:'x',mode:'create'}}),
    authorizeInput({arguments:{path:'/srv/commander/private/readme.txt'}}),
    authorizeInput({arguments:{path:'/srv/commander/approved/../private/readme.txt'}}),
    authorizeInput({arguments:{path:'/srv/commander/approved'}}),
    authorizeInput({arguments:{path:'/srv/commander/approved/readme.txt',length:101}}),
    authorizeInput({approvalReceipt:approvalReceipt({fingerprint:OTHER_FINGERPRINT})}),
    authorizeInput({approvalReceipt:approvalReceipt({trustRevision:4})}),
  ];
  for(const input of invalid){
    await assert.rejects(store.authorizeAndPermit(input,{signCapability:signer()}));
  }
  assert.equal(store.list().length,1);
  assert.equal(JSON.parse(readFileSync(path.join(directory,'tool-grants-v1.json'),'utf8')).records.length,1,
    'denials do not create authorization records or permits');
});

test('result validation runs under the exclusive policy lock and rejects a revoked grant',async t=>{
  const {directory}=fixture(t),store=createStore(directory);
  const created=store.grant(grantInput(),{expectedRevision:0,eventId:EVENT()});
  const permit=await store.authorizeAndPermit(authorizeInput(),{signCapability:signer()});
  permit.release();
  const identity={grantId:created.grantId,ownerDigest:OWNER,deviceId:DEVICE,
    fingerprint:FINGERPRINT,tool:'read_file',policyRevision:permit.policyRevision};
  let callbackCalls=0;
  const accepted=store.withCurrentAuthorization(identity,()=>{callbackCalls++;return 'written';});
  assert.equal(accepted,'written');
  assert.equal(callbackCalls,1);
  store.grant({...grantInput(),ownerDigest:OTHER_OWNER},{expectedRevision:1,eventId:EVENT()});
  assert.equal(store.withCurrentAuthorization(identity,()=>{callbackCalls++;return 'still active';}),
    'still active','unrelated later policy revisions do not invalidate this active grant');
  store.revoke(created.grantId,{expectedRevision:2,eventId:EVENT()});
  assert.throws(()=>store.withCurrentAuthorization(identity,()=>{callbackCalls++;}),/revoked|active grant/i);
  assert.equal(callbackCalls,2,'revoked grants cannot validate a late result');
});

test('result validation rejects an asynchronous callback that could escape its lock',t=>{
  const {directory}=fixture(t),store=createStore(directory);
  const created=store.grant(grantInput(),{expectedRevision:0,eventId:EVENT()});
  const identity={grantId:created.grantId,ownerDigest:OWNER,deviceId:DEVICE,
    fingerprint:FINGERPRINT,tool:'read_file',policyRevision:1};
  assert.throws(()=>store.withCurrentAuthorization(identity,async()=>{}),/synchronous/i);
  assert.equal(store.revision(),1);
});

test('every tool has exact scope and bounded constraints',t=>{
  const {directory}=fixture(t),store=createStore(directory);
  const samples=[
    {tool:'read_file',scope:{root:'/srv/a'},constraints:{maxBytes:1,maxLength:1,maxOffset:0}},
    {tool:'list_directory',scope:{root:'/srv/a'},constraints:{maxDepth:0,maxEntries:1}},
    {tool:'write_file',scope:{root:'/srv/a'},constraints:{maxBytes:1}},
    {tool:'list_processes',scope:{},constraints:{maxJobs:1}},
    {tool:'run_command',scope:{root:'/srv/a',profile:'count_lines'},
      constraints:{maxRuntimeMs:100,maxOutputBytes:1024,profile:'count_lines'}},
  ];
  for(const fields of samples){
    const {grantId}=store.grant({ownerDigest:OWNER,deviceId:DEVICE,fingerprint:FINGERPRINT,
      ...fields},{expectedRevision:store.revision(),eventId:EVENT()});
    assert.match(grantId,/^[0-9a-f-]{36}$/i);
    store.revoke(grantId,{expectedRevision:store.revision(),eventId:EVENT()});
  }
  assert.equal(store.revision(),10);
});

test('valid authorization works for each tool only with a matching scoped grant',async t=>{
  const {directory}=fixture(t),store=createStore(directory);
  const cases=[
    {tool:'read_file',scope:{root:'/srv/a'},constraints:{maxBytes:65_536,maxLength:1000,maxOffset:100_000},
      args:{path:'/srv/a/readme.txt',offset:0,length:100}},
    {tool:'list_directory',scope:{root:'/srv/a'},constraints:{maxDepth:1,maxEntries:20},
      args:{path:'/srv/a/docs',depth:1}},
    {tool:'write_file',scope:{root:'/srv/a'},constraints:{maxBytes:64},
      args:{path:'/srv/a/new.txt',content:'new',mode:'create'}},
    {tool:'list_processes',scope:{},constraints:{maxJobs:10},args:{}},
    {tool:'run_command',scope:{root:'/srv/a',profile:'count_lines'},
      constraints:{maxRuntimeMs:5000,maxOutputBytes:8192,profile:'count_lines'},
      args:{path:'/srv/a/readme.txt',profile:'count_lines'}},
  ];
  for(const item of cases){
    const created=store.grant({ownerDigest:OWNER,deviceId:DEVICE,fingerprint:FINGERPRINT,
      tool:item.tool,scope:item.scope,constraints:item.constraints},
    {expectedRevision:store.revision(),eventId:EVENT()});
    const permit=await store.authorizeAndPermit({ownerDigest:OWNER,deviceId:DEVICE,
      fingerprint:FINGERPRINT,tool:item.tool,arguments:item.args,requestId:randomUUID(),
      approvalReceipt:approvalReceipt()}, {signCapability:signer()});
    assert.equal(permit.grantId,created.grantId);
    assert.equal(permit.authorization.claims.tool,item.tool);
    assert.deepEqual(permit.authorization.claims.scope,item.scope);
    assert.deepEqual(permit.authorization.claims.constraints,item.constraints);
    permit.release();
    store.revoke(created.grantId,{expectedRevision:store.revision(),eventId:EVENT()});
  }
  assert.equal(store.list().filter(grant=>grant.active).length,0);
});

test('corrupt, truncated and interrupted snapshot evidence fails closed',t=>{
  for(const corrupt of ['{"version":1','{"version":1,"revision":99,"records":[],"grants":[]}\n']){
    const {directory}=fixture(t),store=createStore(directory);
    store.grant(grantInput(),{expectedRevision:0,eventId:EVENT()});
    writeFileSync(path.join(directory,'tool-grants-v1.json'),corrupt,{mode:0o600});
    assert.throws(()=>createStore(directory));
  }
  const {directory}=fixture(t),store=createStore(directory);
  writeFileSync(path.join(directory,'.tool-grants-deadbeefdeadbeefdeadbeef.tmp'),'partial',{mode:0o600});
  assert.throws(()=>store.revision(),/temporary|incomplete/i);
});

test('deleting an initialized policy snapshot is not treated as a fresh empty policy',t=>{
  const {directory}=fixture(t),store=createStore(directory);
  store.grant(grantInput(),{expectedRevision:0,eventId:EVENT()});
  unlinkSync(path.join(directory,'tool-grants-v1.json'));
  assert.throws(()=>createStore(directory),/missing|initialized|policy/i);
});

test('abandoned cross-process locks are preserved and block all policy use',async t=>{
  const {directory}=fixture(t);
  const source=`import {createDurableProcessLock} from ${JSON.stringify(pathToFileURL(
    fileURLToPath(new URL('../common/durable-process-lock.mjs',import.meta.url))).href)};\n`+
    `import {openSync,writeSync,fsyncSync,closeSync} from 'node:fs';\n`+
    `const d=process.argv[1];createDurableProcessLock(d,'.tool-grants-operation.lock','tool-grants-operation');\n`+
    `const fd=openSync(d+'/.tool-grants-deadbeefdeadbeefdeadbeef.tmp','wx',0o600);writeSync(fd,'partial');fsyncSync(fd);closeSync(fd);\n`+
    `process.stdout.write('READY');setInterval(()=>{},1000);\n`;
  const child=runChild(source,[directory]);
  const ready=new Promise((resolve,reject)=>{
    child.once('error',reject);child.stdout.once('data',resolve);
  });
  await ready;
  assert.throws(()=>clearStaleDurableToolGrantLocks({directory,
    operatorConfirmedNoActiveWriters:true,operatorConfirmedNoActiveRecovery:true}),
  /active or unverified/i);
  child.kill('SIGKILL');
  const result=await collect(child);
  assert.equal(result.signal,'SIGKILL');
  assert.ok(readdirSync(directory).includes('.tool-grants-operation.lock'));
  assert.ok(readdirSync(directory).some(name=>name.endsWith('.tmp')));
  assert.equal(inspectDurableProcessLock(directory,'.tool-grants-operation.lock').status,'dead');
  assert.throws(()=>createStore(directory),/lock|operation|temporary/i);
  assert.ok(readdirSync(directory).includes('.tool-grants-operation.lock'));
  assert.deepEqual(clearStaleDurableToolGrantLocks({directory,
    operatorConfirmedNoActiveWriters:true,operatorConfirmedNoActiveRecovery:true}),
  {cleared:1,temporaryFileCount:1});
  assert.throws(()=>createStore(directory),/temporary|incomplete/i);
  assert.ok(readdirSync(directory).some(name=>name.endsWith('.tmp')),
    'lock recovery preserves partial snapshot evidence for operator review');
});

test('operator recovery clears only dead writer locks and allows a validated restart',async t=>{
  const {directory}=fixture(t);
  createStore(directory);
  const lockUrl=pathToFileURL(fileURLToPath(new URL('../common/durable-process-lock.mjs',import.meta.url))).href;
  const source=[`import {createDurableProcessLock} from ${JSON.stringify(lockUrl)};\n`,
    `createDurableProcessLock(process.argv[1],'.tool-grants-operation.lock','tool-grants-operation');\n`,
    `process.stdout.write('READY');setInterval(()=>{},1000);\n`].join('');
  const child=runChild(source,[directory]);
  let stderr='';child.stderr.setEncoding('utf8').on('data',chunk=>stderr+=chunk);
  await new Promise((resolve,reject)=>{
    child.once('error',reject);child.stdout.once('data',resolve);
    child.once('exit',(code,signal)=>reject(Error(`lock fixture exited before ready (${code}, ${signal}): ${stderr}`)));
  });
  child.kill('SIGKILL');
  assert.equal((await collect(child)).signal,'SIGKILL');
  assert.throws(()=>createStore(directory),/lock|operation/i);
  assert.throws(()=>clearStaleDurableToolGrantLocks({directory}),/operator confirmation/i);
  assert.deepEqual(clearStaleDurableToolGrantLocks({directory,
    operatorConfirmedNoActiveWriters:true,operatorConfirmedNoActiveRecovery:true}),
  {cleared:1,temporaryFileCount:0});
  assert.equal(createStore(directory).revision(),0);
});

test('operator recovery preserves ownerless locks with unknown process identity',t=>{
  const {directory}=fixture(t);createStore(directory);
  const unknown=path.join(directory,'.tool-grants-operation.lock');
  mkdirSync(unknown,{mode:0o700});
  assert.throws(()=>clearStaleDurableToolGrantLocks({directory,
    operatorConfirmedNoActiveWriters:true,operatorConfirmedNoActiveRecovery:true}),/unverified/i);
  assert.equal(readdirSync(directory).includes('.tool-grants-operation.lock'),true);
  assert.equal(readdirSync(directory).includes('.tool-grants-recovery.lock'),false,
    'the recovery barrier is released without altering unknown evidence');
});

test('SIGKILL before atomic rename preserves the old policy and leaves review evidence',async t=>{
  const {directory}=fixture(t),store=createStore(directory);
  const moduleUrl=MODULE_URL;
  const source=[
    `import fs from 'node:fs';\n`,
    `import {syncBuiltinESMExports} from 'node:module';\n`,
    `import {createDurableToolGrantStore} from ${JSON.stringify(moduleUrl)};\n`,
    `const store=createDurableToolGrantStore({directory:process.argv[1]});\n`,
    `const rename=fs.renameSync;\n`,
    `fs.renameSync=(from,to)=>{if(from.includes('.tool-grants-')&&to.endsWith('tool-grants-v1.json')){fs.writeSync(1,'READY');Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,60000);}return rename(from,to);};\n`,
    `syncBuiltinESMExports();\n`,
    `store.grant(JSON.parse(process.argv[2]),{expectedRevision:0,eventId:process.argv[3]});\n`,
  ].join('');
  const child=runChild(source,[directory,JSON.stringify(grantInput()),EVENT()]);
  let stderr='';child.stderr.setEncoding('utf8').on('data',chunk=>stderr+=chunk);
  await new Promise((resolve,reject)=>{
    child.once('error',reject);child.stdout.once('data',resolve);
    child.once('exit',(code,signal)=>reject(Error(`mutation fixture exited before rename (${code}, ${signal}): ${stderr}`)));
  });
  child.kill('SIGKILL');
  assert.equal((await collect(child)).signal,'SIGKILL');
  assert.equal(JSON.parse(readFileSync(path.join(directory,'tool-grants-v1.json'),'utf8')).revision,0,
    'the old atomic snapshot remains authoritative');
  const diagnosis=clearStaleDurableToolGrantLocks({directory,
    operatorConfirmedNoActiveWriters:true,operatorConfirmedNoActiveRecovery:true});
  assert.deepEqual(diagnosis,{cleared:2,temporaryFileCount:1});
  assert.equal(JSON.parse(readFileSync(path.join(directory,'tool-grants-v1.json'),'utf8')).revision,0);
  assert.throws(()=>createStore(directory),/temporary|incomplete/i);
  assert.deepEqual(readdirSync(directory).filter(name=>name.endsWith('.tmp')).length,1);
});

test('two real processes cannot both mutate from the same expected revision',async t=>{
  const {directory}=fixture(t),store=createStore(directory),ready=path.join(directory,'ready'),start=path.join(directory,'start');
  const source=`import {createDurableToolGrantStore} from ${JSON.stringify(MODULE_URL)};\n`
    +`import {writeFileSync,existsSync} from 'node:fs';\n`
    +`const directory=process.argv[1],ready=process.argv[2],start=process.argv[3];\n`
    +`const store=createDurableToolGrantStore({directory});writeFileSync(ready+process.pid,'1');\n`
    +`const end=Date.now()+5000;while(!existsSync(start)){if(Date.now()>end)process.exit(9);Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,5);}\n`
    +`try{const result=store.grant(JSON.parse(process.argv[4]),{expectedRevision:0,eventId:process.argv[5]});process.stdout.write(JSON.stringify({ok:true,result}));}\n`
    +`catch(error){process.stdout.write(JSON.stringify({ok:false,code:error.code??null,message:error.message}));}\n`;
  const payload=JSON.stringify(grantInput());
  const children=[runChild(source,[directory,ready,start,payload,EVENT()]),
    runChild(source,[directory,ready,start,payload,EVENT()])];
  const waits=Date.now()+10000;
  while(readdirSync(directory).filter(name=>name.startsWith('ready')).length<2&&Date.now()<waits){
    await new Promise(resolve=>setTimeout(resolve,5));
  }
  assert.equal(readdirSync(directory).filter(name=>name.startsWith('ready')).length,2);
  writeFileSync(start,'go');
  const results=await Promise.all(children.map(collect));
  const answers=results.map(result=>JSON.parse(result.stdout));
  assert.equal(answers.filter(answer=>answer.ok).length,1,JSON.stringify(results));
  assert.equal(store.revision(),1);
  assert.equal(store.list().filter(record=>record.active).length,1);
});
