import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { existsSync,mkdtempSync,mkdirSync,readFileSync,rmSync,writeFileSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createDurableMachineBindingStore } from '../devices/durable-machine-bindings.mjs';

const OWNER={issuer:'https://owner-test.cloudflareaccess.com',subject:'synthetic-owner-subject'};
const OWNER_ID='a'.repeat(24);
const DEVICE='f1a2b3c4-d5e6-4a9f-8abc-1bb9b99c0001';
const EVENT='a1a2b3c4-d5e6-4a9f-8abc-1bb9b99c0001';
const BIND_EVENT='b1a2b3c4-d5e6-4a9f-8abc-1bb9b99c0001';
const FP='a'.repeat(64);
const OWNER_DIGEST=createHash('sha256').update('VPSC-I4-OWNER-v1\n')
  .update(JSON.stringify([OWNER.issuer,OWNER.subject])).digest('hex');
const RECEIPT={ownerId:OWNER_ID,deviceId:DEVICE,eventId:EVENT,fingerprint:FP,
  trustRevisionBefore:4,trustRevisionAfter:5,trustRevision:5};
const WRITER_FIXTURE=fileURLToPath(new URL('./fixtures-machine-binding-writer.mjs',import.meta.url));
const LOCK_FIXTURE=fileURLToPath(new URL('./fixtures-machine-binding-lock.mjs',import.meta.url));
function fixture(fn){
  const base=mkdtempSync(path.join(os.tmpdir(),'g7-machine-bindings-'));
  const directory=path.join(base,'bindings');mkdirSync(directory,{mode:0o700});
  const cleanup=()=>rmSync(base,{recursive:true,force:true});
  try{const result=fn(directory,base);
    return result&&typeof result.then==='function'?result.finally(cleanup):(cleanup(),result);
  }catch(error){cleanup();throw error;}
}
function input(overrides={}){
  const approvalReceipt=overrides.approvalReceipt??RECEIPT;
  return {bindingEventId:overrides.bindingEventId??BIND_EVENT,ownerId:overrides.ownerId??OWNER_ID,
    ownerDigest:overrides.ownerDigest??OWNER_DIGEST,clientId:overrides.clientId??'g7-device-test.access',
    deviceId:overrides.deviceId??approvalReceipt.deviceId,
    fingerprint:overrides.fingerprint??approvalReceipt.fingerprint,approvalReceipt};
}
function decisionFor(value,{expectedRevision=0,state='PENDING'}={}){
  const intent={event:'g7_owner_machine_binding',version:3,eventId:value.bindingEventId,
    operation:'bind',ownerId:value.ownerId,ownerDigest:value.ownerDigest,clientId:value.clientId,
    deviceId:value.deviceId,fingerprint:value.fingerprint,approvalEventId:value.approvalReceipt.eventId,
    trustRevisionBefore:value.approvalReceipt.trustRevisionBefore,
    trustRevisionAfter:value.approvalReceipt.trustRevisionAfter,
    trustRevision:value.approvalReceipt.trustRevision,bindingRevisionBefore:expectedRevision,
    phase:'intent'};
  return {state,eventId:value.bindingEventId,intent,
    outcome:state==='COMPLETE'?{...intent,phase:'outcome',outcome:'accepted',
      bindingRevisionAfter:expectedRevision+1}:null};
}
function makeStore(directory,{receipts=[RECEIPT],decisions=new Map()}={}){
  return createDurableMachineBindingStore({directory,
    verifyApprovalReceipt:record=>receipts.find(receipt=>receipt.ownerId===record.ownerId&&
      receipt.deviceId===record.deviceId&&receipt.eventId===record.approvalEventId&&
      receipt.fingerprint===record.fingerprint)??null,
    readBindingDecision:record=>decisions.get(record.bindingEventId)??
      {state:'NOT_FOUND',eventId:record.bindingEventId},
    readBindingHistory:()=>({completed:[...decisions.values()].filter(value=>value.state==='COMPLETE'),
      pending:[...decisions.values()].filter(value=>value.state==='PENDING')}),
  });
}
function childJson(file,env){
  return new Promise((resolve,reject)=>{
    const child=spawn(process.execPath,[file],{cwd:process.cwd(),env:{...process.env,...env},
      stdio:['ignore','pipe','pipe']});
    let output='',error='';child.stdout.setEncoding('utf8');child.stderr.setEncoding('utf8');
    child.stdout.on('data',chunk=>output+=chunk);child.stderr.on('data',chunk=>error+=chunk);
    child.once('error',reject);child.once('close',code=>{
      let value;try{value=JSON.parse(output.trim());}catch{return reject(Error(error||output||'Child emitted no JSON'));}
      resolve({code,value,error});
    });
  });
}
test('machine binding store requires both the I2 approval verifier and Owner audit reader',()=>{
  fixture(directory=>{
    assert.throws(()=>createDurableMachineBindingStore({directory,
      verifyApprovalReceipt:()=>RECEIPT}),/Owner binding audit reader/);
  });
});
test('machine binding is durable, Owner/device/key/revision bound, and secrets are absent',()=>{
  fixture(directory=>{
    const decisions=new Map();
    let store=makeStore(directory,{decisions});
    decisions.set(BIND_EVENT,decisionFor(input()));
    const bound=store.bind(input(),{expectedRevision:0});
    assert.equal(bound.revision,1);
    decisions.set(BIND_EVENT,decisionFor(input(),{expectedRevision:0,state:'COMPLETE'}));
    store.close();
    store=makeStore(directory,{decisions});
    assert.deepEqual(store.resolve('g7-device-test.access'),{
      bindingRevision:1,bindingEventId:BIND_EVENT,clientId:'g7-device-test.access',
      deviceId:DEVICE,fingerprint:FP,ownerId:OWNER_ID,ownerDigest:OWNER_DIGEST,
      approvalEventId:EVENT,trustRevisionBefore:4,trustRevisionAfter:5,trustRevision:5,
    });
    assert.equal(store.resolve('unknown-device.access'),null);
    const bytes=readFileSync(path.join(directory,'machine-bindings-v2.json'),'utf8');
    assert.doesNotMatch(bytes,/private|secret|synthetic-owner-subject/);
    store.close();
  });
});
test('binding intent must exactly match Owner, Client-ID, device, fingerprint, I2 receipt and revision',()=>{
  fixture(directory=>{
    const base=input(),decisions=new Map();
    const store=makeStore(directory,{decisions});
    decisions.set(BIND_EVENT,decisionFor({...base,clientId:'other-client.access'}));
    assert.throws(()=>store.bind(base,{expectedRevision:0}),/Owner binding intent/);
    assert.equal(JSON.parse(readFileSync(path.join(directory,'machine-bindings-v2.json'),'utf8')).revision,0);
    store.close();
  });
});
test('duplicate client or device binding, stale revision and unverified approval fail closed',()=>{
  fixture(directory=>{
    const staleDevice='d1a2b3c4-d5e6-4a9f-8abc-1bb9b99c0001';
    const staleReceipt={ownerId:OWNER_ID,deviceId:staleDevice,
      eventId:'d1a2b3c4-d5e6-4a9f-8abc-1bb9b99c0002',fingerprint:'d'.repeat(64),
      trustRevisionBefore:5,trustRevisionAfter:6,trustRevision:6};
    const first=input(),decisions=new Map();
    const store=makeStore(directory,{receipts:[RECEIPT,staleReceipt],decisions});
    decisions.set(BIND_EVENT,decisionFor(first));
    store.bind(first,{expectedRevision:0});
    decisions.set(BIND_EVENT,decisionFor(first,{expectedRevision:0,state:'COMPLETE'}));
    const duplicate=input({bindingEventId:randomUUID(),clientId:'g7-other-test.access'});
    decisions.set(duplicate.bindingEventId,decisionFor(duplicate,{expectedRevision:1}));
    assert.throws(()=>store.bind(duplicate,{expectedRevision:1}),/already bound/);
    const conflict=input({bindingEventId:randomUUID(),deviceId:'b1a2b3c4-d5e6-4a9f-8abc-1bb9b99c0001',
      clientId:'g7-device-test.access'});
    decisions.set(conflict.bindingEventId,decisionFor(conflict,{expectedRevision:1}));
    assert.throws(()=>store.bind(conflict,{expectedRevision:1}),/already bound|[Aa]pproval/);
    const invalid=input({bindingEventId:randomUUID(),deviceId:'c1a2b3c4-d5e6-4a9f-8abc-1bb9b99c0001',
      fingerprint:'c'.repeat(64),approvalReceipt:{...RECEIPT,
        deviceId:'c1a2b3c4-d5e6-4a9f-8abc-1bb9b99c0001',fingerprint:'c'.repeat(64)}});
    decisions.set(invalid.bindingEventId,decisionFor(invalid,{expectedRevision:1}));
    assert.throws(()=>store.bind(invalid,{expectedRevision:1}),/Approval/);
    assert.throws(()=>store.bind(first,{expectedRevision:0}),/revision|audit/i);
    store.close();
  });
});
test('corrupt or legacy binding snapshot is rejected, never treated as empty policy',()=>{
  fixture(directory=>{
    let store=makeStore(directory);store.close();
    writeFileSync(path.join(directory,'machine-bindings-v2.json'),'{}\n');
    assert.throws(()=>makeStore(directory),/corrupt|schema/i);
    rmSync(path.join(directory,'machine-bindings-v2.json'));
    writeFileSync(path.join(directory,'machine-bindings-v1.json'),'{}\n');
    assert.throws(()=>makeStore(directory),/legacy.*migration/i);
  });
});
test('missing binding snapshot is not initialized empty when WAL has completed or pending decisions',()=>{
  fixture(directory=>{
    makeStore(directory).close();
    rmSync(path.join(directory,'machine-bindings-v2.json'));
    const record=input();
    const completed=new Map([[BIND_EVENT,decisionFor(record,{state:'COMPLETE'})]]);
    assert.throws(()=>makeStore(directory,{decisions:completed}),error=>
      error.code==='BINDING_HISTORY_MISSING');
    const pending=new Map([[BIND_EVENT,decisionFor(record)]]);
    assert.throws(()=>makeStore(directory,{decisions:pending}),error=>
      error.code==='BINDING_OUTCOME_UNKNOWN');
    assert.equal(existsSync(path.join(directory,'machine-bindings-v2.json')),false);
  });
});
test('binding snapshot and complete Owner audit history must match one-to-one on restart',()=>{
  fixture(directory=>{
    const record=input(),decisions=new Map();
    const store=makeStore(directory,{decisions});
    decisions.set(BIND_EVENT,decisionFor(record));
    store.bind(record,{expectedRevision:0});
    decisions.set(BIND_EVENT,decisionFor(record,{state:'COMPLETE'}));
    store.close();
    const contradictory={...decisionFor(record,{state:'COMPLETE'}),
      intent:{...decisionFor(record,{state:'COMPLETE'}).intent,ownerDigest:'c'.repeat(64)}};
    decisions.set(BIND_EVENT,contradictory);
    assert.throws(()=>makeStore(directory,{decisions}),error=>error.code==='BINDING_CORRUPT');
  });
});
test('two real writers cannot bind one revision concurrently',async()=>{
  await fixture(async directory=>{
    makeStore(directory).close();
    const make=(suffix,deviceSuffix,fingerprint)=>{
      const deviceId=`f1a2b3c4-d5e6-4a9f-8abc-1bb9b99c000${deviceSuffix}`;
      const approvalReceipt={ownerId:OWNER_ID,deviceId,eventId:`a1a2b3c4-d5e6-4a9f-8abc-1bb9b99c000${deviceSuffix}`,
        fingerprint,trustRevisionBefore:0,trustRevisionAfter:1,trustRevision:1};
      const record=input({bindingEventId:`b1a2b3c4-d5e6-4a9f-8abc-1bb9b99c000${deviceSuffix}`,
        clientId:`writer-${suffix}.access`,deviceId,fingerprint,approvalReceipt});
      const decision=decisionFor(record);
      return {record,env:{VPSC_TEST_BINDING_INPUT:JSON.stringify({directory,record,decision})}};
    };
    const left=make('one','2','b'.repeat(64)),right=make('two','3','c'.repeat(64));
    const [a,b]=await Promise.all([childJson(WRITER_FIXTURE,left.env),childJson(WRITER_FIXTURE,right.env)]);
    assert.equal([a,b].filter(item=>item.value.ok).length,1);
    assert.equal([a,b].filter(item=>!item.value.ok&&
      ['REVISION_CONFLICT','BINDING_BUSY'].includes(item.value.code)).length,1);
    const winner=a.value.ok?left.record:right.record;
    const decisions=new Map([[winner.bindingEventId,decisionFor(winner,{expectedRevision:0,state:'COMPLETE'})]]);
    const reopened=makeStore(directory,{receipts:[left.record.approvalReceipt,right.record.approvalReceipt],decisions});
    assert.equal(reopened.revision(),1);
    assert.ok(reopened.resolve(winner.clientId));
    assert.equal(reopened.resolve((winner===left.record?right.record:left.record).clientId),null);
    reopened.close();
  });
});
test('SIGKILL leaves a durable writer lock that blocks binding resolution',async()=>{
  await fixture(async directory=>{
    const store=makeStore(directory);
    const child=spawn(process.execPath,[LOCK_FIXTURE],{cwd:process.cwd(),
      env:{...process.env,VPSC_TEST_BINDING_DIR:directory},stdio:['ignore','pipe','ignore']});
    const lines=createInterface({input:child.stdout,crlfDelay:Infinity});
    await new Promise((resolve,reject)=>{
      const timer=setTimeout(()=>reject(Error('writer lock fixture did not start')),5000);
      lines.once('line',line=>{clearTimeout(timer);try{
        assert.equal(JSON.parse(line).ready,true);resolve();
      }catch(error){reject(error);}});
      child.once('error',reject);
    });
    child.kill('SIGKILL');
    await new Promise(resolve=>child.once('close',resolve));
    assert.throws(()=>store.resolve('g7-device-test.access'),error=>error.code==='BINDING_BUSY');
    lines.close();store.close();
  });
});
