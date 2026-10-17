import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { constants, closeSync, fstatSync, fsyncSync, lstatSync, mkdirSync,
  openSync, readFileSync, readdirSync, renameSync, unlinkSync, writeSync } from 'node:fs';
import { createDurableProcessLock, inspectDurableProcessLock,
  removeOwnedDurableProcessLock } from '../common/durable-process-lock.mjs';

// A machine Client-ID binding is routing policy, not a second key registry.
// Every resolution is intersected with the I2 approval receipt and the caller
// must also intersect it with the current trusted-device snapshot.
const FILE='machine-bindings-v2.json';
const LEGACY_FILE='machine-bindings-v1.json';
const GATE='.machine-bindings-writer.lock';
const TEMP_PREFIX='.machine-bindings-';
const DOMAIN='VPSC-G7-MACHINE-BINDINGS-v2\n';
const MAX_BYTES=512*1024;
const MAX_BINDINGS=256;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CLIENT=/^[A-Za-z0-9_.-]{8,256}$/;
const HEX64=/^[a-f0-9]{64}$/;
const OWNER_ID=/^[a-f0-9]{24}$/;
const fail=(code,message)=>Object.assign(new Error(message),{code});
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&
  Object.getPrototypeOf(value)===Object.prototype&&
  Object.keys(value).sort().join(',')===[...keys].sort().join(',');
const digest=value=>createHash('sha256').update(value).digest('hex');
const recordKeys=['approvalEventId','bindingEventId','bindingRevision','clientId','deviceId',
  'fingerprint','ownerDigest','ownerId','trustRevision','trustRevisionAfter','trustRevisionBefore'];

function validateDirectory(directory,{create=false}={}){
  if(process.platform!=='linux'||typeof process.getuid!=='function'){
    throw fail('UNSUPPORTED','Durable machine bindings require Linux process identity evidence');
  }
  if(typeof directory!=='string'||!path.isAbsolute(directory)||path.normalize(directory)!==directory||
     directory===path.parse(directory).root)throw new TypeError('Machine binding directory must be normalized and absolute');
  let cursor=path.parse(directory).root;
  for(const component of directory.slice(cursor.length).split(path.sep)){
    cursor=path.join(cursor,component);
    let stat;
    try{stat=lstatSync(cursor);}catch(error){
      if(error?.code!=='ENOENT'||!create||cursor!==directory)throw error;
      mkdirSync(cursor,{mode:0o700});stat=lstatSync(cursor);
    }
    if(!stat.isDirectory()||stat.isSymbolicLink())throw fail('UNSAFE_STORAGE','Unsafe machine binding directory');
    if(cursor!==directory&&(stat.mode&0o022)!==0&&!(stat.uid===0&&(stat.mode&0o1000)!==0)){
      throw fail('UNSAFE_STORAGE','Writable machine binding ancestor is unsafe');
    }
  }
  const final=lstatSync(directory);
  if(final.uid!==process.getuid()||(final.mode&0o7777)!==0o700){
    throw fail('UNSAFE_STORAGE','Machine binding directory must be owned by this user and mode 0700');
  }
  return directory;
}
function syncDirectory(directory){
  const fd=openSync(directory,constants.O_RDONLY|(constants.O_DIRECTORY??0)|(constants.O_NOFOLLOW??0));
  try{fsyncSync(fd);}finally{closeSync(fd);}
}
function validateReceipt(receipt,ownerId,deviceId,fingerprint){
  if(!exact(receipt,['deviceId','eventId','fingerprint','ownerId','trustRevisionBefore',
      'trustRevisionAfter','trustRevision'])||receipt.deviceId!==deviceId||
     receipt.ownerId!==ownerId||receipt.fingerprint!==fingerprint||!UUID.test(receipt.eventId??'')||
     !Number.isSafeInteger(receipt.trustRevisionBefore)||receipt.trustRevisionBefore<0||
     !Number.isSafeInteger(receipt.trustRevisionAfter)||
     receipt.trustRevisionAfter!==receipt.trustRevisionBefore+1||
     !Number.isSafeInteger(receipt.trustRevision)||receipt.trustRevision<receipt.trustRevisionAfter){
    throw fail('APPROVAL_UNAVAILABLE','Durable Owner approval receipt does not bind this device');
  }
  return receipt;
}
function validateRecord(record,index){
  return exact(record,recordKeys)&&record.bindingRevision===index+1&&
    CLIENT.test(record.clientId??'')&&UUID.test(record.deviceId??'')&&
    HEX64.test(record.fingerprint??'')&&HEX64.test(record.ownerDigest??'')&&
    OWNER_ID.test(record.ownerId??'')&&UUID.test(record.approvalEventId??'')&&
    UUID.test(record.bindingEventId??'')&&
    Number.isSafeInteger(record.trustRevisionBefore)&&record.trustRevisionBefore>=0&&
    Number.isSafeInteger(record.trustRevisionAfter)&&
    record.trustRevisionAfter===record.trustRevisionBefore+1&&
    Number.isSafeInteger(record.trustRevision)&&record.trustRevision>=record.trustRevisionAfter;
}
function snapshotBody(bindings){return {version:2,revision:bindings.length,bindings};}
function snapshotDigest(body){return digest(DOMAIN+JSON.stringify(body));}
function validateSnapshot(value){
  if(!exact(value,['bindings','digest','revision','version'])||value.version!==2||
     !Number.isSafeInteger(value.revision)||value.revision<0||
     !Array.isArray(value.bindings)||value.bindings.length>MAX_BINDINGS||
     value.revision!==value.bindings.length||!HEX64.test(value.digest??'')){
    throw fail('BINDING_CORRUPT','Machine binding snapshot schema is invalid');
  }
  const clients=new Set(),devices=new Set(),events=new Set(),bindingEvents=new Set();
  for(let i=0;i<value.bindings.length;i++){
    const record=value.bindings[i];
    if(!validateRecord(record,i)||clients.has(record.clientId)||devices.has(record.deviceId)||
       events.has(record.approvalEventId)||bindingEvents.has(record.bindingEventId)){
      throw fail('BINDING_CORRUPT','Machine binding history is invalid or duplicated');
    }
    clients.add(record.clientId);devices.add(record.deviceId);events.add(record.approvalEventId);
    bindingEvents.add(record.bindingEventId);
  }
  if(snapshotDigest(snapshotBody(value.bindings))!==value.digest){
    throw fail('BINDING_CORRUPT','Machine binding snapshot digest mismatch');
  }
  return value;
}
function readSnapshot(directory){
  for(const name of readdirSync(directory)){
    if(name!==GATE&&name.startsWith(TEMP_PREFIX)){
      throw fail('BINDING_CORRUPT','Interrupted machine binding snapshot requires operator review');
    }
  }
  const filename=path.join(directory,FILE);
  let named;
  try{named=lstatSync(filename);}catch(error){
    if(error?.code==='ENOENT')return null;
    throw error;
  }
  if(!named.isFile()||named.isSymbolicLink()||named.nlink!==1||
     named.uid!==process.getuid()||(named.mode&0o7777)!==0o600||named.size<=0||named.size>MAX_BYTES){
    throw fail('BINDING_CORRUPT','Machine binding snapshot metadata is unsafe');
  }
  const fd=openSync(filename,constants.O_RDONLY|(constants.O_NOFOLLOW??0));
  try{
    const opened=fstatSync(fd);
    if(!opened.isFile()||opened.nlink!==1||opened.uid!==process.getuid()||
       opened.ino!==named.ino||opened.dev!==named.dev||opened.size!==named.size||
       (opened.mode&0o7777)!==0o600)throw fail('BINDING_CORRUPT','Machine binding snapshot changed during read');
    const bytes=readFileSync(fd);
    let value;
    try{value=JSON.parse(bytes.toString('utf8'));}
    catch{throw fail('BINDING_CORRUPT','Machine binding snapshot is not valid JSON');}
    if(Buffer.from(JSON.stringify(value)+'\n').compare(bytes)!==0){
      throw fail('BINDING_CORRUPT','Machine binding snapshot is not canonical');
    }
    return validateSnapshot(value);
  }finally{closeSync(fd);}
}
function persistSnapshot(directory,bindings){
  const body=snapshotBody(bindings),value={...body,digest:snapshotDigest(body)};
  const bytes=Buffer.from(JSON.stringify(value)+'\n');
  if(bytes.length>MAX_BYTES)throw fail('BINDING_FULL','Machine binding store is full');
  const temp=path.join(directory,TEMP_PREFIX+randomUUID()+'.tmp');
  let fd;
  try{
    fd=openSync(temp,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|
      (constants.O_NOFOLLOW??0),0o600);
    let offset=0;
    while(offset<bytes.length){
      const count=writeSync(fd,bytes,offset,bytes.length-offset);
      if(count<=0)throw fail('BINDING_WRITE_FAILED','Short machine binding snapshot write');
      offset+=count;
    }
    fsyncSync(fd);closeSync(fd);fd=undefined;
    renameSync(temp,path.join(directory,FILE));syncDirectory(directory);
    return value;
  }catch(error){
    if(fd!==undefined)closeSync(fd);
    try{unlinkSync(temp);}catch{}
    if(error?.code==='BINDING_FULL')throw error;
    throw fail('BINDING_WRITE_FAILED','Machine binding snapshot could not be committed');
  }
}
function matchesReceipt(record,receipt){
  return !!receipt&&receipt.ownerId===record.ownerId&&receipt.eventId===record.approvalEventId&&
    receipt.deviceId===record.deviceId&&receipt.fingerprint===record.fingerprint&&
    receipt.trustRevisionBefore===record.trustRevisionBefore&&
    receipt.trustRevisionAfter===record.trustRevisionAfter&&
    Number.isSafeInteger(receipt.trustRevision)&&receipt.trustRevision>=record.trustRevisionAfter;
}

function matchesDecision(record,decision,complete){
  const intent=decision?.intent,outcome=decision?.outcome;
  const same=decision?.state===(complete?'COMPLETE':'PENDING')&&
    intent?.event==='g7_owner_machine_binding'&&intent.version===3&&intent.phase==='intent'&&
    intent.eventId===record.bindingEventId&&intent.operation==='bind'&&
    intent.ownerId===record.ownerId&&intent.ownerDigest===record.ownerDigest&&
    intent.clientId===record.clientId&&intent.deviceId===record.deviceId&&
    intent.fingerprint===record.fingerprint&&intent.approvalEventId===record.approvalEventId&&
    intent.trustRevisionBefore===record.trustRevisionBefore&&
    intent.trustRevisionAfter===record.trustRevisionAfter&&intent.trustRevision===record.trustRevision&&
    intent.bindingRevisionBefore===record.bindingRevision-1;
  if(!same)return false;
  if(!complete)return true;
  return outcome?.event==='g7_owner_machine_binding'&&outcome.version===3&&
    outcome.phase==='outcome'&&outcome.outcome==='accepted'&&outcome.eventId===record.bindingEventId&&
    outcome.bindingRevisionAfter===record.bindingRevision&&
    outcome.ownerId===record.ownerId&&outcome.ownerDigest===record.ownerDigest&&
    outcome.clientId===record.clientId&&outcome.deviceId===record.deviceId&&
    outcome.fingerprint===record.fingerprint&&outcome.approvalEventId===record.approvalEventId&&
    outcome.trustRevisionBefore===record.trustRevisionBefore&&
    outcome.trustRevisionAfter===record.trustRevisionAfter&&outcome.trustRevision===record.trustRevision;
}

export function createDurableMachineBindingStore({directory,verifyApprovalReceipt,
  readBindingDecision,readBindingHistory}={}){
  validateDirectory(directory,{create:true});
  if(typeof verifyApprovalReceipt!=='function'||typeof readBindingDecision!=='function'||
     typeof readBindingHistory!=='function'){
    throw new TypeError('Durable I2 approval verifier and Owner binding audit readers required');
  }
  let closed=false,blocked=false;
  const assertUsable=()=>{
    if(closed||blocked)throw fail('BINDING_UNAVAILABLE','Machine binding store is unavailable');
  };
  const acquire=()=>{
    assertUsable();
    try{return createDurableProcessLock(directory,GATE,'machine-bindings-writer');}
    catch{blocked=true;throw fail('BINDING_BUSY','Machine binding writer lock is active or uncertain');}
  };
  const release=owner=>removeOwnedDurableProcessLock({directory,name:GATE,owner});
  function bindingHistory(){
    let history;
    try{history=readBindingHistory();}
    catch{throw fail('BINDING_AUDIT_UNAVAILABLE','Complete Owner binding audit history is unavailable');}
    if(!exact(history,['completed','pending'])||!Array.isArray(history.completed)||
       !Array.isArray(history.pending)||history.completed.length>MAX_BINDINGS||
       history.pending.length>1){
      throw fail('BINDING_AUDIT_CORRUPT','Owner binding audit history schema is invalid');
    }
    const ids=new Set();
    for(const [list,state] of [[history.completed,'COMPLETE'],[history.pending,'PENDING']]){
      for(const decision of list){
        if(!exact(decision,['eventId','intent','outcome','state'])||decision.state!==state||
           !UUID.test(decision.eventId??'')||decision.intent?.eventId!==decision.eventId||
           ids.has(decision.eventId)||state==='COMPLETE'&&!decision.outcome||
           state==='PENDING'&&decision.outcome!==null){
          throw fail('BINDING_AUDIT_CORRUPT','Owner binding audit history contains invalid decisions');
        }
        ids.add(decision.eventId);
      }
    }
    return history;
  }
  function assertHistoryMatchesSnapshot(snapshot,{allowPendingDecision=null}={}){
    const history=bindingHistory();
    if(history.pending.length){
      const pending=history.pending[0];
      if(!allowPendingDecision||!matchesDecision(allowPendingDecision,pending,false)){
        throw fail('BINDING_OUTCOME_UNKNOWN','An unresolved Owner binding intent requires reconciliation');
      }
    }
    if(history.completed.length!==snapshot.bindings.length){
      throw fail('BINDING_CORRUPT','Machine binding snapshot and Owner audit history have different revisions');
    }
    const decisions=new Map(history.completed.map(value=>[value.eventId,value]));
    for(const record of snapshot.bindings){
      const decision=decisions.get(record.bindingEventId);
      if(!decision||!matchesDecision(record,decision,true)){
        throw fail('BINDING_CORRUPT','Machine binding snapshot contradicts complete Owner audit history');
      }
      decisions.delete(record.bindingEventId);
    }
    if(decisions.size)throw fail('BINDING_CORRUPT','Owner audit contains an unrepresented machine binding');
    return history;
  }
  try{lstatSync(path.join(directory,LEGACY_FILE));
    throw fail('BINDING_LEGACY_UNBOUND','Legacy machine bindings require explicit audited migration');
  }catch(error){if(error?.code!=='ENOENT')throw error;}
  let initial=readSnapshot(directory);
  if(initial){
    if(inspectDurableProcessLock(directory,GATE).present){
      blocked=true;throw fail('BINDING_BUSY','Machine binding writer lock is active or uncertain');
    }
    assertHistoryMatchesSnapshot(initial);
  }else{
    const initialOwner=acquire();
    try{
      initial=readSnapshot(directory);
      if(!initial){
        const history=bindingHistory();
        if(history.pending.length)throw fail('BINDING_OUTCOME_UNKNOWN',
          'An unresolved Owner binding intent requires reconciliation');
        if(history.completed.length)throw fail('BINDING_HISTORY_MISSING',
          'Machine binding snapshot is missing despite accepted Owner audit history');
        initial=persistSnapshot(directory,[]);
      }else{
        assertHistoryMatchesSnapshot(initial);
      }
    }catch(error){
      if(error?.code==='BINDING_WRITE_FAILED')blocked=true;
      throw error;
    }
    finally{if(!blocked)release(initialOwner);}
  }

  function checkedSnapshot(){
    assertUsable();
    try{
      const lock=readSnapshot(directory);
      if(!lock)throw fail('BINDING_CORRUPT','Machine binding snapshot disappeared');
      assertHistoryMatchesSnapshot(lock);
      // Check the writer lock before and after reading so a concurrent mutation
      // cannot be mistaken for a stable authorization lookup.
      const gate=path.join(directory,GATE);
      try{lstatSync(gate);throw fail('BINDING_BUSY','Machine binding mutation is in progress');}
      catch(error){if(error?.code!=='ENOENT')throw error;}
      const latest=readSnapshot(directory);
      if(!latest||latest.digest!==lock.digest||latest.revision!==lock.revision){
        throw fail('BINDING_CHANGED','Machine bindings changed during authorization');
      }
      return latest;
    }catch(error){
      if(['BINDING_BUSY','BINDING_CHANGED','BINDING_CORRUPT'].includes(error?.code))throw error;
      blocked=true;throw fail('BINDING_UNAVAILABLE','Machine binding evidence is unavailable');
    }
  }
  function resolve(clientId){
    if(typeof clientId!=='string'||!CLIENT.test(clientId))return null;
    const snapshot=checkedSnapshot();
    const binding=snapshot.bindings.find(record=>record.clientId===clientId);
    if(!binding)return null;
    let receipt;
    try{receipt=verifyApprovalReceipt(Object.freeze({...binding}));}
    catch{throw fail('APPROVAL_UNAVAILABLE','Durable I2 approval evidence is unavailable');}
    if(!receipt)return null;
    if(!matchesReceipt(binding,receipt)){
      throw fail('BINDING_CORRUPT','Persisted binding contradicts the current I2 approval receipt');
    }
    let decision;
    try{decision=readBindingDecision(Object.freeze({...binding}));}
    catch{throw fail('BINDING_AUDIT_UNAVAILABLE','Owner binding audit evidence is unavailable');}
    if(!matchesDecision(binding,decision,true)){
      throw fail(decision?.state==='PENDING'?'BINDING_OUTCOME_UNKNOWN':'BINDING_CORRUPT',
        'Persisted binding lacks its exact accepted Owner audit outcome');
    }
    return Object.freeze({...binding});
  }
  function bind(input,options={}){
    if(!exact(input,['bindingEventId','ownerId','ownerDigest','clientId','deviceId',
       'fingerprint','approvalReceipt'])||!UUID.test(input.bindingEventId??'')||
       !OWNER_ID.test(input.ownerId??'')||!HEX64.test(input.ownerDigest??'')||
       typeof input.clientId!=='string'||!CLIENT.test(input.clientId)||
       !UUID.test(input.deviceId??'')||!HEX64.test(input.fingerprint??'')){
      throw fail('INVALID','Invalid machine identity binding');
    }
    if(!exact(options,['expectedRevision'])||!Number.isSafeInteger(options.expectedRevision)||
       options.expectedRevision<0)throw fail('INVALID','Expected binding revision is required');
    const receipt=validateReceipt(input.approvalReceipt,input.ownerId,input.deviceId,input.fingerprint);
    const gate=acquire();
    let retain=false;
    try{
      const snapshot=readSnapshot(directory);
      if(!snapshot)throw fail('BINDING_CORRUPT','Machine binding snapshot is missing');
      if(snapshot.revision!==options.expectedRevision){
        throw fail('REVISION_CONFLICT','Machine binding revision conflict');
      }
      const existing=snapshot.bindings.find(record=>record.clientId===input.clientId||
        record.deviceId===input.deviceId||record.approvalEventId===receipt.eventId);
      const candidate={clientId:input.clientId,deviceId:input.deviceId,
        fingerprint:input.fingerprint,ownerId:input.ownerId,ownerDigest:input.ownerDigest,
        approvalEventId:receipt.eventId,bindingEventId:input.bindingEventId,
        trustRevisionBefore:receipt.trustRevisionBefore,
        trustRevisionAfter:receipt.trustRevisionAfter,trustRevision:receipt.trustRevision,
        bindingRevision:snapshot.revision+1};
      let verified;
      try{verified=verifyApprovalReceipt(Object.freeze({...candidate}));}
      catch{throw fail('APPROVAL_UNAVAILABLE','Durable I2 approval evidence is unavailable');}
      if(!matchesReceipt(candidate,verified))throw fail('APPROVAL_DENIED','Approval receipt is not verified');
      let decision;
      try{decision=readBindingDecision(Object.freeze({...candidate}));}
      catch{throw fail('BINDING_AUDIT_UNAVAILABLE','Owner binding audit evidence is unavailable');}
      if(!matchesDecision(candidate,decision,false)){
        throw fail('BINDING_AUDIT_REQUIRED','Matching durable Owner binding intent is required');
      }
      assertHistoryMatchesSnapshot(snapshot,{allowPendingDecision:candidate});
      if(existing){
        const same=existing.clientId===candidate.clientId&&existing.deviceId===candidate.deviceId&&
          existing.fingerprint===candidate.fingerprint&&existing.ownerDigest===candidate.ownerDigest&&
          existing.ownerId===candidate.ownerId&&existing.bindingEventId===candidate.bindingEventId&&
          existing.approvalEventId===candidate.approvalEventId&&
          existing.trustRevisionBefore===candidate.trustRevisionBefore&&
          existing.trustRevisionAfter===candidate.trustRevisionAfter;
        if(same)return Object.freeze({revision:snapshot.revision,binding:Object.freeze({...existing})});
        throw fail('BINDING_CONFLICT','Client-ID or device is already bound to another identity');
      }
      if(snapshot.revision>=MAX_BINDINGS)throw fail('BINDING_FULL','Machine binding store is full');
      const next=[...snapshot.bindings,{...candidate,bindingRevision:snapshot.revision+1}];
      retain=true;
      persistSnapshot(directory,next);
      release(gate);retain=false;
      return Object.freeze({revision:next.length,binding:Object.freeze({...next.at(-1)})});
    }catch(error){
      if(!retain){
        try{release(gate);}catch{blocked=true;}
      }else blocked=true;
      throw error;
    }
  }
  function revision(){return checkedSnapshot().revision;}
  function close(){closed=true;}
  return Object.freeze({bind,resolve,revision,close});
}
