import path from 'node:path';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { constants, closeSync, fstatSync, fsyncSync, lstatSync,
  mkdirSync, openSync, readFileSync, readdirSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import { createDeviceRegistry } from './registry.mjs';
import { createDurableProcessLock, inspectDurableProcessLock,
  removeDeadDurableProcessLock, removeOwnedDurableProcessLock } from '../common/durable-process-lock.mjs';

// G7.2e candidate. Server-side trust records contain PUBLIC keys only.
// Not wired into gateway/server.mjs, Cloudflare or any live tool endpoint.
const FILE='trusted-devices-v1.json';
const OPERATION_GATE='.trusted-devices-operation.lock';
const DISPATCH_PERMIT_PREFIX='.trust-dispatch-permit-';
const MAX_BYTES=1024*1024;
const MAX_TRANSITIONS=2048;
const MAX_TEMP_FILES=16;
const MAX_TEMP_BYTES=4*MAX_BYTES;
const FINGERPRINT=/^[a-f0-9]{64}$/;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const currentSessionProofs=new WeakMap();
const trustError=(code,message)=>Object.assign(new Error(message),{code});
function checkDirectory(directory,{create=false}={}){
  if(process.platform==='win32')throw new Error('VPS trust store requires POSIX owner-only ACLs');
  if(typeof directory!=='string'||!path.isAbsolute(directory)||
     path.normalize(directory)!==directory||directory===path.parse(directory).root){
    throw new TypeError('Trust directory must be a normalized absolute path');
  }
  // Do not follow a symlink in any path component, including ancestors.
  // Parents must be provisioned before the trust store is initialized.
  let cursor=path.parse(directory).root;
  for(const component of directory.slice(cursor.length).split(path.sep)){
    cursor=path.join(cursor,component);
    let st;
    try{st=lstatSync(cursor);}catch(e){
      if(e?.code!=='ENOENT')throw e;
      if(cursor!==directory||!create)throw Error('Missing trusted store directory');
      mkdirSync(cursor,{mode:0o700});
      st=lstatSync(cursor);
    }
    if(!st.isDirectory()||st.isSymbolicLink())throw Error('Unsafe trust directory ancestor');
  }
  const st=lstatSync(directory);
  if(st.uid!==process.getuid()||(st.mode&0o7777)!==0o700){
    throw Error('Unsafe trust directory owner or mode');
  }
  return st;
}
function trustedFile(directory){return path.join(directory,FILE);}
function trustTempEvidence(directory){
  const names=readdirSync(directory).filter(name=>name.startsWith('.trust-')&&
    !name.startsWith(DISPATCH_PERMIT_PREFIX)).sort();
  if(names.length>MAX_TEMP_FILES)throw Error('Trust temporary snapshot limit exceeded');
  let total=0;
  return names.map(name=>{
    if(!/^\.trust-[a-f0-9]{24}$/.test(name))throw Error('Unsafe trust temporary snapshot name');
    const filename=path.join(directory,name),named=lstatSync(filename);
    if(!named.isFile()||named.isSymbolicLink()||named.nlink!==1||
       named.uid!==process.getuid()||(named.mode&0o7777)!==0o600||named.size>MAX_BYTES){
      throw Error('Unsafe trust temporary snapshot');
    }
    const fd=openSync(filename,constants.O_RDONLY|(constants.O_NOFOLLOW??0));
    try{
      const opened=fstatSync(fd);
      if(!opened.isFile()||opened.nlink!==1||opened.uid!==process.getuid()||
         opened.ino!==named.ino||opened.dev!==named.dev||opened.size!==named.size||
         (opened.mode&0o7777)!==0o600)throw Error('Trust temporary snapshot changed');
    }finally{closeSync(fd);}
    total+=named.size;
    if(total>MAX_TEMP_BYTES)throw Error('Trust temporary snapshot capacity exceeded');
    return {name,dev:named.dev,ino:named.ino,size:named.size,uid:named.uid,
      mode:named.mode&0o7777};
  });
}
function assertNoTrustTemps(directory){
  if(trustTempEvidence(directory).length)throw Error('Trust temporary snapshot requires reconciliation');
}
function assertNoWriterLock(directory){
  const lock=inspectDurableProcessLock(directory,'.trusted-devices-writer.lock');
  if(!lock.present)return;
  if(lock.status==='active'){
    throw trustError('TRUST_BUSY','Another verified trust writer is active');
  }
  throw trustError('TRUST_RECOVERY_REQUIRED',
    'Trust writer lock present; owner is stale or cannot be verified; manual reconciliation required');
}
function trustDispatchPermits(directory,{allowActive=true}={}){
  const names=readdirSync(directory).filter(name=>name.startsWith(DISPATCH_PERMIT_PREFIX)).sort();
  if(names.length>64)throw trustError('TRUST_RECOVERY_REQUIRED','Trust dispatch permit limit exceeded');
  const permits=[];
  for(const name of names){
    const permitId=name.slice(DISPATCH_PERMIT_PREFIX.length,-'.lock'.length);
    if(!name.endsWith('.lock')||!UUID.test(permitId)){
      throw trustError('TRUST_RECOVERY_REQUIRED','Unrecognized trust dispatch permit evidence');
    }
    let evidence;
    try{evidence=inspectDurableProcessLock(directory,name);}
    catch{throw trustError('TRUST_RECOVERY_REQUIRED','Trust dispatch permit identity is unverified');}
    if(!evidence.present||evidence.owner?.kind!=='trust-dispatch-permit'||
       evidence.status==='dead'||evidence.status==='unknown'){
      throw trustError('TRUST_RECOVERY_REQUIRED','Stale trust dispatch permit requires operator reconciliation');
    }
    permits.push(evidence);
  }
  if(!allowActive&&permits.length){
    throw trustError('TRUST_BUSY','A dispatched operation holds a trust authorization permit');
  }
  return permits;
}
function acquireTrustOperationGate(directory){
  try{return createDurableProcessLock(directory,OPERATION_GATE,'trust-operation-gate');}
  catch{
    let evidence;
    try{evidence=inspectDurableProcessLock(directory,OPERATION_GATE);}
    catch{throw trustError('TRUST_RECOVERY_REQUIRED','Trust operation gate is uncertain');}
    if(evidence.present&&evidence.status==='active'){
      throw trustError('TRUST_BUSY','Another trust operation is being committed');
    }
    throw trustError('TRUST_RECOVERY_REQUIRED','Stale trust operation gate requires operator reconciliation');
  }
}
function releaseTrustOperationGate(directory,owner){
  removeOwnedDurableProcessLock({directory,name:OPERATION_GATE,owner});
}
function assertNoReconciliationLock(directory){
  const lock=path.join(directory,'.owner-pairing-reconciliation.lock');
  try{lstatSync(lock);}catch(error){if(error?.code==='ENOENT')return;throw error;}
  throw Error('Owner pairing reconciliation in progress; trust store unavailable');
}
function validateHistory(obj){
  if(!obj||typeof obj!=='object'||Array.isArray(obj)||obj.version!==2||
     Object.keys(obj).sort().join(',')!=='devices,historyStartDevices,historyStartRevision,revision,transitions,version'||
     !Number.isSafeInteger(obj.revision)||obj.revision<0||
     !Number.isSafeInteger(obj.historyStartRevision)||obj.historyStartRevision<0||
     obj.historyStartRevision>obj.revision||!Array.isArray(obj.devices)||
     obj.devices.length>256||!Array.isArray(obj.transitions)||
     obj.transitions.length>MAX_TRANSITIONS||!Array.isArray(obj.historyStartDevices)||
     obj.historyStartDevices.length>256)throw Error('Invalid trust document');
  let revision=obj.historyStartRevision;
  const events=new Set(),requests=new Set();
  const current=new Map(),fingerprints=new Set();
  for(const device of obj.historyStartDevices){
    if(!device||typeof device!=='object'||Array.isArray(device)||
       Object.keys(device).sort().join(',')!=='deviceId,fingerprint'||
       !UUID.test(device.deviceId)||!FINGERPRINT.test(device.fingerprint)||
       current.has(device.deviceId)||fingerprints.has(device.fingerprint)){
      throw Error('Invalid trust history baseline');
    }
    current.set(device.deviceId,device.fingerprint);fingerprints.add(device.fingerprint);
  }
  for(const transition of obj.transitions){
    if(!transition||typeof transition!=='object'||Array.isArray(transition)||
       Object.keys(transition).sort().join(',')!==
        'deviceId,eventId,fingerprint,operation,previousRevision,requestId,revision'||
       !['trust','approve','revoke'].includes(transition.operation)||
       !UUID.test(transition.deviceId)||!FINGERPRINT.test(transition.fingerprint)||
       transition.previousRevision!==revision||transition.revision!==revision+1){
      throw Error('Invalid trust transition history');
    }
    if(transition.operation==='approve'){
      if(!UUID.test(transition.eventId)||!UUID.test(transition.requestId)||
         events.has(transition.eventId)||requests.has(transition.requestId)){
        throw Error('Invalid or duplicated trust decision binding');
      }
      events.add(transition.eventId);requests.add(transition.requestId);
    }else if(transition.eventId!==null||transition.requestId!==null){
      throw Error('Invalid trust transition history');
    }
    const priorFingerprint=current.get(transition.deviceId);
    if(transition.operation==='revoke'){
      if(priorFingerprint!==transition.fingerprint)throw Error('Trust revoke has no matching trusted device');
      current.delete(transition.deviceId);fingerprints.delete(transition.fingerprint);
    }else{
      if(priorFingerprint!==undefined||fingerprints.has(transition.fingerprint)){
        throw Error('Trust transition duplicates an existing device');
      }
      current.set(transition.deviceId,transition.fingerprint);fingerprints.add(transition.fingerprint);
    }
    revision=transition.revision;
  }
  if(revision!==obj.revision)throw Error('Trust revision history is incomplete');
  if(current.size!==obj.devices.length)throw Error('Trust snapshot contradicts transition history');
  for(const device of obj.devices){
    if(current.get(device.deviceId)!==device.fingerprint){
      throw Error('Trust snapshot contradicts transition history');
    }
  }
  return obj;
}
function readSnapshot(directory) {
  const filename=trustedFile(directory);
  let stat;
  try{stat=lstatSync(filename);}catch(e){
    if(e?.code==='ENOENT')return {version:2,revision:0,devices:[],
      historyStartRevision:0,historyStartDevices:[],transitions:[]};
    throw e;
  }
  if(!stat.isFile()||stat.isSymbolicLink())throw Error('Unsafe trust file');
  const fd=openSync(filename,constants.O_RDONLY|(constants.O_NOFOLLOW??0));
  try{
    const st=fstatSync(fd);
    if(!st.isFile()||st.nlink!==1||st.uid!==process.getuid()||
       st.size>MAX_BYTES||st.size<=0||(st.mode&0o7777)!==0o600){
      throw Error('Unsafe trust file');
    }
    const data=readFileSync(fd,'utf8');
    let obj;
    try{obj=JSON.parse(data);}catch{throw Error('Invalid trust document');}
    if(!obj||typeof obj!=='object'||Array.isArray(obj)||!Array.isArray(obj.devices)||
       obj.devices.length>256||!Number.isSafeInteger(obj.revision)||obj.revision<0){
      throw Error('Invalid trust document');
    }
    if(obj.version===1&&Object.keys(obj).sort().join(',')==='devices,revision,version'){
      return {version:2,revision:obj.revision,devices:obj.devices,
        historyStartRevision:obj.revision,
        historyStartDevices:obj.devices.map(({deviceId,fingerprint})=>({deviceId,fingerprint})),
        transitions:[]};
    }
    return validateHistory(obj);
  }finally{closeSync(fd);}
}
function commitSnapshot(directory,snapshot){
  const current=trustedFile(directory);
  const temp=path.join(directory,'.trust-'+randomBytes(12).toString('hex'));
  const nofollow=constants.O_NOFOLLOW??0;
  let fd,renamed=false;
  try{
    fd=openSync(temp,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|nofollow,0o600);
    writeFileSync(fd,JSON.stringify(snapshot)+'\n','utf8');
    fsyncSync(fd);
    closeSync(fd);
    fd=undefined;
    renameSync(temp,current);
    renamed=true;
    // POSIX durability: commit directory entry after the atomic rename.
    const dirFd=openSync(directory,constants.O_RDONLY|nofollow);
    try{fsyncSync(dirFd);}finally{closeSync(dirFd);}
  }finally{
    if(fd!==undefined)closeSync(fd);
    if(!renamed){try{unlinkSync(temp);}catch{}}
  }
}
export function createDurableDeviceTrustStore({directory,maxDevices=32,now=Date.now}={}){
  checkDirectory(directory,{create:true});
  const expectedPathStat=lstatSync(directory,{bigint:true});
  // Keep the original directory inode open for the facade lifetime. Birthtime
  // and inode checks alone can miss a fast delete/recreate on filesystems that
  // immediately reuse inode numbers and timestamps.
  const directoryFd=openSync(directory,constants.O_RDONLY|
    (constants.O_DIRECTORY??0)|(constants.O_NOFOLLOW??0));
  let expectedBirthtimeNs,snapshot,current;
  try{
    const expectedOpened=fstatSync(directoryFd,{bigint:true});
    expectedBirthtimeNs=expectedOpened.birthtimeNs;
    if(!expectedOpened.isDirectory()||expectedOpened.dev!==expectedPathStat.dev||
       expectedOpened.ino!==expectedPathStat.ino||expectedBirthtimeNs<=0n){
      throw Error('Trust filesystem lacks stable directory identity support');
    }
    assertNoWriterLock(directory);
    assertNoReconciliationLock(directory);
    assertNoTrustTemps(directory);
    trustDispatchPermits(directory,{allowActive:true});
    const operationGate=inspectDurableProcessLock(directory,OPERATION_GATE);
    if(operationGate.present)throw trustError(operationGate.status==='active'?'TRUST_BUSY':
      'TRUST_RECOVERY_REQUIRED','Trust operation gate is active or requires reconciliation');
    snapshot=readSnapshot(directory);
    assertNoWriterLock(directory);
    current=createDeviceRegistry({maxDevices,now,initialTrustedDevices:snapshot.devices});
  }catch(error){
    closeSync(directoryFd);
    throw error;
  }
  let blocked=false;
  let closed=false;
  // A different process can revoke trust while this instance still holds a
  // live in-memory session. Every authorization-facing operation must fence
  // itself against the authoritative on-disk revision and any active writer.
  const requireHealthy=()=>{
    if(closed||blocked)throw Error('Trust store unavailable; stop routing and restart after repair');
    try {
      checkDirectory(directory);
      const actualPathStat=lstatSync(directory,{bigint:true});
      const openedDirectory=fstatSync(directoryFd,{bigint:true});
      if(actualPathStat.ino!==openedDirectory.ino||
         actualPathStat.dev!==openedDirectory.dev||
         openedDirectory.birthtimeNs!==expectedBirthtimeNs){
        throw Error('Trust directory replaced; restart and reconcile');
      }
      assertNoWriterLock(directory);
      assertNoReconciliationLock(directory);
      assertNoTrustTemps(directory);
      trustDispatchPermits(directory,{allowActive:true});
      const authoritative=readSnapshot(directory);
      if(authoritative.revision!==snapshot.revision||
         JSON.stringify(authoritative.devices)!==JSON.stringify(snapshot.devices)||
         authoritative.historyStartRevision!==snapshot.historyStartRevision||
         JSON.stringify(authoritative.historyStartDevices)!==JSON.stringify(snapshot.historyStartDevices)||
         JSON.stringify(authoritative.transitions)!==JSON.stringify(snapshot.transitions)){
        throw Error('Trust store changed by another process; restart required');
      }
      assertNoWriterLock(directory);
      assertNoReconciliationLock(directory);
    }catch(error){
      if(error?.code==='TRUST_BUSY')throw error;
      blocked=true;
      throw error;
    }
  };
  // Read-only session facade always points to current state. Trust changes keep
  // sessions for unchanged identities and remove only identities no longer trusted.
  const registry=Object.freeze({
    listDevices:(...args)=>{requireHealthy();return current.listDevices(...args);},
    isLiveSession:(...args)=>{requireHealthy();return current.isLiveSession(...args);},
    beginHandshake:(...args)=>{requireHealthy();return current.beginHandshake(...args);},
    completeHandshake:(...args)=>{requireHealthy();return current.completeHandshake(...args);},
    heartbeat:(...args)=>{requireHealthy();return current.heartbeat(...args);},
    acceptSignedFrame:(...args)=>{requireHealthy();return current.acceptSignedFrame(...args);},
    disconnect:(...args)=>{requireHealthy();return current.disconnect(...args);},
    snapshotTrustedDevices:()=>{requireHealthy();return current.snapshotTrustedDevices();},
  });
  function commit(candidate,transition){
    requireHealthy();
    if(snapshot.revision>=Number.MAX_SAFE_INTEGER){blocked=true;throw Error('Trust revision exhausted');}
    if(snapshot.transitions.length>=MAX_TRANSITIONS){
      blocked=true;throw Error('Trust transition history full; manual archival required');
    }
    const nextRevision=snapshot.revision+1;
    const next={version:2,revision:nextRevision,devices:candidate.snapshotTrustedDevices(),
      historyStartRevision:snapshot.historyStartRevision,
      historyStartDevices:snapshot.historyStartDevices,
      transitions:[...snapshot.transitions,{...transition,
        previousRevision:snapshot.revision,revision:nextRevision}]};
    const lockName='.trusted-devices-writer.lock';
    const gateOwner=acquireTrustOperationGate(directory);
    let writerOwner=null,committed=false,staleSnapshot=false;
    try {
      // The operation gate serializes permit creation with mutations. A live
      // dispatch permit is a retryable conflict, not evidence that this store
      // is corrupt and not a reason to poison the facade.
      trustDispatchPermits(directory,{allowActive:false});
      blocked=true;
      writerOwner=createDurableProcessLock(directory,lockName,'trust-writer');
      const lockDirFd=openSync(directory,constants.O_RDONLY|(constants.O_NOFOLLOW??0));
      try{fsyncSync(lockDirFd);}finally{closeSync(lockDirFd);}
      const actual=readSnapshot(directory);
      if(actual.revision!==snapshot.revision ||
         JSON.stringify(actual.devices)!==JSON.stringify(snapshot.devices)||
         actual.historyStartRevision!==snapshot.historyStartRevision||
         JSON.stringify(actual.historyStartDevices)!==JSON.stringify(snapshot.historyStartDevices)||
         JSON.stringify(actual.transitions)!==JSON.stringify(snapshot.transitions)){
        staleSnapshot=true;
        throw Error('Trust store changed by another process; restart required');
      }
      assertNoReconciliationLock(directory);
      commitSnapshot(directory,next); // Do NOT change memory before durable write.
      committed=true;
      snapshot=next;
      current.replaceTrustedDevices(next.devices);
      removeOwnedDurableProcessLock({directory,name:lockName,owner:writerOwner});
      writerOwner=null;
      const dirFd=openSync(directory,constants.O_RDONLY|(constants.O_NOFOLLOW??0));
      try{fsyncSync(dirFd);}finally{closeSync(dirFd);}
      releaseTrustOperationGate(directory,gateOwner);
      blocked=false;
    }catch(error){
      if(error?.code==='TRUST_BUSY'&&!writerOwner&&!committed){
        blocked=false;
        releaseTrustOperationGate(directory,gateOwner);
      }else if(staleSnapshot&&writerOwner&&!committed){
        removeOwnedDurableProcessLock({directory,name:lockName,owner:writerOwner});
        writerOwner=null;
        releaseTrustOperationGate(directory,gateOwner);
        blocked=true; // The instance is stale and must be reopened.
      }else if(!writerOwner&&!committed){
        blocked=true;
        releaseTrustOperationGate(directory,gateOwner);
      }else{
        // A crash or storage error after writer acquisition leaves both fences
        // in place. Recovery must inspect them; never unlock an uncertain commit.
        blocked=true;
      }
      throw error;
    }
  }
  function trustDevice(metadata,options={}) {
    requireHealthy();
    if(!options||typeof options!=='object'||Array.isArray(options)||
       Object.keys(options).some(key=>!['expectedRevision','decision'].includes(key))){
      throw new TypeError('Invalid trust transition options');
    }
    const {expectedRevision,decision}=options;
    if(expectedRevision!==undefined&&(!Number.isSafeInteger(expectedRevision)||expectedRevision<0)){
      throw new TypeError('Invalid expected trust revision');
    }
    if(expectedRevision!==undefined&&expectedRevision!==snapshot.revision){
      throw Error('Trust revision changed before pairing decision');
    }
    const candidate=createDeviceRegistry({maxDevices,now,initialTrustedDevices:snapshot.devices});
    const trusted=candidate.trustDevice(metadata);
    let transition={operation:'trust',eventId:null,requestId:null,
      fingerprint:trusted.fingerprint,deviceId:trusted.deviceId};
    if(decision!==undefined){
      if(!decision||typeof decision!=='object'||Array.isArray(decision)||
         Object.keys(decision).sort().join(',')!=='eventId,fingerprint,requestId'||
         !UUID.test(decision.eventId)||!UUID.test(decision.requestId)||
         !FINGERPRINT.test(decision.fingerprint)||decision.fingerprint!==trusted.fingerprint||
         expectedRevision===undefined){
        throw new TypeError('Invalid owner pairing decision binding');
      }
      if(snapshot.transitions.some(item=>item.eventId===decision.eventId||
         item.requestId===decision.requestId)){
        throw Error('Owner pairing decision already applied');
      }
      transition={...decision,operation:'approve',deviceId:trusted.deviceId};
    }
    commit(candidate,transition);
    return trusted;
  }
  function revokeDevice(deviceId) {
    requireHealthy();
    const candidate=createDeviceRegistry({maxDevices,now,initialTrustedDevices:snapshot.devices});
    if(!candidate.revokeDevice(deviceId))return false;
    const prior=snapshot.devices.find(device=>device.deviceId===deviceId);
    commit(candidate,{operation:'revoke',eventId:null,requestId:null,
      fingerprint:prior.fingerprint,deviceId});
    return true;
  }
  function acquireDispatchPermit({deviceId,sessionId,expectedRevision}={}){
    if(!UUID.test(deviceId??'')||!UUID.test(sessionId??'')||
       !Number.isSafeInteger(expectedRevision)||expectedRevision<0){
      throw trustError('TRUST_INVALID','A device, live session and expected trust revision are required');
    }
    requireHealthy();
    const gateOwner=acquireTrustOperationGate(directory);
    let gateHeld=true,permitOwner=null,permitName=null,uncertain=false;
    try{
      requireHealthy();
      if(expectedRevision!==snapshot.revision){
        throw trustError('TRUST_CHANGED','Trust revision changed before dispatch authorization');
      }
      if(!current.isLiveSession(deviceId,sessionId)){
        throw trustError('TRUST_SESSION_STALE','Device session is no longer live');
      }
      const existing=trustDispatchPermits(directory,{allowActive:true});
      if(existing.length>=64)throw trustError('TRUST_BUSY','Trust dispatch permit limit reached');
      permitName=DISPATCH_PERMIT_PREFIX+randomUUID()+'.lock';
      permitOwner=createDurableProcessLock(directory,permitName,'trust-dispatch-permit');
      // The marker is durably visible before the gate is released. Every trust
      // mutation takes this same gate and refuses to commit while a permit lives.
      releaseTrustOperationGate(directory,gateOwner);gateHeld=false;
      let released=false;
      return Object.freeze({trustRevision:snapshot.revision,release:()=>{
        if(released)return false;
        try{removeOwnedDurableProcessLock({directory,name:permitName,owner:permitOwner});}
        catch(error){blocked=true;throw trustError('TRUST_RECOVERY_REQUIRED',
          'Trust dispatch permit release is uncertain; operator recovery is required');}
        released=true;
        return true;
      }});
    }catch(error){
      if(permitOwner){uncertain=true;blocked=true;}
      throw error;
    }finally{
      if(gateHeld&&!uncertain){
        try{releaseTrustOperationGate(directory,gateOwner);}
        catch{blocked=true;}
      }
    }
  }
  function withCurrentSession({deviceId,sessionId,expectedRevision}={},callback){
    if(!UUID.test(deviceId??'')||!UUID.test(sessionId??'')||
       !Number.isSafeInteger(expectedRevision)||expectedRevision<0||typeof callback!=='function'||
       callback.constructor?.name==='AsyncFunction'){
      throw trustError('TRUST_INVALID','A synchronous callback and exact device session are required');
    }
    const gateOwner=acquireTrustOperationGate(directory);
    const proof=Object.freeze(Object.create(null));
    try{
      requireHealthy();
      if(expectedRevision!==snapshot.revision||!current.isLiveSession(deviceId,sessionId)){
        throw trustError('TRUST_SESSION_STALE','Device trust revision or session changed');
      }
      currentSessionProofs.set(proof,{directory,deviceId,sessionId,expectedRevision,gateOwner,
        isCurrent:()=>!closed&&!blocked&&snapshot.revision===expectedRevision&&
          current.isLiveSession(deviceId,sessionId)});
      const result=callback(proof);
      if(result&&typeof result.then==='function'){
        throw trustError('TRUST_INVALID','Trust response guard callback must be synchronous');
      }
      return result;
    }finally{
      currentSessionProofs.delete(proof);
      releaseTrustOperationGate(directory,gateOwner);
    }
  }
  const revision=()=>{requireHealthy();return snapshot.revision;};
  function close(){
    if(closed)return;
    closed=true;
    closeSync(directoryFd);
  }
  return Object.freeze({registry,trustDevice,revokeDevice,revision,acquireDispatchPermit,
    withCurrentSession,close});
}

// A proof is an in-process capability minted only while withCurrentSession
// owns the operation gate. It is deliberately opaque and is useful only for
// synchronously verifying read-only durable evidence under that same gate.
export function isCurrentTrustSessionProof(proof,{directory,deviceId,sessionId,
  expectedRevision,trustRevision}={}){
  const state=proof&&typeof proof==='object'?currentSessionProofs.get(proof):undefined;
  if(!state||state.directory!==directory||state.deviceId!==deviceId||
     sessionId!==undefined&&state.sessionId!==sessionId||
     state.expectedRevision!==expectedRevision||
     trustRevision!==expectedRevision||!state.isCurrent())return false;
  try{
    const gate=inspectDurableProcessLock(directory,OPERATION_GATE);
    if(!gate.present||gate.status!=='active'||gate.owner?.kind!=='trust-operation-gate'||
       gate.owner?.token!==state.gateOwner.token||gate.owner?.pid!==state.gateOwner.pid||
       gate.owner?.uid!==state.gateOwner.uid||gate.owner?.bootId!==state.gateOwner.bootId||
       gate.owner?.startTicks!==state.gateOwner.startTicks)return false;
    const writer=inspectDurableProcessLock(directory,'.trusted-devices-writer.lock');
    if(writer.present)return false;
    if(trustTempEvidence(directory).length!==0)return false;
    // Dispatch permits prevent trust mutations and cannot change the revision.
    // Accept only permits whose durable process owners remain verified active;
    // dead, unknown, malformed, or foreign permit evidence remains fail-closed.
    trustDispatchPermits(directory,{allowActive:true});
    const reconciliation=inspectDurableProcessLock(directory,'.owner-pairing-reconciliation.lock');
    if(reconciliation.present)return false;
    return true;
  }catch{return false;}
}

function trustLockEvidence(directory){
  return inspectDurableProcessLock(directory,'.trusted-devices-writer.lock');
}

// Read-only evidence inspection intentionally works while an old writer lock
// exists. It never clears that lock or creates a missing store directory.
export function inspectDurableDeviceTrust({directory}={}){
  checkDirectory(directory);
  const snapshot=readSnapshot(directory);
  createDeviceRegistry({maxDevices:256,initialTrustedDevices:snapshot.devices});
  const lock=trustLockEvidence(directory);
  const operationGate=inspectDurableProcessLock(directory,OPERATION_GATE);
  const dispatchPermits=readdirSync(directory).filter(name=>name.startsWith(DISPATCH_PERMIT_PREFIX))
    .sort().map(name=>{
      const permitId=name.slice(DISPATCH_PERMIT_PREFIX.length,-'.lock'.length);
      if(!name.endsWith('.lock')||!UUID.test(permitId)){
        throw trustError('TRUST_RECOVERY_REQUIRED','Unrecognized trust dispatch permit evidence');
      }
      const permit=inspectDurableProcessLock(directory,name);
      if(permit.present&&permit.owner?.kind!=='trust-dispatch-permit'){
        throw trustError('TRUST_RECOVERY_REQUIRED','Trust dispatch permit kind is invalid');
      }
      return permit;
    });
  const temporaryFiles=trustTempEvidence(directory);
  return Object.freeze({...snapshot,lockPresent:lock.present,
    lockStatus:lock.status,lockReason:lock.reason,lockDigest:lock.digest,
    operationGatePresent:operationGate.present,operationGateStatus:operationGate.status,
    operationGateDigest:operationGate.digest,
    dispatchPermits:Object.freeze(dispatchPermits.map(item=>Object.freeze({name:item.name,
      kind:item.owner?.kind,status:item.status,reason:item.reason,digest:item.digest}))),
    temporaryFiles:Object.freeze(temporaryFiles),
    snapshotDigest:createHash('sha256').update(JSON.stringify({snapshot,temporaryFiles,
      operationGatePresent:operationGate.present,operationGateStatus:operationGate.status,
      operationGateDigest:operationGate.digest,dispatchPermits})).digest('hex')});
}

// Lock removal is only reachable through an explicit operator reconciliation.
// Callers must first establish that every trust writer is stopped.
export function releaseTrustWriterLockForReconciliation({directory,expectedRevision,
  expectedSnapshotDigest,operatorConfirmedNoActiveWriters}={}){
  if(operatorConfirmedNoActiveWriters!==true){
    throw Error('Operator confirmation that no writers are active is required');
  }
  checkDirectory(directory);
  const recoveryLock=inspectDurableProcessLock(directory,'.owner-pairing-reconciliation.lock');
  if(!recoveryLock.present||recoveryLock.status!=='active'||
     recoveryLock.owner.kind!=='reconciliation'||recoveryLock.owner.pid!==process.pid){
    throw Error('Reconciliation lock required to release trust writer lock');
  }
  const evidence=inspectDurableDeviceTrust({directory});
  if(evidence.revision!==expectedRevision||evidence.snapshotDigest!==expectedSnapshotDigest){
    throw Error('Trust evidence changed during reconciliation');
  }
  const lock=trustLockEvidence(directory);
  const operationGate=inspectDurableProcessLock(directory,OPERATION_GATE);
  const permits=evidence.dispatchPermits;
  if(lock.present&&lock.status!=='dead')throw Error('Trust writer is active or unverified');
  if(operationGate.present&&operationGate.status!=='dead'){
    throw Error('Trust operation gate is active or unverified');
  }
  if(permits.some(item=>item.status!=='dead')){
    throw Error('Trust dispatch permit is active or unverified');
  }
  for(const item of evidence.temporaryFiles){
    const filename=path.join(directory,item.name),current=lstatSync(filename);
    if(!current.isFile()||current.isSymbolicLink()||current.dev!==item.dev||
       current.ino!==item.ino||current.size!==item.size||current.uid!==item.uid||
       (current.mode&0o7777)!==item.mode){
      throw Error('Trust temporary snapshot changed during reconciliation');
    }
    unlinkSync(filename);
  }
  let removed=false;
  if(lock.present)removed=removeDeadDurableProcessLock({directory,
    name:'.trusted-devices-writer.lock',expectedDigest:lock.digest})||removed;
  if(operationGate.present)removed=removeDeadDurableProcessLock({directory,
    name:OPERATION_GATE,expectedDigest:operationGate.digest})||removed;
  for(const permit of permits){
    removed=removeDeadDurableProcessLock({directory,name:permit.name,
      expectedDigest:permit.digest})||removed;
  }
  return removed;
}
