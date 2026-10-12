import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { constants, closeSync, fstatSync, fsyncSync, lstatSync,
  mkdirSync, openSync, readFileSync, renameSync, rmdirSync, unlinkSync, writeFileSync } from 'node:fs';
import { createDeviceRegistry } from './registry.mjs';

// G7.2e candidate. Server-side trust records contain PUBLIC keys only.
// Not wired into gateway/server.mjs, Cloudflare or any live tool endpoint.
const FILE='trusted-devices-v1.json';
const MAX_BYTES=128*1024;
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
function assertNoWriterLock(directory){
  const lock=path.join(directory,'.trusted-devices-writer.lock');
  try{lstatSync(lock);}catch(e){
    if(e?.code==='ENOENT')return;
    throw e;
  }
  throw Error('Trust writer lock present; manual reconciliation required');
}
function readSnapshot(directory) {
  const filename=trustedFile(directory);
  let stat;
  try{stat=lstatSync(filename);}catch(e){
    if(e?.code==='ENOENT')return {version:1,revision:0,devices:[]};
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
    if(!obj||typeof obj!=='object'||Array.isArray(obj)||
       Object.keys(obj).sort().join(',')!=='devices,revision,version'||
       obj.version!==1||!Number.isSafeInteger(obj.revision)||obj.revision<0||
       !Array.isArray(obj.devices)||obj.devices.length>256)throw Error('Invalid trust document');
    return obj;
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
  const expectedDirectory=checkDirectory(directory,{create:true});
  // On Linux filesystems an inode number can be reused immediately after
  // deletion. Include the POSIX birth timestamp to fence reincarnated paths.
  const expectedBirthtimeNs=lstatSync(directory,{bigint:true}).birthtimeNs;
  if(expectedBirthtimeNs<=0n)throw Error('Trust filesystem lacks directory identity support');
  assertNoWriterLock(directory);
  let snapshot=readSnapshot(directory);
  assertNoWriterLock(directory);
  let current=createDeviceRegistry({maxDevices,now,initialTrustedDevices:snapshot.devices});
  let blocked=false;
  // A different process can revoke trust while this instance still holds a
  // live in-memory session. Every authorization-facing operation must fence
  // itself against the authoritative on-disk revision and any active writer.
  const requireHealthy=()=>{
    if(blocked)throw Error('Trust store unavailable; stop routing and restart after repair');
    try {
      const actualDirectory=checkDirectory(directory);
      if(actualDirectory.ino!==expectedDirectory.ino||
         actualDirectory.dev!==expectedDirectory.dev||
         lstatSync(directory,{bigint:true}).birthtimeNs!==expectedBirthtimeNs){
        throw Error('Trust directory replaced; restart and reconcile');
      }
      assertNoWriterLock(directory);
      const authoritative=readSnapshot(directory);
      if(authoritative.revision!==snapshot.revision||
         JSON.stringify(authoritative.devices)!==JSON.stringify(snapshot.devices)){
        throw Error('Trust store changed by another process; restart required');
      }
      assertNoWriterLock(directory);
    }catch(error){
      blocked=true;
      throw error;
    }
  };
  // Read-only session facade always points to current state. Persistence of any
  // trust change resets ALL live sessions; callers must re-authenticate.
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
  function commit(candidate){
    requireHealthy();
    if(snapshot.revision>=Number.MAX_SAFE_INTEGER){blocked=true;throw Error('Trust revision exhausted');}
    const next={version:1,revision:snapshot.revision+1,devices:candidate.snapshotTrustedDevices()};
    blocked=true; // Fail closed if ANY storage/lock failure or stale snapshot occurs.
    // mkdir is exclusive across processes on a local POSIX filesystem. Never
    // steal a pre-existing lock: after a crash, an operator must reconcile it.
    const lock=path.join(directory,'.trusted-devices-writer.lock');
    let locked=false, committed=false;
    try {
      mkdirSync(lock,{mode:0o700});
      locked=true;
      const actual=readSnapshot(directory);
      if(actual.revision!==snapshot.revision ||
         JSON.stringify(actual.devices)!==JSON.stringify(snapshot.devices)){
        throw Error('Trust store changed by another process; restart required');
      }
      commitSnapshot(directory,next); // Do NOT change memory before durable write.
      committed=true;
      snapshot=next;
      current=candidate; // New registry discards sessions / challenges.
      rmdirSync(lock);
      locked=false;
      blocked=false;
    } finally {
      // On a failed durability step, do not remove the lock automatically:
      // after a crash/uncertain write the next writer must stop for recovery.
      // A deterministic pre-commit stale revision is safe to release.
      if(locked&&!committed){
        // Keep lock in place for operator inspection (fail-closed).
      }
    }
  }
  function trustDevice(metadata) {
    requireHealthy();
    const candidate=createDeviceRegistry({maxDevices,now,initialTrustedDevices:snapshot.devices});
    const trusted=candidate.trustDevice(metadata);
    commit(candidate);
    return trusted;
  }
  function revokeDevice(deviceId) {
    requireHealthy();
    const candidate=createDeviceRegistry({maxDevices,now,initialTrustedDevices:snapshot.devices});
    if(!candidate.revokeDevice(deviceId))return false;
    commit(candidate);
    return true;
  }
  const revision=()=>{requireHealthy();return snapshot.revision;};
  return Object.freeze({registry,trustDevice,revokeDevice,revision});
}
