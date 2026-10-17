import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  constants, closeSync, fstatSync, fsyncSync, lstatSync, mkdirSync,
  openSync, readFileSync, readdirSync, rmdirSync, unlinkSync, writeSync,
} from 'node:fs';

const OWNER='owner.json';
const GUARD='.g7-process-lock.guard';
const WORKER_FLAG='--g7-process-lock-worker';
const MODULE_PATH=fileURLToPath(import.meta.url);
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-4[0-9a-f]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const MAX_OWNER_BYTES=512;

function validLocation(directory,name){
  if(process.platform!=='linux'||typeof process.getuid!=='function'){
    throw Error('Durable process locks require Linux process identity evidence');
  }
  if(typeof directory!=='string'||!path.isAbsolute(directory)||
     path.normalize(directory)!==directory||directory===path.parse(directory).root||
     typeof name!=='string'||path.basename(name)!==name||name==='.'||name==='..'){
    throw new TypeError('Invalid durable process lock location');
  }
  const directoryStat=lstatSync(directory);
  if(!directoryStat.isDirectory()||directoryStat.isSymbolicLink()||
     directoryStat.uid!==process.getuid()||(directoryStat.mode&0o7777)!==0o700){
    throw Error('Unsafe durable process lock directory');
  }
  return path.join(directory,name);
}

function bootId(){
  const value=readFileSync('/proc/sys/kernel/random/boot_id','utf8').trim();
  if(!UUID.test(value))throw Error('Linux boot identity unavailable');
  return value.toLowerCase();
}

function processStartTicks(pid){
  const value=readFileSync(`/proc/${pid}/stat`,'utf8');
  const close=value.lastIndexOf(')');
  if(close<0)throw Error('Invalid Linux process stat');
  const fields=value.slice(close+1).trim().split(/\s+/);
  const startTicks=fields[19]; // field 22, after pid + comm + state (field 3)
  if(!/^\d+$/.test(startTicks??''))throw Error('Linux process start identity unavailable');
  return {startTicks,state:fields[0]};
}

function currentOwner(kind){
  if(typeof kind!=='string'||!/^[a-z][a-z0-9-]{0,63}$/.test(kind)){
    throw new TypeError('Invalid durable process lock kind');
  }
  const identity=processStartTicks(process.pid);
  return {version:1,kind,pid:process.pid,uid:process.getuid(),bootId:bootId(),
    startTicks:identity.startTicks,token:randomUUID()};
}

function validateOwner(owner){
  return owner&&typeof owner==='object'&&!Array.isArray(owner)&&
    Object.keys(owner).sort().join(',')==='bootId,kind,pid,startTicks,token,uid,version'&&
    owner.version===1&&typeof owner.kind==='string'&&/^[a-z][a-z0-9-]{0,63}$/.test(owner.kind)&&
    Number.isSafeInteger(owner.pid)&&owner.pid>0&&Number.isSafeInteger(owner.uid)&&owner.uid>=0&&
    UUID.test(owner.bootId)&&/^\d+$/.test(owner.startTicks)&&UUID.test(owner.token);
}

function ownerProcessStatus(owner){
  let activeBoot;
  try{activeBoot=bootId();}catch(error){return {status:'unknown',reason:error.message};}
  if(owner.bootId!==activeBoot)return {status:'dead',reason:'owner belongs to an earlier boot'};
  let current;
  try{current=processStartTicks(owner.pid);}catch(error){
    if(error?.code==='ENOENT')return {status:'dead',reason:'owner process no longer exists'};
    return {status:'unknown',reason:'owner process identity cannot be read'};
  }
  if(current.startTicks!==owner.startTicks){
    return {status:'dead',reason:'pid has been reused by a different process'};
  }
  if(current.state==='Z'||current.state==='X')return {status:'dead',reason:'owner process has exited'};
  return {status:'active',reason:'owner process identity is still present'};
}

function syncDirectory(directory){
  const fd=openSync(directory,constants.O_RDONLY|(constants.O_DIRECTORY??0)|
    (constants.O_NOFOLLOW??0));
  try{fsyncSync(fd);}finally{closeSync(fd);}
}

function ensureGuardFile(directory){
  const filename=path.join(directory,GUARD);
  let fd;
  try{
    fd=openSync(filename,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|
      (constants.O_NOFOLLOW??0),0o600);
    fsyncSync(fd);
    closeSync(fd);fd=undefined;
    syncDirectory(directory);
  }catch(error){
    if(fd!==undefined)closeSync(fd);
    if(error?.code!=='EEXIST')throw error;
  }
  const stat=lstatSync(filename);
  if(!stat.isFile()||stat.isSymbolicLink()||stat.nlink!==1||
     stat.uid!==process.getuid()||(stat.mode&0o7777)!==0o600){
    throw Error('Unsafe durable process lock guard file');
  }
  return filename;
}

function runGuarded(directory,name,operation,payload){
  validLocation(directory,name);
  const guard=ensureGuardFile(directory);
  const result=spawnSync('/usr/bin/flock',['-F','-x',guard,process.execPath,MODULE_PATH,
    WORKER_FLAG,operation,directory,name,JSON.stringify({...payload,callerPid:process.pid})],
    {encoding:'utf8',timeout:10000,maxBuffer:4096});
  if(result.error)throw result.error;
  let response;
  try{response=JSON.parse(result.stdout??'');}
  catch{throw Error((result.stderr||'Durable process lock operation failed').trim());}
  if(result.status!==0||!response?.ok){
    const error=Error(response?.message||result.stderr||'Durable process lock operation failed');
    if(response?.code)error.code=response.code;
    throw error;
  }
  return response.value;
}

function readOwner(directory,name,lockPath,lockStat){
  const entries=readdirSync(lockPath);
  if(entries.length===0)return {present:true,status:'unknown',reason:'legacy lock has no owner record',
    directory,name,lockPath,lockDev:lockStat.dev,lockIno:lockStat.ino};
  if(entries.length!==1||entries[0]!==OWNER){
    throw Error('Unsafe durable process lock contents');
  }
  const filename=path.join(lockPath,OWNER),named=lstatSync(filename);
  if(!named.isFile()||named.isSymbolicLink()||named.nlink!==1||
     named.uid!==process.getuid()||(named.mode&0o7777)!==0o600||
     named.size<=0||named.size>MAX_OWNER_BYTES){
    throw Error('Unsafe durable process lock owner record');
  }
  const fd=openSync(filename,constants.O_RDONLY|(constants.O_NOFOLLOW??0));
  let bytes;
  try{
    const opened=fstatSync(fd);
    if(!opened.isFile()||opened.nlink!==1||opened.uid!==process.getuid()||
       opened.ino!==named.ino||opened.dev!==named.dev||opened.size!==named.size||
       (opened.mode&0o7777)!==0o600){
      throw Error('Durable process lock owner record changed');
    }
    bytes=readFileSync(fd);
  }finally{closeSync(fd);}
  let owner;
  try{owner=JSON.parse(bytes.toString('utf8'));}catch{throw Error('Invalid durable process lock owner record');}
  if(!validateOwner(owner)||Buffer.from(JSON.stringify(owner)+'\n').compare(bytes)!==0){
    throw Error('Invalid durable process lock owner schema');
  }
  const identity=ownerProcessStatus(owner);
  const latestLock=lstatSync(lockPath),latestOwner=lstatSync(filename);
  if(latestLock.dev!==lockStat.dev||latestLock.ino!==lockStat.ino||
     latestOwner.dev!==named.dev||latestOwner.ino!==named.ino){
    throw Error('Durable process lock changed during inspection');
  }
  return {present:true,status:identity.status,reason:identity.reason,owner,
    digest:createHash('sha256').update(bytes).digest('hex'),
    directory,name,lockPath,lockDev:lockStat.dev,lockIno:lockStat.ino};
}

export function inspectDurableProcessLock(directory,name){
  const lockPath=validLocation(directory,name);
  let lockStat;
  try{lockStat=lstatSync(lockPath);}catch(error){
    if(error?.code==='ENOENT')return Object.freeze({present:false,status:'absent',directory,name,lockPath});
    throw error;
  }
  if(!lockStat.isDirectory()||lockStat.isSymbolicLink()||
     lockStat.uid!==process.getuid()||(lockStat.mode&0o7777)!==0o700){
    throw Error('Unsafe durable process lock');
  }
  return Object.freeze(readOwner(directory,name,lockPath,lockStat));
}

function createLockUnlocked(directory,name,owner){
  const lockPath=validLocation(directory,name);
  if(!validateOwner(owner)||owner.uid!==process.getuid()){
    throw new TypeError('Invalid durable process lock owner');
  }
  if(ownerProcessStatus(owner).status!=='active'){
    throw Error('Durable process lock owner is no longer active');
  }
  mkdirSync(lockPath,{mode:0o700});
  syncDirectory(directory);
  const filename=path.join(lockPath,OWNER),bytes=Buffer.from(JSON.stringify(owner)+'\n');
  const fd=openSync(filename,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|
    (constants.O_NOFOLLOW??0),0o600);
  try{
    let offset=0;
    while(offset<bytes.length){
      const written=writeSync(fd,bytes,offset,bytes.length-offset);
      if(written<=0)throw Error('Short durable process lock owner write');
      offset+=written;
    }
    fsyncSync(fd);
  }finally{closeSync(fd);}
  syncDirectory(lockPath);
  syncDirectory(directory);
  return Object.freeze(owner);
}

export function createDurableProcessLock(directory,name,kind){
  return runGuarded(directory,name,'create',{owner:currentOwner(kind)});
}

function verifyExpected(lock,expectedDigest){
  if(expectedDigest!==undefined&&lock.digest!==expectedDigest){
    throw Error('Durable process lock changed during recovery');
  }
  return lock;
}

function removeDeadLockUnlocked(directory,name,expectedDigest){
  const lock=verifyExpected(inspectDurableProcessLock(directory,name),expectedDigest);
  if(!lock.present)return false;
  if(lock.status==='active')throw Error('Durable process lock owner is active');
  if(lock.status!=='dead')throw Error('Durable process lock owner identity is unknown');
  const filename=path.join(lock.lockPath,OWNER);
  unlinkSync(filename);
  rmdirSync(lock.lockPath);
  syncDirectory(directory);
  return true;
}

export function removeDeadDurableProcessLock({directory,name,expectedDigest}={}){
  return runGuarded(directory,name,'remove-dead',{expectedDigest});
}

function removeOwnedLockUnlocked(directory,name,owner,callerPid){
  const lock=inspectDurableProcessLock(directory,name);
  if(!lock.present||lock.status!=='active'||!validateOwner(owner)||
     owner.pid!==callerPid||owner.uid!==process.getuid()||
     lock.digest!==createHash('sha256').update(JSON.stringify(owner)+'\n').digest('hex')||
     lock.owner.token!==owner.token){
    throw Error('Durable process lock is not owned by this process');
  }
  unlinkSync(path.join(lock.lockPath,OWNER));
  rmdirSync(lock.lockPath);
  syncDirectory(directory);
  return true;
}

export function removeOwnedDurableProcessLock({directory,name,owner}={}){
  return runGuarded(directory,name,'remove-owned',{owner});
}

if(process.argv[1]&&path.resolve(process.argv[1])===MODULE_PATH&&
   process.argv[2]===WORKER_FLAG){
  try{
    const [operation,directory,name,serialized]=process.argv.slice(3);
    const payload=JSON.parse(serialized??'{}');
    let value;
    if(operation==='create'){
      if(payload.owner?.pid!==payload.callerPid)throw Error('Process lock owner must be caller');
      value=createLockUnlocked(directory,name,payload.owner);
    }
    else if(operation==='remove-dead')value=removeDeadLockUnlocked(directory,name,
      payload.expectedDigest);
    else if(operation==='remove-owned')value=removeOwnedLockUnlocked(directory,name,
      payload.owner,payload.callerPid);
    else throw Error('Unknown durable process lock operation');
    process.stdout.write(JSON.stringify({ok:true,value}));
  }catch(error){
    process.stdout.write(JSON.stringify({ok:false,message:String(error?.message??error),
      ...(error?.code?{code:error.code}:{})}));
    process.exitCode=1;
  }
}
