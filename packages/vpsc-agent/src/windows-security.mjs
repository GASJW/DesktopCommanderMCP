import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

export const WINDOWS_POWERSHELL=path.join(process.env.SystemRoot??'C:\\Windows','System32',
  'WindowsPowerShell','v1.0','powershell.exe');
const HELPER=fileURLToPath(new URL('./windows-security.ps1',import.meta.url));
const ARGS=['-NoLogo','-NoProfile','-NonInteractive','-File',HELPER];
const heldLocks=new Map();
const request=(op,fields={})=>({op,...fields});

function runSync(input,{maxBuffer=2*1024*1024}={}) {
  if(process.platform!=='win32')throw new Error('Windows security primitive is unavailable');
  const proc=spawnSync(WINDOWS_POWERSHELL,ARGS,{input:JSON.stringify(input),encoding:'utf8',
    windowsHide:true,timeout:20_000,maxBuffer,shell:false});
  let value;
  try{value=JSON.parse(proc.stdout);}catch{}
  if(proc.error||proc.status!==0)throw Object.assign(new Error('Windows security helper failed'),{
    code:/^[A-Z_]{1,48}$/.test(value?.error??'')?value.error:'WINDOWS_SECURITY',
    details:{spawnError:proc.error?.message,status:proc.status}});
  if(!value)throw new Error('Windows security helper returned invalid output');
  return value;
}
function run(input,options) {
  const value=runSync(input,options);
  if(value?.ok!==true)throw Object.assign(new Error('Windows security check failed'),{
    code:/^[A-Z_]{1,48}$/.test(value?.error??'')?value.error:'WINDOWS_SECURITY'});
  return value;
}

export function assertNotElevatedWindows() {
  if(run(request('elevated')).elevated)throw Object.assign(new Error('G7 agent must run unelevated'),{code:'PRIVILEGE'});
}
export function securePrivateWindowsDirectory(directory) { run(request('secure-directory',{path:directory})); }
export function securePrivateWindowsFile(filename) { run(request('secure-file',{path:filename})); }
export function verifyPrivateWindowsDirectory(directory) { run(request('verify-private-directory',{path:directory})); }
export function verifyPrivateWindowsFile(filename) { run(request('verify-private-file',{path:filename})); }
export function verifyWindowsOperationRoot(directory) { return run(request('operation-root',{path:directory})).path; }
export function windowsProcessStartTicks(pid=process.pid) { return run(request('process-start',{pid})).startTicks; }
export function readPrivateWindowsFile(filename,{maxBytes=1024*1024,privateOnly=true}={}) {
  if(privateOnly)verifyPrivateWindowsFile(filename);
  return readWindowsFileBeneath(path.dirname(filename),filename,{maxBytes});
}
export function readWindowsFileBeneath(root,filename,{maxBytes=1024*1024}={}) {
  const value=run(request('read',{root,path:filename,maxBytes}),{maxBuffer:maxBytes*2+1024*1024});
  return Buffer.from(value.bytes,'base64');
}
export function listWindowsDirectoryBeneath(root,filename,{depth=0,limit=200}={}) {
  return run(request('list',{root,path:filename,depth,limit})).value;
}
export function createWindowsFileBeneath(root,filename,bytes) {
  return run(request('create',{root,path:filename,bytes:Buffer.from(bytes).toString('base64')})).bytes;
}
export function moveWindowsFileWriteThrough(source,destination,{replace=true}={}) {
  if(typeof replace!=='boolean')throw new TypeError('Windows replace mode must be boolean');
  run(request('move-write-through',{source,destination,replace}));
}

function lockBytes(owner){return Buffer.from(JSON.stringify(owner)+'\n');}
function lockDigest(owner){return createHash('sha256').update(lockBytes(owner)).digest('hex');}
export function inspectWindowsFileLock(directory,name) {
  const result=run(request('lock-inspect',{path:path.join(directory,name)}));
  if(result.status==='absent')return Object.freeze({present:false,status:'absent',directory,name,
    lockPath:path.join(directory,name)});
  if(result.status==='active')return Object.freeze({present:true,status:'active',directory,name,
    lockPath:path.join(directory,name),reason:'exclusive Windows file handle is held'});
  if(!['dead','unknown'].includes(result.status)||typeof result.bytes!=='string')
    return Object.freeze({present:true,status:'unknown',directory,name,lockPath:path.join(directory,name)});
  let owner;
  try{owner=JSON.parse(Buffer.from(result.bytes,'base64').toString('utf8'));}catch{}
  if(!owner||owner.version!==1||!Number.isSafeInteger(owner.pid)||typeof owner.startTicks!=='string'||
     !/^[0-9]+$/.test(owner.startTicks)||typeof owner.token!=='string'){
    return Object.freeze({present:true,status:'unknown',directory,name,lockPath:path.join(directory,name)});
  }
  const digest=createHash('sha256').update(Buffer.from(result.bytes,'base64')).digest('hex');
  return Object.freeze({present:true,status:result.status,directory,name,lockPath:path.join(directory,name),
    owner:Object.freeze(owner),digest,reason:result.status==='dead'?'owner process identity is no longer active':'owner process identity is unavailable'});
}
function clearWindowsFileLock(directory,name,owner,allowActive) {
  const result=runSync(request('lock-clear',{path:path.join(directory,name),
    expectedBytes:lockBytes(owner).toString('base64'),pid:owner.pid,startTicks:owner.startTicks,
    allowActive}));
  return result?.cleared===true;
}
export function createWindowsFileLock(directory,name,kind) {
  if(typeof kind!=='string'||!/^[a-z][a-z0-9-]{0,63}$/.test(kind))throw new TypeError('Invalid Windows lock kind');
  const owner=Object.freeze({version:1,kind,pid:process.pid,
    startTicks:windowsProcessStartTicks(),token:randomUUID()});
  const filename=path.join(directory,name);
  createWindowsFileBeneath(directory,filename,lockBytes(owner));
  securePrivateWindowsFile(filename);
  return owner;
}
export function removeOwnedWindowsFileLock({directory,name,owner}={}) {
  if(owner?.pid!==process.pid||owner.startTicks!==windowsProcessStartTicks()||
     !clearWindowsFileLock(directory,name,owner,true))
    throw Object.assign(new Error('Windows lock ownership or release is uncertain'),{code:'LOCK_RELEASE_UNCERTAIN'});
  return true;
}
export function removeDeadWindowsFileLock({directory,name,expectedDigest}={}) {
  const lock=inspectWindowsFileLock(directory,name);
  if(!lock.present)return false;
  if(lock.status!=='dead'||lock.digest!==expectedDigest)
    throw Object.assign(new Error('Windows lock changed or is still active'),{code:'LOCK_RECOVERY_BLOCKED'});
  if(!clearWindowsFileLock(directory,name,lock.owner,false))
    throw Object.assign(new Error('Windows stale lock changed during recovery'),{code:'LOCK_RECOVERY_BLOCKED'});
  return true;
}
export function createWindowsDurableProcessLock(directory,name,kind) {
  if(typeof kind!=='string'||!/^[a-z][a-z0-9-]{0,63}$/.test(kind))throw new TypeError('Invalid durable lock kind');
  const token=randomUUID();
  const owner={version:1,kind,pid:process.pid,startTicks:'pending',token};
  const child=spawn(WINDOWS_POWERSHELL,ARGS,{stdio:['pipe','pipe','ignore'],windowsHide:true,shell:false});
  child.stdin.end(JSON.stringify({op:'lock-hold',path:path.join(directory,name),ownerJson:JSON.stringify(owner)}));
  return new Promise((resolve,reject)=>{
    let output='',settled=false;
    const timer=setTimeout(()=>finish(Object.assign(new Error('Windows durable lock timed out'),{code:'LOCK_UNAVAILABLE'})),10_000);
    const finish=(error,value)=>{if(settled)return;settled=true;clearTimeout(timer);
      if(error){try{child.kill();}catch{}reject(error);}else resolve(value);};
    child.stdout.setEncoding('utf8').on('data',chunk=>{
      output+=chunk;const line=output.split(/\r?\n/)[0];
      if(line.startsWith('READY:')){
        owner.startTicks=line.slice(6);
        heldLocks.set(token,{child,directory,name,owner:Object.freeze({...owner})});
        finish(null,Object.freeze({...owner}));
      }else if(['BUSY','STALE'].includes(line)||line.startsWith('ERROR_')){
        finish(Object.assign(new Error('Windows durable lock unavailable'),{
          code:line==='BUSY'?'EEXIST':line==='STALE'?'STALE_LOCK':'LOCK_UNAVAILABLE',details:{helperStatus:line}}));
      }
    });
    child.once('error',error=>finish(error));
    child.once('exit',code=>{if(!settled)finish(Object.assign(new Error('Windows lock helper exited'),{
      code:code===2?'STALE_LOCK':'LOCK_UNAVAILABLE',details:{code,output:output.slice(-256)}}));});
  });
}
export async function removeOwnedWindowsDurableProcessLock({directory,name,owner}={}) {
  const held=heldLocks.get(owner?.token);
  if(!held||held.directory!==directory||held.name!==name||
     JSON.stringify(held.owner)!==JSON.stringify(owner))throw new Error('Windows lock is not owned by this process');
  heldLocks.delete(owner.token);
  if(held.child.exitCode===null){
    await new Promise(resolve=>{held.child.once('exit',resolve);try{held.child.kill();}catch{resolve();}});
  }
  if(!clearWindowsFileLock(directory,name,owner,true))
    throw Object.assign(new Error('Windows lock release is uncertain'),{code:'LOCK_RELEASE_UNCERTAIN'});
  return true;
}
