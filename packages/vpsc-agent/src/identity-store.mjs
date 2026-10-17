import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { constants, closeSync, fstatSync, fsyncSync, lstatSync, mkdirSync,
  openSync, readFileSync, readdirSync, renameSync, unlinkSync, writeFileSync, writeSync } from 'node:fs';
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { createPairingIdentityFromPkcs8 } from './pairing.mjs';
import { createDurableProcessLock, inspectDurableProcessLock,
  removeDeadDurableProcessLock, removeOwnedDurableProcessLock } from '../../../gateway/common/durable-process-lock.mjs';

// This is an offline identity-store candidate, NOT connected to an agent route.
// Persistence never implies enrollment, trust, or server-side authorization.
const KEY_FILE = 'identity-v1.json';
const BINDING_LOCK = 'identity-binding.lock';
const BINDING_RECOVERY_LOCK = 'identity-binding-recovery.lock';
const BINDING_TEMP_PREFIX = '.identity-binding-';
const MAX_FILE_BYTES = 8192;
const FILE_MASK = 0o077;
const DIR_MASK = 0o077;
const FOLDER = '.vpsc-device';
const DOMAIN = 'VPSC-AGENT-KEY-v1';
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const OWNER_ID=/^[a-f0-9]{24}$/;
const CLIENT=/^[A-Za-z0-9_.-]{8,256}$/;
const HEX64=/^[a-f0-9]{64}$/;

function storageFolder(platform) {
  if (platform === 'win32') {
    const base = process.env.LOCALAPPDATA;
    if (typeof base !== 'string' || !path.isAbsolute(base)) {
      throw new Error('Windows LOCALAPPDATA must be absolute');
    }
    return path.join(base,'VPSCommander','device');
  }
  if (platform === 'linux' || platform === 'darwin') return path.join(os.homedir(),FOLDER);
  throw new Error('Unsupported device platform');
}

function assertStoreDir(dir,platform) {
  if (typeof dir !== 'string' || !path.isAbsolute(dir)) throw new TypeError('Invalid identity directory');
  mkdirSync(dir,{recursive:true,mode:0o700});
  const st=lstatSync(dir);
  if (!st.isDirectory() || st.isSymbolicLink()) throw new Error('Unsafe identity directory');
  if (platform !== 'win32' && (st.mode & DIR_MASK)) {
    throw new Error('Identity directory permissions must be owner-only');
  }
}

function powershellDpapi(op,input) {
  // Script body is static and contains no secrets. PKCS8 key material is sent
  // only through stdin, never in argv, the shell command or the output logs.
  const code = [
    "Add-Type -AssemblyName System.Security",
    "$ErrorActionPreference='Stop'",
    "$s=[Console]::In.ReadToEnd().Trim()",
    "$bytes=[Convert]::FromBase64String($s)",
    "$entropy=[Text.Encoding]::UTF8.GetBytes('"+DOMAIN+"')",
    "$scope=[System.Security.Cryptography.DataProtectionScope]::CurrentUser",
    "$cipher=[System.Security.Cryptography.ProtectedData]::"+(op==='protect'?'Protect':'Unprotect')+"($bytes,$entropy,$scope)",
    "[Console]::Out.Write([Convert]::ToBase64String($cipher))",
  ].join(';');
  const proc=spawnSync('powershell.exe',['-NoProfile','-NonInteractive','-EncodedCommand',
    Buffer.from(code,'utf16le').toString('base64')],{
    input:Buffer.from(input).toString('base64'),encoding:'utf8',
    windowsHide:true,timeout:12_000,maxBuffer:8192,shell:false,
  });
  if (proc.error || proc.status !== 0 ||
      typeof proc.stdout !== 'string' || !/^[A-Za-z0-9+/=\s]+$/.test(proc.stdout.trim())) {
    throw new Error('Windows user-scoped key protection unavailable');
  }
  const output=Buffer.from(proc.stdout.trim(),'base64');
  if (output.length < 16 || output.length > 2048) throw new Error('Invalid DPAPI output');
  return output;
}

function sameKeys(value,keys){
  return value&&typeof value==='object'&&!Array.isArray(value)&&
    Object.getPrototypeOf(value)===Object.prototype&&
    Object.keys(value).sort().join(',')===[...keys].sort().join(',');
}
function validBinding(value,fingerprint){
  return sameKeys(value,['deviceId','clientId','fingerprint','approvalEventId',
    'bindingEventId','bindingRevision','ownerId','ownerDigest',
    'trustRevisionBefore','trustRevisionAfter','trustRevision'])&&
    UUID.test(value.deviceId??'')&&CLIENT.test(value.clientId??'')&&
    value.fingerprint===fingerprint&&HEX64.test(value.fingerprint??'')&&
    UUID.test(value.approvalEventId??'')&&UUID.test(value.bindingEventId??'')&&
    OWNER_ID.test(value.ownerId??'')&&HEX64.test(value.ownerDigest??'')&&
    Number.isSafeInteger(value.bindingRevision)&&value.bindingRevision>0&&
    Number.isSafeInteger(value.trustRevisionBefore)&&value.trustRevisionBefore>=0&&
    Number.isSafeInteger(value.trustRevisionAfter)&&
    value.trustRevisionAfter===value.trustRevisionBefore+1&&
    Number.isSafeInteger(value.trustRevision)&&value.trustRevision>=value.trustRevisionAfter;
}
function parsePersisted(text,platform) {
  let envelope;
  try { envelope=JSON.parse(text); } catch { throw new Error('Invalid device identity envelope'); }
  const legacy=!!envelope&&envelope.version===1&&sameKeys(envelope,
    ['encoding','fingerprint','key','version']);
  const olderBound=!!envelope&&envelope.version===2&&sameKeys(envelope,
    ['deviceBinding','encoding','fingerprint','key','version'])&&
    envelope.deviceBinding&&sameKeys(envelope.deviceBinding,['deviceId','clientId','fingerprint',
      'approvalEventId','trustRevisionBefore','trustRevisionAfter','trustRevision'])&&
    UUID.test(envelope.deviceBinding.deviceId??'')&&CLIENT.test(envelope.deviceBinding.clientId??'')&&
    envelope.deviceBinding.fingerprint===envelope.fingerprint&&HEX64.test(envelope.fingerprint??'')&&
    UUID.test(envelope.deviceBinding.approvalEventId??'')&&
    Number.isSafeInteger(envelope.deviceBinding.trustRevisionBefore)&&envelope.deviceBinding.trustRevisionBefore>=0&&
    Number.isSafeInteger(envelope.deviceBinding.trustRevisionAfter)&&
    envelope.deviceBinding.trustRevisionAfter===envelope.deviceBinding.trustRevisionBefore+1&&
    Number.isSafeInteger(envelope.deviceBinding.trustRevision)&&
    envelope.deviceBinding.trustRevision>=envelope.deviceBinding.trustRevisionAfter;
  const bound=!!envelope&&envelope.version===3&&sameKeys(envelope,
    ['deviceBinding','encoding','fingerprint','key','version'])&&
    validBinding(envelope.deviceBinding,envelope.fingerprint);
  if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope) ||
      !(legacy||olderBound||bound) || typeof envelope.key !== 'string' ||
      envelope.key.length > 3000 || !/^[A-Za-z0-9+/]+={0,2}$/.test(envelope.key) ||
      !/^[a-f0-9]{64}$/.test(envelope.fingerprint)) {
    throw new Error('Invalid device identity envelope');
  }
  const required=platform==='win32'?'dpapi-current-user':'pkcs8-owner-file';
  if (envelope.encoding !== required) throw new Error('Wrong identity platform protection');
  let key=Buffer.from(envelope.key,'base64');
  if (key.length < 16 || key.length > 2048) throw new Error('Invalid key encoding');
  if (platform==='win32') key=powershellDpapi('unprotect',key);
  const identity=createPairingIdentityFromPkcs8(key);
  key.fill(0);
  if (identity.fingerprint !== envelope.fingerprint) throw new Error('Identity fingerprint mismatch');
  return Object.freeze({...identity,deviceBinding:bound
    ?Object.freeze({...envelope.deviceBinding}):null,
    ...(olderBound?{legacyDeviceBinding:Object.freeze({...envelope.deviceBinding})}:{})});
}

function syncDirectory(directory){
  const fd=openSync(directory,constants.O_RDONLY|(constants.O_DIRECTORY??0)|(constants.O_NOFOLLOW??0));
  try{fsyncSync(fd);}finally{closeSync(fd);}
}

function assertNoInterruptedBinding(directory){
  for(const name of [BINDING_LOCK,BINDING_RECOVERY_LOCK])try{
    const stat=lstatSync(path.join(directory,name));
    if(stat.isDirectory()&&!stat.isSymbolicLink()&&process.platform==='linux'&&
       typeof process.getuid==='function'){
      const lock=inspectDurableProcessLock(directory,name);
      throw new Error(`Identity binding requires operator recovery (${name}: ${lock.status})`);
    }
    throw new Error('Identity binding requires operator recovery (unverified legacy lock)');
  }catch(error){if(error?.code!=='ENOENT')throw error;}
  for(const name of readdirSync(directory)){
    if(name.startsWith(BINDING_TEMP_PREFIX)){
      throw new Error('Interrupted identity binding requires operator recovery');
    }
  }
}

export function analyzeDeviceIdentityBindingRecovery({directory}={}){
  assertStoreDir(directory,process.platform);
  const locks=[];
  for(const name of [BINDING_LOCK,BINDING_RECOVERY_LOCK])try{
    const stat=lstatSync(path.join(directory,name));
    locks.push(stat.isDirectory()&&!stat.isSymbolicLink()&&process.platform==='linux'&&
      typeof process.getuid==='function'?inspectDurableProcessLock(directory,name):
      {present:true,status:'unknown',name});
  }catch(error){if(error?.code!=='ENOENT')return Object.freeze({state:'LOCK_UNVERIFIED'});}
  const temporaryFiles=readdirSync(directory).filter(name=>name.startsWith(BINDING_TEMP_PREFIX));
  const lock=locks.find(item=>item.name!==BINDING_RECOVERY_LOCK)??locks[0]??
    {present:false,status:'absent'};
  const recoveryLock=locks.find(item=>item.name===BINDING_RECOVERY_LOCK);
  if(temporaryFiles.length)return Object.freeze({state:'TEMPORARY_EVIDENCE',
    temporaryFileCount:temporaryFiles.length,lockPresent:lock.present,lockStatus:lock.status,
    ...(lock.digest?{lockDigest:lock.digest}:{})});
  if(recoveryLock)return Object.freeze({state:recoveryLock.status==='active'?'RECOVERY_ACTIVE':
    recoveryLock.status==='dead'?'RECOVERY_STALE':'RECOVERY_UNVERIFIED',
    lockPresent:lock.present,lockStatus:lock.status,
    ...(lock.digest?{lockDigest:lock.digest}:{}),
    recoveryLockDigest:recoveryLock.digest});
  if(lock.present)return Object.freeze({state:lock.status==='active'?'ACTIVE_LOCK':
    lock.status==='dead'?'STALE_LOCK':'LOCK_UNVERIFIED',lockStatus:lock.status,
    ...(lock.digest?{lockDigest:lock.digest}:{})});
  return Object.freeze({state:'CLEAN'});
}

// This is an explicit operator action. It only releases a provably dead Linux
// process lock after the caller confirms writer quiescence and verifies the
// matching durable machine binding in the Gateway audit/store. Interrupted
// temporary envelopes are preserved for investigation and block this action.
export function clearStaleDeviceIdentityBindingLock({directory,expectedLockDigest,
  operatorConfirmedNoActiveWriters,verifyMachineBinding}={}){
  if(operatorConfirmedNoActiveWriters!==true||typeof verifyMachineBinding!=='function'){
    throw new Error('Operator quiescence and machine binding verification are required');
  }
  if(process.platform!=='linux'||typeof process.getuid!=='function'){
    throw new Error('Safe identity lock recovery requires Linux process identity evidence');
  }
  const diagnosis=analyzeDeviceIdentityBindingRecovery({directory});
  if(diagnosis.state!=='STALE_LOCK'||typeof expectedLockDigest!=='string'||
     diagnosis.lockDigest!==expectedLockDigest){
    throw new Error(`Identity binding lock recovery blocked: ${diagnosis.state}`);
  }
  const recoveryOwner=createDurableProcessLock(directory,BINDING_RECOVERY_LOCK,
    'device-identity-recovery');
  try{
    const currentDiagnosis=analyzeDeviceIdentityBindingRecovery({directory});
    if(currentDiagnosis.state!=='RECOVERY_ACTIVE'||currentDiagnosis.lockStatus!=='dead'||
       currentDiagnosis.lockDigest!==expectedLockDigest){
      throw new Error(`Identity binding lock changed during recovery: ${currentDiagnosis.state}`);
    }
    const current=readEnvelope(directory,process.platform);
    if(verifyMachineBinding(Object.freeze({fingerprint:current.identity.fingerprint,
         binding:current.identity.deviceBinding}))!==true){
      throw new Error('Matching durable Gateway machine binding was not verified');
    }
    return removeDeadDurableProcessLock({directory,name:BINDING_LOCK,
      expectedDigest:expectedLockDigest});
  }finally{
    removeOwnedDurableProcessLock({directory,name:BINDING_RECOVERY_LOCK,owner:recoveryOwner});
  }
}

function readEnvelope(directory,platform){
  const filename=path.join(directory,KEY_FILE),nofollow=constants.O_NOFOLLOW??0;
  const fd=openSync(filename,constants.O_RDONLY|nofollow);
  try{
    const st=fstatSync(fd);
    if(!st.isFile()||st.size<=0||st.size>MAX_FILE_BYTES||
       platform!=='win32'&&(st.mode&FILE_MASK))throw new Error('Unsafe identity file');
    const text=readFileSync(fd,'utf8');
    const identity=parsePersisted(text,platform);
    return {text,envelope:JSON.parse(text),identity,stat:st};
  }finally{closeSync(fd);}
}

function validateApprovalReceipt(receipt){
  if(!sameKeys(receipt,['deviceId','eventId','fingerprint','trustRevisionBefore',
       'trustRevisionAfter','trustRevision'])||!UUID.test(receipt.deviceId??'')||
     !UUID.test(receipt.eventId??'')||!HEX64.test(receipt.fingerprint??'')||
     !Number.isSafeInteger(receipt.trustRevisionBefore)||receipt.trustRevisionBefore<0||
     !Number.isSafeInteger(receipt.trustRevisionAfter)||
     receipt.trustRevisionAfter!==receipt.trustRevisionBefore+1||
     !Number.isSafeInteger(receipt.trustRevision)||receipt.trustRevision<receipt.trustRevisionAfter){
    throw new Error('Invalid approval receipt');
  }
}

function writeBoundEnvelope(directory,envelope){
  const filename=path.join(directory,KEY_FILE);
  const temp=path.join(directory,BINDING_TEMP_PREFIX+randomUUID()+'.tmp');
  const persisted={version:3,encoding:envelope.encoding,fingerprint:envelope.fingerprint,
    key:envelope.key,deviceBinding:envelope.deviceBinding};
  const bytes=Buffer.from(JSON.stringify(persisted)+'\n');
  if(bytes.length>MAX_FILE_BYTES)throw new Error('Device identity envelope exceeds limit');
  let fd,renameAttempted=false;
  try{
    fd=openSync(temp,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|
      (constants.O_NOFOLLOW??0),0o600);
    let offset=0;
    while(offset<bytes.length){
      const count=writeSync(fd,bytes,offset,bytes.length-offset);
      if(count<=0)throw new Error('Short identity binding write');
      offset+=count;
    }
    fsyncSync(fd);closeSync(fd);fd=undefined;
    const current=lstatSync(filename);
    if(!current.isFile()||current.isSymbolicLink()||current.nlink!==1||
       current.ino!==envelope._expectedInode||current.dev!==envelope._expectedDevice){
      throw new Error('Identity changed during binding');
    }
    renameAttempted=true;
    renameSync(temp,filename);
    syncDirectory(directory);
    return persisted;
  }catch(error){
    if(fd!==undefined)closeSync(fd);
    try{unlinkSync(temp);}catch{}
    if(renameAttempted)error.code='IDENTITY_BINDING_UNCERTAIN';
    throw error;
  }
}

// Persist the result of the existing Owner-approved pairing flow next to the
// agent's Ed25519 key. This function cannot create trust: the caller must pass
// the durable I2 approval receipt, which the Gateway independently rechecks.
export function bindApprovedDeviceIdentity({
  directory=storageFolder(process.platform),platform=process.platform,machineBinding,
}={}){
  if(!['linux','darwin','win32'].includes(platform)||platform!==process.platform){
    throw new Error('Identity store cannot impersonate a platform');
  }
  const binding=machineBinding;
  if(!binding||!sameKeys(binding,['deviceId','clientId','fingerprint','approvalEventId',
      'bindingEventId','bindingRevision','ownerId','ownerDigest','trustRevisionBefore',
      'trustRevisionAfter','trustRevision'])||!validBinding(binding,binding.fingerprint)){
    throw new TypeError('Verified durable machine binding required');
  }
  validateApprovalReceipt({deviceId:binding.deviceId,eventId:binding.approvalEventId,
    fingerprint:binding.fingerprint,trustRevisionBefore:binding.trustRevisionBefore,
    trustRevisionAfter:binding.trustRevisionAfter,trustRevision:binding.trustRevision});
  assertStoreDir(directory,platform);
  assertNoInterruptedBinding(directory);
  const lockPath=path.join(directory,BINDING_LOCK),token=randomUUID()+'\n';
  let lockFd,lockOwner,preserveLock=false;
  try{
    if(platform==='linux'&&typeof process.getuid==='function'){
      lockOwner=createDurableProcessLock(directory,BINDING_LOCK,'device-identity-binding');
    }else{
      lockFd=openSync(lockPath,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|
        (constants.O_NOFOLLOW??0),0o600);
      writeFileSync(lockFd,token,'utf8');fsyncSync(lockFd);syncDirectory(directory);
    }
  }catch(error){
    if(lockFd!==undefined)closeSync(lockFd);
    if(error?.code==='EEXIST'||error?.code==='BINDING_BUSY')throw new Error('Identity binding is locked; operator recovery required');
    throw error;
  }
  try{
    const current=readEnvelope(directory,platform);
    if(current.identity.fingerprint!==binding.fingerprint){
      throw new Error('Approval receipt does not bind this device identity');
    }
    const previousBinding=current.identity.deviceBinding??current.identity.legacyDeviceBinding;
    if(previousBinding){
      if(JSON.stringify(current.identity.deviceBinding)===JSON.stringify(binding))return current.identity;
      const previous=previousBinding;
      if(previous.bindingEventId===undefined&&previous.deviceId===binding.deviceId&&
         previous.clientId===binding.clientId&&previous.fingerprint===binding.fingerprint&&
         previous.approvalEventId===binding.approvalEventId&&
         previous.trustRevisionBefore===binding.trustRevisionBefore&&
         previous.trustRevisionAfter===binding.trustRevisionAfter&&
         previous.trustRevision===binding.trustRevision){
        const envelope={...current.envelope,version:3,deviceBinding:binding,
          _expectedInode:current.stat.ino,_expectedDevice:current.stat.dev};
        try{writeBoundEnvelope(directory,envelope);preserveLock=true;}
        catch(error){if(error?.code==='IDENTITY_BINDING_UNCERTAIN')preserveLock=true;throw error;}
        const upgraded=readEnvelope(directory,platform).identity;
        preserveLock=false;
        return upgraded;
      }
      throw new Error('Device identity is already bound to another approval');
    }
    const envelope={...current.envelope,version:3,deviceBinding:binding,
      _expectedInode:current.stat.ino,_expectedDevice:current.stat.dev};
    try{writeBoundEnvelope(directory,envelope);preserveLock=true;}
    catch(error){if(error?.code==='IDENTITY_BINDING_UNCERTAIN')preserveLock=true;throw error;}
    const bound=readEnvelope(directory,platform).identity;
    preserveLock=false;
    return bound;
  }finally{
    if(preserveLock){
      // The envelope rename or its directory durability/readback is uncertain.
      // Leave the process lock as evidence; after this process exits, recovery
      // must verify the Gateway binding before an operator can clear it.
    }else if(lockOwner){
      try{removeOwnedDurableProcessLock({directory,name:BINDING_LOCK,owner:lockOwner});}
      catch(error){throw new Error('Identity binding commit or lock release is uncertain; operator recovery required',{cause:error});}
    }else{
      try{
        const stat=lstatSync(lockPath);
        if(!stat.isFile()||stat.isSymbolicLink()||stat.nlink!==1||
           stat.uid!==(typeof process.getuid==='function'?process.getuid():stat.uid)||
           readFileSync(lockPath,'utf8')!==token){
          throw new Error('Identity binding lock ownership changed');
        }
        unlinkSync(lockPath);syncDirectory(directory);
      }catch(error){throw new Error('Identity binding commit or lock release is uncertain; operator recovery required',{cause:error});}
    }
    if(lockFd!==undefined)closeSync(lockFd);
  }
}

export function loadOrCreateDeviceIdentity({
  directory=storageFolder(process.platform),platform=process.platform,
} = {}) {
  if (!['linux','darwin','win32'].includes(platform) || platform!==process.platform) {
    throw new Error('Identity store cannot impersonate a platform');
  }
  assertStoreDir(directory,platform);
  assertNoInterruptedBinding(directory);
  const filename=path.join(directory,KEY_FILE);
  const nofollow=constants.O_NOFOLLOW??0;
  let fd;
  try {
    fd=openSync(filename,constants.O_RDONLY|nofollow);
  } catch (error) {
    if (error?.code!=='ENOENT') throw error;
    // Generate a locally owned identity. A second contender wins atomically
    // with O_EXCL; the loser must load that existing winner.
    const {privateKey}=generateKeyPairSync('ed25519');
    const privateDer=privateKey.export({type:'pkcs8',format:'der'});
    const identity=createPairingIdentityFromPkcs8(privateDer);
    const stored=platform==='win32'?powershellDpapi('protect',privateDer):Buffer.from(privateDer);
    privateDer.fill(0);
    const envelope=JSON.stringify({version:1,
      encoding:platform==='win32'?'dpapi-current-user':'pkcs8-owner-file',
      fingerprint:identity.fingerprint,key:stored.toString('base64')})+'\n';
    stored.fill(0);
    try {
      fd=openSync(filename,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|nofollow,0o600);
      writeFileSync(fd,envelope,'utf8');
      fsyncSync(fd);
      closeSync(fd);
      fd=undefined;
      syncDirectory(directory);
      // File is complete before this process considers it usable.
      return loadOrCreateDeviceIdentity({directory,platform});
    } catch (e) {
      if(fd!==undefined)closeSync(fd);
      if (e?.code==='EEXIST')return loadOrCreateDeviceIdentity({directory,platform});
      throw e;
    }
  }
  try {
    const st=fstatSync(fd);
    if (!st.isFile() || st.size <= 0 || st.size > MAX_FILE_BYTES ||
        (platform !== 'win32' && (st.mode & FILE_MASK))) {
      throw new Error('Unsafe identity file');
    }
    const identity=parsePersisted(readFileSync(fd,'utf8'),platform);
    closeSync(fd);fd=undefined;
    // A binding lock or temporary file left by a crashed writer is evidence of
    // an incomplete transition. Never use the pre-transition envelope then.
    assertNoInterruptedBinding(directory);
    return identity;
  } finally {
    if(fd!==undefined)closeSync(fd);
  }
}
