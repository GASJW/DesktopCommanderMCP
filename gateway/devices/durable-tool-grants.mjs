import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import {
  constants, closeSync, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync,
  readFileSync, readdirSync, renameSync, writeSync,
} from 'node:fs';
import { toolArgumentsDigest } from './tool-grant-capability.mjs';
import { createDurableProcessLock, inspectDurableProcessLock,
  removeOwnedDurableProcessLock } from '../common/durable-process-lock.mjs';
import { removeDeadDurableProcessLock } from '../common/durable-process-lock.mjs';

// Development candidate: versioned Owner/device/tool grants, isolated from the
// I2 trust snapshot and audit WAL. Missing policy initializes to an empty policy.
const FILE='tool-grants-v1.json';
const INITIALIZED='.tool-grants-initialized';
const INITIALIZED_BYTES=Buffer.from('VPSC-G7-DURABLE-TOOL-GRANTS-v1\n');
const DOMAIN='VPSC-G7-DURABLE-TOOL-GRANTS-v1\n';
const EMPTY_HASH='0'.repeat(64);
const MAX_BYTES=4*1024*1024;
const MAX_RECORDS=20_000;
const MAX_GRANTS=2048;
const MAX_PERMITS=256;
const MAX_LINE=32*1024;
const GATE='.tool-grants-operation.lock';
const WRITER='.tool-grants-writer.lock';
const RECOVERY_LOCK='.tool-grants-recovery.lock';
const PERMIT_PREFIX='.tool-grant-permit-';
const TEMP_PREFIX='.tool-grants-';
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HEX64=/^[a-f0-9]{64}$/;
const TOOLS=new Set(['read_file','list_directory','write_file','list_processes','run_command']);
const PERMIT_TTL_MS=30_000;
const fail=(code,message)=>Object.assign(new Error(message),{code});
const sameKeys=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&
  Object.getPrototypeOf(value)===Object.prototype&&
  Object.keys(value).sort().join(',')===[...keys].sort().join(',');

function canonical(value,seen=new Set()){
  if(value===null||typeof value==='string'||typeof value==='boolean')return value;
  if(typeof value==='number'&&Number.isFinite(value))return value;
  if(Array.isArray(value)){
    if(seen.has(value))throw fail('INVALID','Circular policy value');
    seen.add(value);const result=value.map(item=>canonical(item,seen));seen.delete(value);return result;
  }
  if(value&&typeof value==='object'&&Object.getPrototypeOf(value)===Object.prototype){
    if(seen.has(value))throw fail('INVALID','Circular policy value');
    seen.add(value);
    const result=Object.fromEntries(Object.keys(value).sort().map(key=>[
      key,canonical(value[key],seen),
    ]));
    seen.delete(value);return result;
  }
  throw fail('INVALID','Policy data must contain only plain JSON values');
}
function freezeDeep(value){
  if(value&&typeof value==='object'&&!Object.isFrozen(value)){
    for(const child of Object.values(value))freezeDeep(child);
    Object.freeze(value);
  }
  return value;
}
function digest(value){return createHash('sha256').update(value).digest('hex');}
function checkDirectory(directory,{create=false}={}){
  if(process.platform!=='linux'||typeof process.getuid!=='function'){
    throw fail('UNSUPPORTED','Durable tool grants require Linux process identity evidence');
  }
  if(typeof directory!=='string'||!path.isAbsolute(directory)||
     path.normalize(directory)!==directory||directory===path.parse(directory).root){
    throw new TypeError('Grant directory must be a normalized absolute path');
  }
  let cursor=path.parse(directory).root;
  for(const component of directory.slice(cursor.length).split(path.sep)){
    cursor=path.join(cursor,component);
    let st;
    try{st=lstatSync(cursor);}catch(error){
      if(error?.code!=='ENOENT')throw error;
      if(cursor!==directory||!create)throw fail('POLICY_UNAVAILABLE','Grant directory is missing');
      mkdirSync(cursor,{mode:0o700});st=lstatSync(cursor);
    }
    if(!st.isDirectory()||st.isSymbolicLink())throw fail('UNSAFE_STORAGE','Unsafe grant directory ancestor');
    if(cursor!==directory&&(st.mode&0o022)!==0&&!(st.uid===0&&(st.mode&0o1000)!==0)){
      throw fail('UNSAFE_STORAGE','Writable grant ancestor is not root-owned sticky');
    }
  }
  const final=lstatSync(directory);
  if(final.uid!==process.getuid()||(final.mode&0o7777)!==0o700){
    throw fail('UNSAFE_STORAGE','Grant directory must be owned by this user and mode 0700');
  }
  return directory;
}
function syncDirectory(directory){
  const fd=openSync(directory,constants.O_RDONLY|(constants.O_DIRECTORY??0)|
    (constants.O_NOFOLLOW??0));
  try{fsyncSync(fd);}finally{closeSync(fd);}
}
function tempEvidence(directory){
  const names=readdirSync(directory).filter(name=>name.startsWith(TEMP_PREFIX)&&name.endsWith('.tmp'));
  if(names.length)throw fail('POLICY_CORRUPT','Interrupted policy snapshot temporary file requires reconciliation');
  return names;
}
function snapshotPath(directory){return path.join(directory,FILE);}
function initializedEvidence(directory){
  const filename=path.join(directory,INITIALIZED);
  let named;
  try{named=lstatSync(filename);}catch(error){
    if(error?.code==='ENOENT')return false;
    throw error;
  }
  if(!named.isFile()||named.isSymbolicLink()||named.nlink!==1||named.uid!==process.getuid()||
     (named.mode&0o7777)!==0o600||named.size!==INITIALIZED_BYTES.length){
    throw fail('POLICY_CORRUPT','Unsafe policy initialization marker');
  }
  const fd=openSync(filename,constants.O_RDONLY|(constants.O_NOFOLLOW??0));
  try{
    const opened=fstatSync(fd);
    if(!opened.isFile()||opened.nlink!==1||opened.uid!==process.getuid()||
       opened.ino!==named.ino||opened.dev!==named.dev||opened.size!==named.size||
       (opened.mode&0o7777)!==0o600||!readFileSync(fd).equals(INITIALIZED_BYTES)){
      throw fail('POLICY_CORRUPT','Policy initialization marker is invalid');
    }
  }finally{closeSync(fd);}
  return true;
}
function writeInitializedMarker(directory){
  const filename=path.join(directory,INITIALIZED);
  const fd=openSync(filename,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|
    (constants.O_NOFOLLOW??0),0o600);
  try{
    let offset=0;
    while(offset<INITIALIZED_BYTES.length){
      const count=writeSync(fd,INITIALIZED_BYTES,offset,INITIALIZED_BYTES.length-offset);
      if(count<=0)throw fail('POLICY_WRITE_FAILED','Short policy initialization marker write');
      offset+=count;
    }
    fsyncSync(fd);
  }finally{closeSync(fd);}
  syncDirectory(directory);
}
function validateRecordHash(record){
  const expected=digest(DOMAIN+JSON.stringify({sequence:record.sequence,
    previousHash:record.previousHash,event:record.event}));
  return expected===record.hash;
}
function validateRoot(value){
  if(typeof value!=='string'||value.length===0||value.length>4096||value.includes('\0')||
     !path.isAbsolute(value)||path.resolve(value)!==value||value===path.parse(value).root||
     value.startsWith('//'))throw fail('INVALID','Tool grant root must be a normalized non-root absolute path');
  return value;
}
function boundedInt(value,min,max){return Number.isSafeInteger(value)&&value>=min&&value<=max;}
function validateGrantInput(input){
  if(!sameKeys(input,['ownerDigest','deviceId','fingerprint','tool','scope','constraints'])||
     !HEX64.test(input.ownerDigest??'')||!UUID.test(input.deviceId??'')||
     !HEX64.test(input.fingerprint??'')||!TOOLS.has(input.tool)){
    throw fail('INVALID','Invalid Owner/device/tool grant identity');
  }
  let scope,constraints;
  if(['read_file','list_directory','write_file'].includes(input.tool)){
    if(!sameKeys(input.scope,['root']))throw fail('INVALID','File tool scope must contain only root');
    scope={root:validateRoot(input.scope.root)};
  }else if(input.tool==='run_command'){
    if(!sameKeys(input.scope,['root','profile'])||input.scope.profile!=='count_lines'){
      throw fail('INVALID','run_command scope must name the fixed count_lines profile');
    }
    scope={root:validateRoot(input.scope.root),profile:'count_lines'};
  }else{
    if(!sameKeys(input.scope,[]))throw fail('INVALID','list_processes scope must be empty');
    scope={};
  }
  switch(input.tool){
    case 'read_file':
      if(!sameKeys(input.constraints,['maxBytes','maxLength','maxOffset'])||
         !boundedInt(input.constraints.maxBytes,1,65_536)||
         !boundedInt(input.constraints.maxLength,1,1_000)||
         !boundedInt(input.constraints.maxOffset,0,100_000)){
        throw fail('INVALID','Invalid bounded read_file constraints');
      }
      constraints={maxBytes:input.constraints.maxBytes,maxLength:input.constraints.maxLength,
        maxOffset:input.constraints.maxOffset};break;
    case 'list_directory':
      if(!sameKeys(input.constraints,['maxDepth','maxEntries'])||
         !boundedInt(input.constraints.maxDepth,0,2)||
         !boundedInt(input.constraints.maxEntries,1,200)){
        throw fail('INVALID','Invalid bounded list_directory constraints');
      }
      constraints={maxDepth:input.constraints.maxDepth,maxEntries:input.constraints.maxEntries};break;
    case 'write_file':
      if(!sameKeys(input.constraints,['maxBytes'])||
         !boundedInt(input.constraints.maxBytes,1,65_536)){
        throw fail('INVALID','Invalid bounded write_file constraints');
      }
      constraints={maxBytes:input.constraints.maxBytes};break;
    case 'list_processes':
      if(!sameKeys(input.constraints,['maxJobs'])||!boundedInt(input.constraints.maxJobs,1,32)){
        throw fail('INVALID','Invalid bounded list_processes constraints');
      }
      constraints={maxJobs:input.constraints.maxJobs};break;
    case 'run_command':
      if(!sameKeys(input.constraints,['maxOutputBytes','maxRuntimeMs','profile'])||
         !boundedInt(input.constraints.maxOutputBytes,1_024,16_384)||
         !boundedInt(input.constraints.maxRuntimeMs,100,10_000)||
         input.constraints.profile!=='count_lines'){
        throw fail('INVALID','Invalid bounded run_command constraints');
      }
      constraints={maxOutputBytes:input.constraints.maxOutputBytes,
        maxRuntimeMs:input.constraints.maxRuntimeMs,profile:'count_lines'};break;
  }
  return canonical({ownerDigest:input.ownerDigest,deviceId:input.deviceId.toLowerCase(),
    fingerprint:input.fingerprint,tool:input.tool,scope,constraints});
}
function validateMutationOptions(options){
  if(!sameKeys(options,['expectedRevision','eventId'])||
     !Number.isSafeInteger(options.expectedRevision)||options.expectedRevision<0||
     !UUID.test(options.eventId??''))throw fail('INVALID','Expected policy revision and UUID eventId are required');
}
function validateApproval(input){
  const receipt=input.approvalReceipt;
  if(!sameKeys(receipt,['deviceId','eventId','fingerprint','trustRevision',
       'trustRevisionAfter','trustRevisionBefore'])||receipt.deviceId!==input.deviceId||
     receipt.fingerprint!==input.fingerprint||!UUID.test(receipt.eventId??'')||
     !Number.isSafeInteger(receipt.trustRevisionBefore)||receipt.trustRevisionBefore<0||
     !Number.isSafeInteger(receipt.trustRevisionAfter)||
     receipt.trustRevisionAfter!==receipt.trustRevisionBefore+1||
     !Number.isSafeInteger(receipt.trustRevision)||receipt.trustRevision<receipt.trustRevisionAfter){
    throw fail('DENIED','Durable approval receipt does not bind this device identity');
  }
  return {eventId:receipt.eventId,trustRevisionBefore:receipt.trustRevisionBefore,
    trustRevisionAfter:receipt.trustRevisionAfter,trustRevision:receipt.trustRevision};
}
function insideScope(root,target){
  const relative=path.relative(root,target);
  return relative===''||relative!=='..'&&!relative.startsWith('..'+path.sep)&&!path.isAbsolute(relative);
}
function validateArguments(tool,args,grant){
  if(!args||Object.getPrototypeOf(args)!==Object.prototype){
    throw fail('DENIED','Tool arguments must be a plain object');
  }
  const exact=(required,optional=[])=>{
    const keys=Object.keys(args);
    return required.every(key=>Object.hasOwn(args,key))&&
      keys.every(key=>required.includes(key)||optional.includes(key));
  };
  const pathIsGranted=({allowRoot=false}={})=>typeof args.path==='string'&&args.path.length<=4096&&
    !args.path.includes('\0')&&path.isAbsolute(args.path)&&path.resolve(args.path)===args.path&&
    !args.path.startsWith('//')&&insideScope(grant.scope.root,args.path)&&
    (allowRoot||args.path!==grant.scope.root);
  if(tool==='read_file'){
    if(!exact(['path'],['offset','length'])||!pathIsGranted()||
       args.offset!==undefined&&!boundedInt(args.offset,0,100_000)||
       args.length!==undefined&&!boundedInt(args.length,1,1_000))throw fail('DENIED','read_file arguments exceed grant');
    const offset=args.offset??0,length=args.length??1_000;
    if(offset>grant.constraints.maxOffset||length>grant.constraints.maxLength){
      throw fail('DENIED','read_file parameters exceed grant constraints');
    }
    return;
  }
  if(tool==='list_directory'){
    if(!exact(['path'],['depth'])||!pathIsGranted({allowRoot:true})||
       args.depth!==undefined&&!boundedInt(args.depth,0,2))throw fail('DENIED','list_directory arguments exceed grant');
    if((args.depth??2)>grant.constraints.maxDepth){
      throw fail('DENIED','Directory depth exceeds grant constraints');
    }
    return;
  }
  if(tool==='write_file'){
    if(!exact(['path','content','mode'])||!pathIsGranted({allowRoot:true})||args.mode!=='create'||
       typeof args.content!=='string'||Buffer.byteLength(args.content,'utf8')>65_536||
       Buffer.byteLength(args.content,'utf8')>grant.constraints.maxBytes){
      throw fail('DENIED','write_file arguments exceed grant');
    }
    return;
  }
  if(tool==='list_processes'){
    if(!exact([]))throw fail('DENIED','list_processes accepts no arguments');
    return;
  }
  if(tool==='run_command'){
    if(!exact(['path','profile'])||!pathIsGranted()||args.profile!=='count_lines'||
       args.profile!==grant.scope.profile||args.profile!==grant.constraints.profile){
      throw fail('DENIED','run_command profile or path exceeds grant');
    }
    return;
  }
  throw fail('DENIED','No policy exists for this tool');
}
function validateAuthorizeInput(input){
  if(!sameKeys(input,['ownerDigest','deviceId','fingerprint','tool','arguments','requestId','approvalReceipt'])||
     !HEX64.test(input.ownerDigest??'')||!UUID.test(input.deviceId??'')||
     !HEX64.test(input.fingerprint??'')||!TOOLS.has(input.tool)||!UUID.test(input.requestId??'')){
    throw fail('DENIED','Invalid tool authorization identity');
  }
  return {ownerDigest:input.ownerDigest,deviceId:input.deviceId.toLowerCase(),
    fingerprint:input.fingerprint,tool:input.tool,requestId:input.requestId.toLowerCase(),
    arguments:canonical(input.arguments),approval:validateApproval(input)};
}
function assertPrivateSnapshot(filename){
  let named;
  try{named=lstatSync(filename);}catch(error){
    if(error?.code==='ENOENT')throw fail('POLICY_UNAVAILABLE','Durable policy snapshot is missing');
    throw error;
  }
  if(!named.isFile()||named.isSymbolicLink()||named.nlink!==1||named.uid!==process.getuid()||
     (named.mode&0o7777)!==0o600||named.size<=0||named.size>MAX_BYTES){
    throw fail('POLICY_CORRUPT','Unsafe durable policy snapshot');
  }
  const fd=openSync(filename,constants.O_RDONLY|(constants.O_NOFOLLOW??0));
  try{
    const opened=fstatSync(fd);
    if(!opened.isFile()||opened.nlink!==1||opened.uid!==process.getuid()||
       opened.ino!==named.ino||opened.dev!==named.dev||opened.size!==named.size||
       (opened.mode&0o7777)!==0o600)throw fail('POLICY_CORRUPT','Policy snapshot changed during read');
    return readFileSync(fd);
  }finally{closeSync(fd);}
}
function parseSnapshot(directory){
  if(!initializedEvidence(directory))throw fail('POLICY_CORRUPT','Policy initialization evidence is missing');
  tempEvidence(directory);
  const bytes=assertPrivateSnapshot(snapshotPath(directory));
  let value;
  try{value=JSON.parse(bytes.toString('utf8'));}
  catch{throw fail('POLICY_CORRUPT','Durable policy snapshot is invalid JSON');}
  if(!Buffer.from(JSON.stringify(canonical(value))+'\n').equals(bytes)){
    throw fail('POLICY_CORRUPT','Policy snapshot is not canonical or is truncated');
  }
  if(!sameKeys(value,['version','revision','records','grants'])||value.version!==1||
     !Number.isSafeInteger(value.revision)||value.revision<0||
     !Array.isArray(value.records)||value.records.length>MAX_RECORDS||
     !Array.isArray(value.grants)||value.grants.length>MAX_GRANTS){
    throw fail('POLICY_CORRUPT','Invalid versioned policy snapshot schema');
  }
  let revision=0,previousHash=EMPTY_HASH;
  const grants=new Map(),events=new Set(),decisions=new Set(),requests=new Set();
  for(let index=0;index<value.records.length;index++){
    const record=value.records[index];
    if(!sameKeys(record,['sequence','previousHash','hash','event'])||
       record.sequence!==index+1||record.previousHash!==previousHash||
       !HEX64.test(record.hash??'')||!validateRecordHash(record)){
      throw fail('POLICY_CORRUPT','Policy record hash chain is invalid');
    }
    previousHash=record.hash;
    const event=record.event;
    if(!event||typeof event!=='object'||Array.isArray(event))throw fail('POLICY_CORRUPT','Invalid policy event');
    if(event.type==='grant'){
      if(!sameKeys(event,['type','revision','eventId','grant'])||
         !UUID.test(event.eventId??'')||events.has(event.eventId)||
         event.revision!==revision+1||grants.size>=MAX_GRANTS){
        throw fail('POLICY_CORRUPT','Invalid policy grant event');
      }
      if(!sameKeys(event.grant,['ownerDigest','deviceId','fingerprint','tool','scope','constraints','grantId'])){
        throw fail('POLICY_CORRUPT','Invalid policy grant payload');
      }
      const {grantId,...grantInput}=event.grant;
      const input=validateGrantInput(grantInput);
      if(!UUID.test(grantId??'')||grants.has(grantId)||
         Array.from(grants.values()).some(grant=>grant.active&&grant.ownerDigest===input.ownerDigest&&
           grant.deviceId===input.deviceId&&grant.tool===input.tool)){
        throw fail('POLICY_CORRUPT','Duplicate active policy grant');
      }
      events.add(event.eventId);revision=event.revision;
      grants.set(grantId,{...input,grantId,
        revision,eventId:event.eventId,active:true});
      continue;
    }
    if(event.type==='revoke'){
      if(!sameKeys(event,['type','revision','eventId','grantId'])||
         !UUID.test(event.eventId??'')||events.has(event.eventId)||
         event.revision!==revision+1||!UUID.test(event.grantId??'')){
        throw fail('POLICY_CORRUPT','Invalid policy revoke event');
      }
      const grant=grants.get(event.grantId);
      if(!grant?.active)throw fail('POLICY_CORRUPT','Policy revoke has no active grant');
      events.add(event.eventId);revision=event.revision;
      grants.set(event.grantId,{...grant,active:false,revokedRevision:revision,
        revokedEventId:event.eventId});
      continue;
    }
    if(event.type==='authorize'){
      if(!sameKeys(event,['type','decisionId','claims'])||
         !UUID.test(event.decisionId??'')||decisions.has(event.decisionId)){
        throw fail('POLICY_CORRUPT','Invalid or repeated authorization event');
      }
      const claims=event.claims;
      if(!validClaims(claims)||claims.decisionId!==event.decisionId||
         claims.policyRevision!==revision||requests.has(claims.requestId)){
        throw fail('POLICY_CORRUPT','Authorization claims contradict policy history');
      }
      const grant=grants.get(claims.grantId);
      if(!grant?.active||!claimsMatchGrant(claims,grant)){
        throw fail('POLICY_CORRUPT','Authorization event has no matching active grant');
      }
      decisions.add(event.decisionId);requests.add(claims.requestId);
      continue;
    }
    throw fail('POLICY_CORRUPT','Unknown durable policy event');
  }
  if(value.revision!==revision)throw fail('POLICY_CORRUPT','Policy revision does not match history');
  const derived=Array.from(grants.values()).sort((a,b)=>a.grantId.localeCompare(b.grantId));
  if(JSON.stringify(canonical(value.grants))!==JSON.stringify(canonical(derived))){
    throw fail('POLICY_CORRUPT','Policy snapshot grants contradict hash-chained history');
  }
  return {version:1,revision,records:value.records,grants:derived,
    decisions,requests,events};
}
function validClaims(claims){
  if(!sameKeys(claims,['version','decisionId','requestId','ownerDigest','deviceId','fingerprint',
      'tool','argumentsDigest','grantId','policyRevision','scope','constraints','approvalEventId',
      'approvalTrustRevisionBefore','approvalTrustRevisionAfter','trustRevision','issuedAt','expiresAt'])||
     claims.version!==1||!UUID.test(claims.decisionId??'')||!UUID.test(claims.requestId??'')||
     !HEX64.test(claims.ownerDigest??'')||!UUID.test(claims.deviceId??'')||
     !HEX64.test(claims.fingerprint??'')||!TOOLS.has(claims.tool)||
     !HEX64.test(claims.argumentsDigest??'')||!UUID.test(claims.grantId??'')||
     !Number.isSafeInteger(claims.policyRevision)||claims.policyRevision<1||
     !UUID.test(claims.approvalEventId??'')||
     !Number.isSafeInteger(claims.approvalTrustRevisionBefore)||claims.approvalTrustRevisionBefore<0||
     claims.approvalTrustRevisionAfter!==claims.approvalTrustRevisionBefore+1||
     !Number.isSafeInteger(claims.trustRevision)||claims.trustRevision<claims.approvalTrustRevisionAfter||
     !Number.isSafeInteger(claims.issuedAt)||!Number.isSafeInteger(claims.expiresAt)||
     claims.expiresAt<=claims.issuedAt||claims.expiresAt-claims.issuedAt>PERMIT_TTL_MS){return false;}
  try{
    const grant={ownerDigest:claims.ownerDigest,deviceId:claims.deviceId,
      fingerprint:claims.fingerprint,tool:claims.tool,scope:claims.scope,constraints:claims.constraints};
    const normalized=validateGrantInput(grant);
    return JSON.stringify(normalized)===JSON.stringify(canonical(grant));
  }catch{return false;}
}
function claimsMatchGrant(claims,grant){
  return claims.grantId===grant.grantId&&claims.ownerDigest===grant.ownerDigest&&
    claims.deviceId===grant.deviceId&&claims.fingerprint===grant.fingerprint&&
    claims.tool===grant.tool&&JSON.stringify(canonical(claims.scope))===JSON.stringify(grant.scope)&&
    JSON.stringify(canonical(claims.constraints))===JSON.stringify(grant.constraints);
}
function serializeSnapshot(state){
  const value=canonical({version:1,revision:state.revision,records:state.records,
    grants:state.grants.slice().sort((a,b)=>a.grantId.localeCompare(b.grantId))});
  const bytes=Buffer.from(JSON.stringify(value)+'\n');
  if(bytes.length>MAX_BYTES)throw fail('POLICY_FULL','Durable tool grant store is full');
  return bytes;
}
function persistSnapshot(directory,state){
  if(state.records.length>MAX_RECORDS)throw fail('POLICY_FULL','Durable tool grant record limit reached');
  const bytes=serializeSnapshot(state),tempName=TEMP_PREFIX+randomUUID().replaceAll('-','').slice(0,24)+'.tmp';
  const tempPath=path.join(directory,tempName);
  let fd;
  try{
    fd=openSync(tempPath,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|
      (constants.O_NOFOLLOW??0),0o600);
    let offset=0;
    while(offset<bytes.length){
      const count=writeSync(fd,bytes,offset,bytes.length-offset);
      if(count<=0)throw fail('POLICY_WRITE_FAILED','Short policy snapshot write');
      offset+=count;
    }
    fsyncSync(fd);closeSync(fd);fd=undefined;
    renameSync(tempPath,snapshotPath(directory));
    syncDirectory(directory);
  }catch(error){
    if(fd!==undefined)closeSync(fd);
    if(error?.code==='POLICY_FULL')throw error;
    throw fail('POLICY_WRITE_FAILED','Durable policy snapshot could not be committed');
  }
}
function appendRecord(state,event){
  if(state.records.length>=MAX_RECORDS)throw fail('POLICY_FULL','Durable tool grant record limit reached');
  const previousHash=state.records.at(-1)?.hash??EMPTY_HASH;
  const record={sequence:state.records.length+1,previousHash,event:canonical(event)};
  record.hash=digest(DOMAIN+JSON.stringify({sequence:record.sequence,previousHash,event:record.event}));
  if(Buffer.byteLength(JSON.stringify(canonical(record))+'\n')>MAX_LINE){
    throw fail('POLICY_FULL','Policy record exceeds its size limit');
  }
  state.records.push(record);
}
function lockNames(directory){return readdirSync(directory);}
function inspectLock(directory,name){return inspectDurableProcessLock(directory,name);}
function assertMarkerState(directory,{allowActivePermits=true,ignoreGate=false}={}){
  for(const name of lockNames(directory)){
    if(name===GATE||name===WRITER||name===RECOVERY_LOCK||name.startsWith(PERMIT_PREFIX)){
      if(ignoreGate&&name===GATE)continue;
      const evidence=inspectLock(directory,name);
      if(!evidence.present||evidence.status==='unknown'||evidence.status==='dead'){
        throw fail('STALE_LOCK','Policy lock is stale or cannot be verified; operator reconciliation required');
      }
      if(name===RECOVERY_LOCK){
        throw fail('POLICY_BUSY','Policy lock recovery is active; new operations are blocked');
      }
      if(name===GATE||name===WRITER||name.startsWith(PERMIT_PREFIX)&&!allowActivePermits){
        throw fail('POLICY_BUSY',name.startsWith(PERMIT_PREFIX)
          ?'Active permit lock prevents policy mutation'
          :'Policy has an active operation lock');
      }
    }
  }
}
function assertNoRecoveryLock(directory){
  const evidence=inspectLock(directory,RECOVERY_LOCK);
  if(!evidence.present)return;
  if(evidence.status==='active')throw fail('POLICY_BUSY','Policy lock recovery is active');
  throw fail('STALE_LOCK','Policy recovery lock is stale or cannot be verified');
}
function acquireGate(directory){
  assertNoRecoveryLock(directory);
  let owner;
  try{owner=createDurableProcessLock(directory,GATE,'tool-grants-operation');}
  catch{throw fail('POLICY_BUSY','Tool grant policy operation is locked; no lock was stolen');}
  try{assertNoRecoveryLock(directory);}
  catch(error){releaseOwned(directory,GATE,owner);throw error;}
  return owner;
}
function releaseOwned(directory,name,owner){
  removeOwnedDurableProcessLock({directory,name,owner});
}
function addEvent(state,event){appendRecord(state,event);}
function checkExpectedRevision(state,expectedRevision){
  if(state.revision!==expectedRevision)throw fail('REVISION_CONFLICT','Tool grant policy revision conflict');
}
function persistMutation(directory,gateOwner,operation){
  let writerOwner=null,retained=false;
  try{
    assertMarkerState(directory,{allowActivePermits:false,ignoreGate:true});
    writerOwner=createDurableProcessLock(directory,WRITER,'tool-grants-writer');
    const result=operation();
    return result;
  }catch(error){
    if(error?.code==='POLICY_WRITE_FAILED'||error?.code==='POLICY_FULL'&&error.message.includes('snapshot'))retained=true;
    throw error;
  }finally{
    if(!retained){
      if(writerOwner)releaseOwned(directory,WRITER,writerOwner);
      releaseOwned(directory,GATE,gateOwner);
    }
  }
}
function initialSnapshot(){return {version:1,revision:0,records:[],grants:[]};}
function initialize(directory){
  tempEvidence(directory);
  let snapshotMissing=false;
  try{lstatSync(snapshotPath(directory));}
  catch(error){if(error?.code==='ENOENT')snapshotMissing=true;else throw error;}
  const isInitialized=initializedEvidence(directory);
  if(!snapshotMissing&&!isInitialized){
    throw fail('POLICY_CORRUPT','Policy initialization evidence is missing');
  }
  if(snapshotMissing&&isInitialized){
    throw fail('POLICY_CORRUPT','Initialized policy snapshot is missing');
  }
  if(!snapshotMissing){
    assertMarkerState(directory,{allowActivePermits:true});
    parseSnapshot(directory);
    return;
  }
  const gateOwner=acquireGate(directory);
  let retained=false;
  try{
    assertMarkerState(directory,{allowActivePermits:true,ignoreGate:true});
    tempEvidence(directory);
    let nowMissing=false;
    try{lstatSync(snapshotPath(directory));}
    catch(error){if(error?.code==='ENOENT')nowMissing=true;else throw error;}
    const nowInitialized=initializedEvidence(directory);
    if(!nowMissing&&!nowInitialized)throw fail('POLICY_CORRUPT','Policy initialization evidence is missing');
    if(nowMissing&&nowInitialized)throw fail('POLICY_CORRUPT','Initialized policy snapshot is missing');
    if(nowMissing){
      if(lockNames(directory).some(name=>name.startsWith(PERMIT_PREFIX)||name===WRITER)){
        throw fail('POLICY_CORRUPT','Policy snapshot is missing while durable lock evidence exists');
      }
      persistSnapshot(directory,initialSnapshot());
      writeInitializedMarker(directory);
    }
    parseSnapshot(directory);
  }catch(error){
    if(error?.code==='POLICY_WRITE_FAILED')retained=true;
    throw error;
  }finally{
    if(!retained)releaseOwned(directory,GATE,gateOwner);
  }
}
function readCurrent(directory){
  checkDirectory(directory);
  assertMarkerState(directory,{allowActivePermits:true});
  return parseSnapshot(directory);
}
function makeState(snapshot){
  return {version:1,revision:snapshot.revision,records:snapshot.records.slice(),
    grants:snapshot.grants.map(grant=>({...grant}))};
}
function addPermit(directory){
  const name=PERMIT_PREFIX+randomUUID()+'.lock';
  const owner=createDurableProcessLock(directory,name,'tool-grant-permit');
  return {name,owner};
}
function findGrant(snapshot,input){
  return snapshot.grants.find(grant=>grant.active&&grant.ownerDigest===input.ownerDigest&&
    grant.deviceId===input.deviceId&&grant.fingerprint===input.fingerprint&&grant.tool===input.tool);
}
function argumentDigest(tool,args){return toolArgumentsDigest(tool,args);}
function appendGrant(snapshot,input,eventId,grantId){
  const revision=snapshot.revision+1;
  const grant={...input,grantId,revision,eventId,active:true};
  addEvent(snapshot,{type:'grant',revision,eventId,grant:{...input,grantId}});
  snapshot.revision=revision;
  snapshot.grants.push(grant);
  return grant;
}
function appendRevoke(snapshot,grantId,eventId){
  const revision=snapshot.revision+1;
  const grant=snapshot.grants.find(value=>value.grantId===grantId);
  if(!grant?.active)throw fail('NOT_FOUND','Active tool grant not found');
  addEvent(snapshot,{type:'revoke',revision,eventId,grantId});
  grant.active=false;grant.revokedRevision=revision;grant.revokedEventId=eventId;
  snapshot.revision=revision;
  return grant;
}
function ensureNoDuplicateActive(snapshot,input){
  if(snapshot.grants.some(grant=>grant.active&&grant.ownerDigest===input.ownerDigest&&
     grant.deviceId===input.deviceId&&grant.tool===input.tool)){
    throw fail('DUPLICATE_GRANT','An active grant already exists for this owner, device and tool');
  }
}
function authorizeForGrant(snapshot,input,issuedAt){
  const grant=findGrant(snapshot,input);
  if(!grant)throw fail('DENIED','No active tool grant matches this owner, device, identity and tool');
  validateArguments(input.tool,input.arguments,grant);
  if(snapshot.requests.has(input.requestId))throw fail('DUPLICATE_REQUEST','Tool requestId was already authorized');
  const decisionId=randomUUID();
  const expiresAt=issuedAt+PERMIT_TTL_MS;
  return {grant,decisionId,issuedAt,expiresAt};
}
function validateCurrentAuthorization(input){
  if(!sameKeys(input,['grantId','ownerDigest','deviceId','fingerprint','tool','policyRevision'])||
     !UUID.test(input.grantId??'')||!HEX64.test(input.ownerDigest??'')||
     !UUID.test(input.deviceId??'')||!HEX64.test(input.fingerprint??'')||
     !TOOLS.has(input.tool)||!Number.isSafeInteger(input.policyRevision)||input.policyRevision<1){
    throw fail('DENIED','Invalid current authorization identity');
  }
  return input;
}
function makeClaims(input,approval,authorization,snapshot){
  const {grant,decisionId,issuedAt,expiresAt}=authorization;
  return canonical({version:1,decisionId,requestId:input.requestId,ownerDigest:input.ownerDigest,
    deviceId:input.deviceId,fingerprint:input.fingerprint,tool:input.tool,
    argumentsDigest:argumentDigest(input.tool,input.arguments),grantId:grant.grantId,
    policyRevision:snapshot.revision,scope:grant.scope,constraints:grant.constraints,
    approvalEventId:approval.eventId,approvalTrustRevisionBefore:approval.trustRevisionBefore,
    approvalTrustRevisionAfter:approval.trustRevisionAfter,trustRevision:approval.trustRevision,
    issuedAt,expiresAt});
}
function checkedEnvelope(value){
  let cloned;
  try{
    const text=JSON.stringify(value);
    if(typeof text!=='string'||Buffer.byteLength(text,'utf8')>16*1024)throw Error();
    cloned=JSON.parse(text);
  }catch{throw fail('SIGNER','Capability signer returned invalid or oversized JSON');}
  if(!cloned||typeof cloned!=='object'||Array.isArray(cloned)||
     Object.getPrototypeOf(cloned)!==Object.prototype){
    throw fail('SIGNER','Capability signer must return a plain JSON object');
  }
  return freezeDeep(cloned);
}
export function createDurableToolGrantStore({directory,now=Date.now}={}){
  checkDirectory(directory,{create:false});
  if(typeof now!=='function')throw new TypeError('Grant policy clock must be a function');
  initialize(directory);
  const clock=()=>{
    const value=now();
    if(!Number.isSafeInteger(value)||value<0)throw fail('CLOCK','Invalid policy clock');
    return value;
  };
  function revision(){return readCurrent(directory).revision;}
  function list(){return freezeDeep(readCurrent(directory).grants.map(grant=>canonical(grant)));}
  function grant(input,options){
    const normalized=validateGrantInput(input);validateMutationOptions(options);
    const gateOwner=acquireGate(directory);
    return persistMutation(directory,gateOwner,()=>{
      const snapshot=parseSnapshot(directory);checkExpectedRevision(snapshot,options.expectedRevision);
      if(snapshot.events.has(options.eventId))throw fail('DUPLICATE_EVENT','Policy mutation event ID was already used');
      ensureNoDuplicateActive(snapshot,normalized);
      if(snapshot.grants.length>=MAX_GRANTS)throw fail('POLICY_FULL','Grant count limit reached');
      const next=makeState(snapshot),created=appendGrant(next,normalized,options.eventId,randomUUID());
      persistSnapshot(directory,next);
      return freezeDeep(canonical(created));
    });
  }
  function revoke(grantId,options){
    if(!UUID.test(grantId??''))throw fail('INVALID','Grant UUID required');
    validateMutationOptions(options);
    const gateOwner=acquireGate(directory);
    return persistMutation(directory,gateOwner,()=>{
      const snapshot=parseSnapshot(directory);checkExpectedRevision(snapshot,options.expectedRevision);
      if(snapshot.events.has(options.eventId))throw fail('DUPLICATE_EVENT','Policy mutation event ID was already used');
      const next=makeState(snapshot),revoked=appendRevoke(next,grantId,options.eventId);
      persistSnapshot(directory,next);
      return freezeDeep(canonical({...revoked,revision:next.revision}));
    });
  }
  function withCurrentAuthorization(input,callback){
    const identity=validateCurrentAuthorization(input);
    if(typeof callback!=='function'||callback.constructor?.name==='AsyncFunction'){
      throw fail('INVALID','Current authorization callback must be synchronous');
    }
    const gateOwner=acquireGate(directory);
    try{
      assertMarkerState(directory,{allowActivePermits:true,ignoreGate:true});
      const snapshot=parseSnapshot(directory);
      const grant=snapshot.grants.find(candidate=>candidate.grantId===identity.grantId&&candidate.active);
      if(!grant||grant.ownerDigest!==identity.ownerDigest||grant.deviceId!==identity.deviceId||
         grant.fingerprint!==identity.fingerprint||grant.tool!==identity.tool||
         grant.revision>identity.policyRevision||identity.policyRevision>snapshot.revision){
        throw fail('DENIED','Grant is revoked, stale or bound to a different identity');
      }
      const result=callback();
      if(result&&typeof result.then==='function'){
        throw fail('INVALID','Current authorization callback must complete synchronously');
      }
      return result;
    }finally{releaseOwned(directory,GATE,gateOwner);}
  }
  async function authorizeAndPermit(input,{signCapability}={}){
    if(typeof signCapability!=='function')throw fail('SIGNER','Capability signer is required');
    const normalized=validateAuthorizeInput(input),gateOwner=acquireGate(directory);
    let permit=null,retained=false,writerOwner=null;
    try{
      assertMarkerState(directory,{allowActivePermits:true,ignoreGate:true});
      const snapshot=parseSnapshot(directory);
      const authorization=authorizeForGrant(snapshot,normalized,clock());
      const finalClaims=freezeDeep(makeClaims(normalized,normalized.approval,authorization,snapshot));
      if(!validClaims(finalClaims))throw fail('INVALID','Capability claims failed schema validation');
      if(lockNames(directory).filter(name=>name.startsWith(PERMIT_PREFIX)).length>=MAX_PERMITS){
        throw fail('POLICY_BUSY','Active tool authorization permit limit reached');
      }
      permit=addPermit(directory);
      const signed=checkedEnvelope(await signCapability(finalClaims));
      writerOwner=createDurableProcessLock(directory,WRITER,'tool-grants-writer');
      const latest=parseSnapshot(directory);
      if(latest.revision!==snapshot.revision||
         findGrant(latest,normalized)?.grantId!==authorization.grant.grantId){
        throw fail('REVISION_CONFLICT','Policy changed before authorization evidence was committed');
      }
      if(latest.requests.has(normalized.requestId)||latest.decisions.has(authorization.decisionId)){
        throw fail('DUPLICATE_REQUEST','Tool request or decision was already authorized');
      }
      const next=makeState(latest);
      addEvent(next,{type:'authorize',decisionId:authorization.decisionId,claims:finalClaims});
      persistSnapshot(directory,next);
      releaseOwned(directory,WRITER,writerOwner);writerOwner=null;
      releaseOwned(directory,GATE,gateOwner);
      let released=false;
      const release=()=>{
        if(released)return false;
        releaseOwned(directory,permit.name,permit.owner);released=true;return true;
      };
      return Object.freeze({policyRevision:finalClaims.policyRevision,
        grantId:authorization.grant.grantId,ownerDigest:finalClaims.ownerDigest,
        deviceId:finalClaims.deviceId,fingerprint:finalClaims.fingerprint,tool:finalClaims.tool,
        decisionId:authorization.decisionId,authorization:signed,release});
    }catch(error){
      if(writerOwner||error?.code==='POLICY_WRITE_FAILED')retained=true;
      if(!retained){
        if(permit){try{releaseOwned(directory,permit.name,permit.owner);}catch{retained=true;}}
        if(!retained){try{releaseOwned(directory,GATE,gateOwner);}catch{retained=true;}}
      }
      throw error;
    }
  }
  return Object.freeze({revision,list,grant,revoke,authorizeAndPermit,withCurrentAuthorization});
}

// Offline operator recovery: a private recovery lock fences every new store
// operation while dead operation/writer/permit locks are examined and removed.
// Temporary snapshot evidence is reported but never deleted or interpreted.
export function clearStaleDurableToolGrantLocks({directory,operatorConfirmedNoActiveWriters,
  operatorConfirmedNoActiveRecovery}={}){
  if(operatorConfirmedNoActiveWriters!==true||operatorConfirmedNoActiveRecovery!==true){
    throw fail('OPERATOR_REQUIRED','Operator confirmation that no policy writer or recovery process is active is required');
  }
  checkDirectory(directory);
  const existing=inspectLock(directory,RECOVERY_LOCK);
  if(existing.present){
    if(existing.status!=='dead')throw fail(existing.status==='active'?'POLICY_BUSY':'STALE_LOCK',
      'An active or unverified policy recovery lock cannot be cleared');
    removeDeadDurableProcessLock({directory,name:RECOVERY_LOCK,expectedDigest:existing.digest});
  }
  let recoveryOwner;
  try{recoveryOwner=createDurableProcessLock(directory,RECOVERY_LOCK,'tool-grants-recovery');}
  catch{throw fail('POLICY_BUSY','Another policy recovery process owns the recovery lock');}
  try{
    const candidates=lockNames(directory).filter(name=>name===GATE||name===WRITER||
      name.startsWith(PERMIT_PREFIX));
    const evidence=candidates.map(name=>inspectLock(directory,name));
    if(evidence.some(lock=>lock.status!=='dead')){
      throw fail(evidence.some(lock=>lock.status==='active')?'POLICY_BUSY':'STALE_LOCK',
        'Active or unverified policy writers/permits prevent lock recovery');
    }
    let cleared=0;
    for(const lock of evidence){
      if(removeDeadDurableProcessLock({directory,name:lock.name,expectedDigest:lock.digest}))cleared++;
    }
    const temporaryFileCount=lockNames(directory).filter(name=>
      name.startsWith(TEMP_PREFIX)&&name.endsWith('.tmp')).length;
    return Object.freeze({cleared,temporaryFileCount});
  }finally{removeOwnedDurableProcessLock({directory,name:RECOVERY_LOCK,owner:recoveryOwner});}
}
