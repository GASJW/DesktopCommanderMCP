import path from 'node:path';
import os from 'node:os';
import { createHash, randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import {
  constants, closeSync, fstatSync, fsyncSync, linkSync, lstatSync, mkdirSync,
  openSync, readFileSync, readSync, readdirSync, realpathSync, statSync, unlinkSync, writeSync,
} from 'node:fs';
import { createDurableProcessLock, inspectDurableProcessLock,
  removeOwnedDurableProcessLock } from '../../../gateway/common/durable-process-lock.mjs';
import { verifyToolGrantCapability } from '../../../gateway/devices/tool-grant-capability.mjs';
import { createLocalReadonlyMcp, LocalMcpError } from './local-mcp-readonly.mjs';

const LEDGER='i4-execution.jsonl';
const LOCK='i4-execution-lock';
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const TOOL_NAMES=new Set(['read_file','list_directory','write_file','list_processes','run_command']);
const MAX_LEDGER_BYTES=4*1024*1024;
const MAX_LEDGER_RECORDS=20_000;
const MAX_CONTENT_BYTES=64*1024;
const MAX_OUTPUT_BYTES=16*1024;
const MAX_DIRECTORY_ENTRIES=200;
const MAX_JOBS=32;
const fail=(code,message)=>new LocalMcpError(code,message);
const sameKeys=(value,keys)=>value&&Object.getPrototypeOf(value)===Object.prototype&&
  Object.keys(value).sort().join(',')===[...keys].sort().join(',');
function validAuthorization(value){
  const envelope=value&&typeof value==='object'&&!Array.isArray(value)&&
    sameKeys(value,['claims','signature','version'])&&value.version===1&&
    value.claims&&typeof value.claims==='object'&&!Array.isArray(value.claims)&&
    Object.getPrototypeOf(value.claims)===Object.prototype&&
    typeof value.signature==='string'&&/^[A-Za-z0-9_-]{86}$/.test(value.signature);
  const legacy=value&&typeof value==='object'&&!Array.isArray(value)&&
    sameKeys(value,['approvalEventId','approvalTrustRevisionAfter','approvalTrustRevisionBefore',
      'fingerprint','ownerDigest','policyRevision','trustRevision'])&&
    UUID.test(value.approvalEventId??'')&&/^[a-f0-9]{64}$/.test(value.fingerprint??'')&&
    /^[a-f0-9]{64}$/.test(value.ownerDigest??'')&&
    Number.isSafeInteger(value.approvalTrustRevisionBefore)&&value.approvalTrustRevisionBefore>=0&&
    Number.isSafeInteger(value.approvalTrustRevisionAfter)&&
    value.approvalTrustRevisionAfter===value.approvalTrustRevisionBefore+1&&
    Number.isSafeInteger(value.trustRevision)&&value.trustRevision>=value.approvalTrustRevisionAfter&&
    typeof value.policyRevision==='string'&&value.policyRevision.length>0&&
    value.policyRevision.length<=128&&!/[\u0000-\u001f\u007f]/.test(value.policyRevision);
  return envelope||legacy;
}
function syncDirectory(directory){
  const fd=openSync(directory,constants.O_RDONLY|(constants.O_DIRECTORY??0)|(constants.O_NOFOLLOW??0));
  try{fsyncSync(fd);}finally{closeSync(fd);}
}
function safeDirectoryPath(directory,{privateFinal=false}={}){
  if(process.platform!=='linux'||typeof process.getuid!=='function'){
    throw fail('POLICY','Durable execution ledger requires Linux process identity');
  }
  if(typeof directory!=='string'||!path.isAbsolute(directory)||path.normalize(directory)!==directory){
    throw fail('POLICY','Absolute normalized execution ledger directory required');
  }
  const root=path.parse(directory).root;
  const segments=directory.slice(root.length).split(path.sep).filter(Boolean);
  let current=root,st=null;
  try{
    for(let index=0;index<segments.length;index++){
      current=path.join(current,segments[index]);
      st=lstatSync(current);
      if(!st.isDirectory()||st.isSymbolicLink())throw Error('not a real directory');
      const final=index===segments.length-1;
      if(!final&&(st.mode&0o022)!==0&&(!(st.mode&0o1000)||st.uid!==0)){
        throw Error('writable ancestor is not root-owned sticky');
      }
      if(final&&(st.uid!==process.getuid()||
         (privateFinal?(st.mode&0o7777)!==0o700:(st.mode&0o022)!==0))){
        throw Error('unsafe directory owner or permissions');
      }
    }
  }catch{
    throw fail('POLICY',privateFinal
      ?'Execution ledger directory or an ancestor is unsafe'
      :'Approved operation root or an ancestor is unsafe');
  }
  return directory;
}
function safeStateDirectory(directory){return safeDirectoryPath(directory,{privateFinal:true});}
function safeOperationRoot(directory){return safeDirectoryPath(directory);}
const directoryFlags=constants.O_RDONLY|(constants.O_DIRECTORY??0)|(constants.O_NOFOLLOW??0);
const procFd=fd=>`/proc/self/fd/${fd}`;
function assertPinnedDirectory(directory,fd){
  let named,opened;
  try{named=lstatSync(directory,{bigint:true});opened=fstatSync(fd,{bigint:true});}
  catch{throw fail('STATE_DIRECTORY_CHANGED','Execution state directory is unavailable');}
  if(!named.isDirectory()||named.isSymbolicLink()||!opened.isDirectory()||
     named.dev!==opened.dev||named.ino!==opened.ino||opened.uid!==BigInt(process.getuid())||
     (Number(opened.mode)&0o7777)!==0o700){
    throw fail('STATE_DIRECTORY_CHANGED','Execution state directory identity changed');
  }
}
function relativeSegments(root,target,{allowRoot=false}={}){
  if(typeof target!=='string'||!path.isAbsolute(target)||target.length>4096||target.includes('\0')){
    throw fail('DENIED','Invalid absolute path');
  }
  const absolute=path.resolve(target);
  if(absolute===root&&allowRoot)return [];
  if(!inside(root,absolute))throw fail('DENIED','Path is outside the approved operation scope');
  const relative=path.relative(root,absolute);
  const segments=relative.split(path.sep);
  if(segments.some(segment=>!segment||segment==='.'||segment==='..')){
    throw fail('DENIED','Invalid path component');
  }
  return segments;
}
function openDirectoryBeneath(rootFd,root,target,{allowRoot=false}={}){
  const segments=relativeSegments(root,target,{allowRoot});
  if(segments.length===0)return {fd:rootFd,owned:false};
  let fd=rootFd,owned=false;
  try{
    for(const segment of segments){
      const next=openSync(path.join(procFd(fd),segment),directoryFlags);
      const st=fstatSync(next);
      if(!st.isDirectory()||(st.mode&0o022)!==0){
        closeSync(next);throw fail('DENIED','Unsafe or writable directory in approved path');
      }
      if(owned)closeSync(fd);
      fd=next;owned=true;
    }
    return {fd,owned};
  }catch(error){
    if(owned)closeSync(fd);
    if(error instanceof LocalMcpError)throw error;
    throw fail('DENIED','Directory path could not be opened beneath the approved root');
  }
}
function openFileBeneath(rootFd,root,filename,maxBytes=MAX_CONTENT_BYTES){
  const segments=relativeSegments(root,filename);
  const base=segments.pop();
  let parent;
  try{
    parent=openDirectoryBeneath(rootFd,root,path.join(root,...segments),{allowRoot:true});
    const fd=openSync(path.join(procFd(parent.fd),base),constants.O_RDONLY|(constants.O_NOFOLLOW??0));
    const st=fstatSync(fd);
    if(!st.isFile()||st.size>maxBytes){closeSync(fd);throw fail('DENIED','File is outside the approved operation scope');}
    return {fd,stat:st};
  }catch(error){
    if(error instanceof LocalMcpError)throw error;
    throw fail('DENIED','File is unavailable beneath the approved root');
  }finally{if(parent?.owned)closeSync(parent.fd);}
}
function validateLedgerFile(filename){
  let named;
  try{named=lstatSync(filename);}catch(error){if(error?.code==='ENOENT')return null;throw error;}
  if(!named.isFile()||named.isSymbolicLink()||named.nlink!==1||
     named.uid!==process.getuid()||(named.mode&0o7777)!==0o600||named.size>MAX_LEDGER_BYTES){
    throw fail('LEDGER_CORRUPT','Execution ledger file has unsafe metadata');
  }
  const fd=openSync(filename,constants.O_RDONLY|(constants.O_NOFOLLOW??0));
  try{
    const opened=fstatSync(fd);
    if(!opened.isFile()||opened.nlink!==1||opened.uid!==process.getuid()||
       opened.ino!==named.ino||opened.dev!==named.dev||opened.size!==named.size||
       (opened.mode&0o7777)!==0o600){
      throw fail('LEDGER_CORRUPT','Execution ledger changed during inspection');
    }
    return readFileSync(fd);
  }finally{closeSync(fd);}
}
function validateRecord(record){
  const authorization=record?.authorization;
  if(!record||typeof record!=='object'||Array.isArray(record)||record.version!==2||
     !UUID.test(record.requestId??'')||!UUID.test(record.deviceId??'')||
     !TOOL_NAMES.has(record.tool)||!/^[a-f0-9]{64}$/.test(record.argumentHash??'')||
     !validAuthorization(authorization)||
     typeof record.occurredAt!=='string'||!Number.isFinite(Date.parse(record.occurredAt)))return false;
  if(record.type==='intent')return sameKeys(record,['argumentHash','authorization','deviceId','occurredAt',
    'requestId','tool','type','version']);
  if(record.type==='outcome')return sameKeys(record,['argumentHash','deviceId','occurredAt',
    'authorization','exitCode','requestId','resultHash','status','tool','type','version'])&&
    ['success','failed','ambiguous'].includes(record.status)&&
    (record.exitCode===null||Number.isSafeInteger(record.exitCode))&&
    (record.resultHash===null||/^[a-f0-9]{64}$/.test(record.resultHash));
  return false;
}
function readLedger(filename){
  const bytes=validateLedgerFile(filename);
  if(bytes===null)return {entries:new Map(),count:0,bytes:0};
  if(bytes.length===0||bytes[bytes.length-1]!==10)throw fail('LEDGER_CORRUPT','Execution ledger is truncated');
  const lines=bytes.toString('utf8').slice(0,-1).split('\n');
  if(lines.length>MAX_LEDGER_RECORDS)throw fail('LEDGER_FULL','Execution ledger record limit reached');
  const entries=new Map();
  for(const line of lines){
    let record;
    try{record=JSON.parse(line);}catch{throw fail('LEDGER_CORRUPT','Execution ledger contains invalid JSON');}
    if(!validateRecord(record)||JSON.stringify(record)!==line){
      throw fail('LEDGER_CORRUPT','Execution ledger record schema is invalid');
    }
    const entry=entries.get(record.requestId);
    if(record.type==='intent'){
      if(entry)throw fail('LEDGER_CORRUPT','Execution ledger repeats a request intent');
      entries.set(record.requestId,{intent:record,outcome:null});
    }else{
      if(!entry||entry.outcome||entry.intent.deviceId!==record.deviceId||
         entry.intent.tool!==record.tool||entry.intent.argumentHash!==record.argumentHash){
        throw fail('LEDGER_CORRUPT','Execution outcome does not match its intent');
      }
      if(JSON.stringify(entry.intent.authorization)!==JSON.stringify(record.authorization)){
        throw fail('LEDGER_CORRUPT','Execution outcome authorization does not match its intent');
      }
      entry.outcome=record;
    }
  }
  return {entries,count:lines.length,bytes:bytes.length};
}
function appendRecord(directory,filename,record,directoryFd){
  const line=Buffer.from(JSON.stringify(record)+'\n');
  if(line.length>8192)throw fail('LEDGER_FULL','Execution ledger record exceeds its limit');
  try{
    let existing;
    try{existing=lstatSync(filename);}catch(error){if(error?.code!=='ENOENT')throw error;}
    if(existing&&(!existing.isFile()||existing.isSymbolicLink()||existing.nlink!==1||
       existing.uid!==process.getuid()||(existing.mode&0o7777)!==0o600||
       existing.size+line.length>MAX_LEDGER_BYTES)){
      throw fail('LEDGER_FULL','Execution ledger is unsafe or full');
    }
    const fd=openSync(filename,constants.O_WRONLY|constants.O_APPEND|constants.O_CREAT|
      (constants.O_NOFOLLOW??0),0o600);
    try{
      const opened=fstatSync(fd);
      if(!opened.isFile()||opened.nlink!==1||opened.uid!==process.getuid()||
         (opened.mode&0o7777)!==0o600||opened.size+line.length>MAX_LEDGER_BYTES){
        throw fail('LEDGER_WRITE_FAILED','Execution ledger metadata changed');
      }
      let offset=0;
      while(offset<line.length){
        const count=writeSync(fd,line,offset,line.length-offset);
        if(count<=0)throw fail('LEDGER_WRITE_FAILED','Short execution ledger write');
        offset+=count;
      }
      fsyncSync(fd);
    }finally{closeSync(fd);}
    if(!existing){
      if(directoryFd!==undefined)fsyncSync(directoryFd);
      else syncDirectory(directory);
    }
  }catch(error){
    if(error instanceof LocalMcpError)throw error;
    throw fail('LEDGER_WRITE_FAILED','Execution ledger could not be committed');
  }
}
function canonical(value){
  if(Array.isArray(value))return value.map(canonical);
  if(value&&typeof value==='object')return Object.fromEntries(Object.keys(value).sort().map(key=>[key,canonical(value[key])]));
  return value;
}
function hash(value){return createHash('sha256').update(value).digest('hex');}
function result(text,structuredContent){
  return {content:[{type:'text',text}],isError:false,structuredContent};
}
function jsonResult(value){return result(JSON.stringify(value),value);}
function inside(root,target){
  const relative=path.relative(root,target);
  return relative!==''&&relative!=='..'&&!relative.startsWith('..'+path.sep)&&!path.isAbsolute(relative);
}
function readPinnedText(opened,maxBytes,offset,length){
  const before=fstatSync(opened.fd,{bigint:true});
  if(!before.isFile()||before.size>BigInt(maxBytes)){
    throw fail('DENIED','File is outside the approved operation scope');
  }
  const buffer=Buffer.alloc(maxBytes+1);
  let bytesRead=0;
  while(bytesRead<buffer.length){
    const count=readSync(opened.fd,buffer,bytesRead,buffer.length-bytesRead,bytesRead);
    if(count===0)break;
    bytesRead+=count;
  }
  const after=fstatSync(opened.fd,{bigint:true});
  if(bytesRead>maxBytes||BigInt(bytesRead)!==before.size||
     before.dev!==after.dev||before.ino!==after.ino||before.size!==after.size||
     before.mtimeNs!==after.mtimeNs||before.ctimeNs!==after.ctimeNs){
    throw fail('FILE_CHANGED','File changed while the approved descriptor was read');
  }
  let text;
  try{text=new TextDecoder('utf-8',{fatal:true}).decode(buffer.subarray(0,bytesRead));}
  catch{throw fail('INVALID_UTF8','File is not valid UTF-8 text');}
  const lines=text.match(/[^\n]*(?:\n|$)/g)?.filter(line=>line.length>0)??[];
  return result(lines.slice(offset,offset+length).join(''));
}
function checkedArguments(name,args){
  if(!args||Object.getPrototypeOf(args)!==Object.prototype)throw fail('DENIED','Invalid tool arguments');
  const exact=(required,optional=[])=>{
    const keys=Object.keys(args);
    return required.every(key=>Object.hasOwn(args,key))&&
      keys.every(key=>required.includes(key)||optional.includes(key));
  };
  if(name==='read_file'&&exact(['path'],['offset','length'])&&
     (args.offset===undefined||Number.isSafeInteger(args.offset)&&args.offset>=0&&args.offset<=100_000)&&
     (args.length===undefined||Number.isSafeInteger(args.length)&&args.length>=1&&args.length<=1000))return;
  if(name==='list_directory'&&exact(['path'],['depth'])&&
     (args.depth===undefined||Number.isSafeInteger(args.depth)&&args.depth>=0&&args.depth<=2))return;
  if(name==='write_file'&&exact(['path','content','mode'])&&args.mode==='create'&&
     typeof args.content==='string'&&Buffer.byteLength(args.content,'utf8')<=MAX_CONTENT_BYTES)return;
  if(name==='list_processes'&&exact([]))return;
  if(name==='run_command'&&exact(['profile','path'])&&args.profile==='count_lines')return;
  throw fail('DENIED','Unsupported tool or invalid arguments');
}
function createOnlyWrite(rootFd,root,filename,content){
  const absolute=path.resolve(filename),parent=path.dirname(absolute),base=path.basename(absolute);
  if(!base||base==='.'||base==='..')throw fail('DENIED','Invalid destination file name');
  const openedParent=openDirectoryBeneath(rootFd,root,parent,{allowRoot:true});
  const bytes=Buffer.from(content,'utf8');
  if(bytes.length>MAX_CONTENT_BYTES){if(openedParent.owned)closeSync(openedParent.fd);throw fail('DENIED','Write content is too large');}
  const anchored=procFd(openedParent.fd);
  const tempPath=path.join(anchored,`.vpsc-create-${randomUUID()}.tmp`);
  const destination=path.join(anchored,base);
  let existing;
  try{existing=lstatSync(destination);}catch(error){if(error?.code!=='ENOENT'){if(openedParent.owned)closeSync(openedParent.fd);throw error;}}
  if(existing){if(openedParent.owned)closeSync(openedParent.fd);throw fail('ALREADY_EXISTS','Create-only write never replaces an existing path');}
  let fileFd,linked=false;
  try{
    fileFd=openSync(tempPath,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|
      (constants.O_NOFOLLOW??0),0o600);
    let offset=0;
    while(offset<bytes.length){
      const count=writeSync(fileFd,bytes,offset,bytes.length-offset);
      if(count<=0)throw fail('WRITE_FAILED','Short file write');
      offset+=count;
    }
    fsyncSync(fileFd);
    closeSync(fileFd);fileFd=undefined;
    try{linkSync(tempPath,destination);}catch(error){
      if(error?.code==='EEXIST')throw fail('ALREADY_EXISTS','Create-only write never replaces an existing path');
      throw fail('WRITE_FAILED','Atomic create is unavailable');
    }
    linked=true;
    unlinkSync(tempPath);
    fsyncSync(openedParent.fd);
  }catch(error){
    if(fileFd!==undefined)closeSync(fileFd);
    try{unlinkSync(tempPath);}catch{}
    if(error instanceof LocalMcpError)throw error;
    if(linked)throw fail('AMBIGUOUS_WRITE','File was linked but directory durability is unknown');
    throw fail('WRITE_FAILED','Atomic create failed');
  }finally{if(openedParent.owned)closeSync(openedParent.fd);}
  return jsonResult({created:true,bytes:bytes.length});
}
function boundedList(rootFd,root,filename,depthLimit,entryLimit=MAX_DIRECTORY_ENTRIES){
  const opened=openDirectoryBeneath(rootFd,root,path.resolve(filename),{allowRoot:true});
  const entries=[];let truncated=false;
  const queue=[{fd:opened.fd,owned:opened.owned,depth:0,relative:''}];
  try{
    for(let cursor=0;cursor<queue.length&&!truncated;cursor++){
      const current=queue[cursor];
      try{
        for(const entry of readdirSync(procFd(current.fd),{withFileTypes:true})){
          if(entries.length>=Math.min(MAX_DIRECTORY_ENTRIES,entryLimit)){truncated=true;break;}
          const relative=current.relative?path.join(current.relative,entry.name):entry.name;
          entries.push({name:entry.name,path:relative,type:entry.isDirectory()?'directory':
            entry.isFile()?'file':entry.isSymbolicLink()?'symlink':'other'});
          if(entry.isDirectory()&&current.depth<depthLimit){
            let childFd=null;
            try{
              childFd=openSync(path.join(procFd(current.fd),entry.name),directoryFlags);
              const childStat=fstatSync(childFd);
              if(!childStat.isDirectory()||(childStat.mode&0o022)!==0){closeSync(childFd);childFd=null;continue;}
              queue.push({fd:childFd,owned:true,depth:current.depth+1,relative});
              childFd=null;
            }catch{if(childFd!==null)closeSync(childFd);}
          }
        }
      }finally{
        if(current.owned){closeSync(current.fd);current.fd=-1;current.owned=false;}
      }
    }
  }finally{
    for(let index=0;index<queue.length;index++){
      const item=queue[index];
      if(item.owned&&item.fd!==-1){try{closeSync(item.fd);}catch{}item.fd=-1;item.owned=false;}
    }
  }
  return jsonResult({entries,truncated});
}
function runCountLines({rootFd,root,filename,timeoutMs,signal,jobs,activeChildren,onSpawn,
  afterFileOpen,slowTestCommand=false,failTestCommand=false,maxOutputBytes=MAX_OUTPUT_BYTES}){
  if(process.platform!=='linux')throw fail('UNSUPPORTED','count_lines profile is Linux-only');
  const opened=openFileBeneath(rootFd,root,filename,1024*1024);
  try{afterFileOpen?.({tool:'run_command',path:filename});}
  catch(error){closeSync(opened.fd);throw error;}
  const executable=slowTestCommand?'/usr/bin/sleep':failTestCommand?'/usr/bin/false':'/usr/bin/wc';
  const commandArgs=slowTestCommand?['30']:failTestCommand?[]:['--lines'];
  try{if(!statSync(executable).isFile())throw Error();}catch{closeSync(opened.fd);throw fail('UNSUPPORTED','Fixed count_lines executable is unavailable');}
  if(signal?.aborted){closeSync(opened.fd);throw fail('CANCELLED','Operation cancelled before command start');}
  const job={jobId:randomUUID(),profile:'count_lines',pid:null,state:'running',
    startedAt:new Date().toISOString(),exitCode:null};
  jobs.push(job);if(jobs.length>MAX_JOBS)jobs.shift();
  return new Promise((resolve,reject)=>{
    let child,stdout='',stderr='',total=0,timeout=null,killTimer=null,finished=false,fileFdOpen=true;
    let timedOut=false,cancelled=false,overflow=false;
    const terminate=()=>{
      if(!child||child.exitCode!==null)return;
      try{process.kill(-child.pid,'SIGTERM');}catch{try{child.kill('SIGTERM');}catch{}}
      killTimer=setTimeout(()=>{try{process.kill(-child.pid,'SIGKILL');}catch{try{child.kill('SIGKILL');}catch{}}},300);
      killTimer.unref?.();
    };
    const onAbort=()=>{cancelled=true;terminate();};
    const finish=(error,value)=>{
      if(finished)return;finished=true;
      clearTimeout(timeout);clearTimeout(killTimer);signal?.removeEventListener('abort',onAbort);
      if(fileFdOpen){closeSync(opened.fd);fileFdOpen=false;}
      if(child)activeChildren.delete(child);
      if(error){job.state=error.code?.startsWith('AMBIGUOUS_')?'ambiguous':'failed';reject(error);}
      else{
        if(job.state==='running')job.state='completed';
        job.exitCode=value?.structuredContent?.exitCode??null;resolve(value);
      }
    };
    try{
      child=spawn(executable,commandArgs,{cwd:root,env:{PATH:'/usr/bin:/bin',LC_ALL:'C'},
        shell:false,stdio:[opened.fd,'pipe','pipe'],detached:true});
    }catch{finish(fail('COMMAND_START_FAILED','Fixed command could not start'));return;}
    child.once('spawn',()=>{
      if(fileFdOpen){closeSync(opened.fd);fileFdOpen=false;}
      try{onSpawn?.(child.pid);}catch{terminate();}
    });
    activeChildren.add(child);job.pid=child.pid;
    const collect=(which,chunk)=>{
      total+=chunk.length;
      if(total>Math.min(MAX_OUTPUT_BYTES,maxOutputBytes)){overflow=true;terminate();return;}
      if(which==='stdout')stdout+=chunk.toString('utf8');else stderr+=chunk.toString('utf8');
    };
    child.stdout.on('data',chunk=>collect('stdout',chunk));
    child.stderr.on('data',chunk=>collect('stderr',chunk));
    child.once('error',()=>finish(fail('COMMAND_START_FAILED','Fixed command could not start')));
    child.once('close',(exitCode,signalName)=>{
      if(cancelled)return finish(fail('AMBIGUOUS_CANCELLED','Command cancellation outcome is unknown'));
      if(timedOut)return finish(fail('AMBIGUOUS_TIMEOUT','Command timed out; do not replay'));
      if(overflow)return finish(fail('AMBIGUOUS_OUTPUT_LIMIT','Command output exceeded the limit'));
      if(signalName)return finish(fail('AMBIGUOUS_COMMAND','Command exited without a result'));
      const output={profile:'count_lines',exitCode,stdout:stdout.slice(0,Math.min(MAX_OUTPUT_BYTES,maxOutputBytes)),
        stderr:stderr.slice(0,Math.min(MAX_OUTPUT_BYTES,maxOutputBytes))};
      job.state=exitCode===0?'completed':'failed';job.exitCode=exitCode;
      finish(null,jsonResult(output));
    });
    timeout=setTimeout(()=>{timedOut=true;terminate();},timeoutMs);
    timeout.unref?.();
    signal?.addEventListener('abort',onAbort,{once:true});
    if(signal?.aborted)onAbort();
  });
}

export function analyzeI4ExecutionRecovery({ledgerDirectory}={}){
  const directory=safeStateDirectory(ledgerDirectory);
  const directoryFd=openSync(directory,directoryFlags);
  let lock,ledger;
  try{
    assertPinnedDirectory(directory,directoryFd);
    lock=inspectDurableProcessLock(directory,LOCK);
    ledger=readLedger(path.join(procFd(directoryFd),LEDGER));
    assertPinnedDirectory(directory,directoryFd);
  }finally{closeSync(directoryFd);}
  const unresolved=Array.from(ledger.entries.values()).filter(entry=>!entry.outcome)
    .map(entry=>({deviceId:entry.intent.deviceId,requestId:entry.intent.requestId,
      tool:entry.intent.tool,argumentHash:entry.intent.argumentHash}));
  const ambiguous=Array.from(ledger.entries.values()).filter(entry=>entry.outcome?.status==='ambiguous')
    .map(entry=>({deviceId:entry.intent.deviceId,requestId:entry.intent.requestId,
      tool:entry.intent.tool,argumentHash:entry.intent.argumentHash}));
  return Object.freeze({status:lock.status==='active'?'writer-active':lock.status==='unknown'?'lock-unknown':
    lock.present?'stale-lock':unresolved.length?'ambiguous-intent':ambiguous.length?'ambiguous-outcome':'consistent',
    lock:Object.freeze({present:lock.present,status:lock.status,reason:lock.reason??null,
      digest:lock.digest??null}),
    recordCount:ledger.count,unresolved:Object.freeze(unresolved),ambiguous:Object.freeze(ambiguous),automaticReplay:false,
    automaticLockRemoval:false});
}

export function createGovernedAgentExecutor({allowedRoot,entrypoint,nodeBin=process.execPath,
  ledgerDirectory,timeoutMs=8000,startupTimeoutMs=30_000,maxFileBytes=64*1024,
  commandTimeoutMs=10_000,gatewayPolicyPublicKey,deviceId,fingerprint,testHooks}={}){
  if(typeof process.getuid==='function'&&process.getuid()===0)throw fail('PRIVILEGE','Agent must run as nonroot');
  if(process.platform!=='linux')throw fail('UNSUPPORTED','I4 durable execution currently requires Linux');
  if(!Number.isSafeInteger(commandTimeoutMs)||commandTimeoutMs<100||commandTimeoutMs>30_000){
    throw fail('POLICY','Invalid fixed command timeout');
  }
  if(!gatewayPolicyPublicKey||!UUID.test(deviceId??'')||!/^[a-f0-9]{64}$/.test(fingerprint??'')){
    throw fail('POLICY','Pinned Gateway policy key and agent identity are required');
  }
  if(testHooks!==undefined&&(!process.env.NODE_TEST_CONTEXT||!testHooks||
     typeof testHooks!=='object'||Array.isArray(testHooks)||
     Object.keys(testHooks).some(key=>!['afterOperationBeforeOutcome','afterFileOpen',
       'failCommandForTest','onCommandSpawn','sleepCommandForTimeout'].includes(key))||
     testHooks.afterOperationBeforeOutcome!==undefined&&typeof testHooks.afterOperationBeforeOutcome!=='function'||
     testHooks.afterFileOpen!==undefined&&typeof testHooks.afterFileOpen!=='function'||
     testHooks.failCommandForTest!==undefined&&typeof testHooks.failCommandForTest!=='boolean'||
     testHooks.onCommandSpawn!==undefined&&typeof testHooks.onCommandSpawn!=='function'||
     testHooks.sleepCommandForTimeout!==undefined&&typeof testHooks.sleepCommandForTimeout!=='boolean')){
    throw fail('POLICY','Fault hooks are available only inside the Node test runner');
  }
  let root,rootFd,stateFd;
  try{
    safeOperationRoot(allowedRoot);
    root=realpathSync(allowedRoot);
    rootFd=openSync(root,directoryFlags);
    const openedRoot=fstatSync(rootFd);
    if(!openedRoot.isDirectory()||openedRoot.uid!==process.getuid()||(openedRoot.mode&0o022)!==0||
       realpathSync(procFd(rootFd))!==root)throw Error();
  }catch{if(rootFd!==undefined)closeSync(rootFd);throw fail('POLICY','Absolute private non-symlink approved directory required');}
  let state;
  try{
    state=safeStateDirectory(ledgerDirectory);
    stateFd=openSync(state,directoryFlags);
    assertPinnedDirectory(state,stateFd);
  }catch(error){
    if(stateFd!==undefined)closeSync(stateFd);
    closeSync(rootFd);
    if(error instanceof LocalMcpError)throw error;
    throw fail('POLICY','Execution ledger directory could not be pinned');
  }
  const ledgerPath=path.join(procFd(stateFd),LEDGER);
  const local=createLocalReadonlyMcp({allowedRoot:root,entrypoint,nodeBin,timeoutMs,
    startupTimeoutMs,maxFileBytes});
  const jobs=[],activeChildren=new Set();
  let started=false,closed=false,uncertain=false;
  const assertState=()=>assertPinnedDirectory(state,stateFd);
  const readCurrentLedger=()=>{assertState();const ledger=readLedger(ledgerPath);assertState();return ledger;};
  const appendCurrentRecord=record=>{assertState();appendRecord(state,ledgerPath,record,stateFd);assertState();};
  const inspectCurrentRecovery=()=>{assertState();const inspection=analyzeI4ExecutionRecovery({ledgerDirectory:state});
    assertState();return inspection;};
  async function start(){
    if(started||closed)throw fail('STATE','Governed executor is single-use');
    started=true;
    const inspection=inspectCurrentRecovery();
    if(inspection.status!=='consistent'){
      throw fail('RECOVERY_REQUIRED',`I4 recovery state requires operator review: ${inspection.status}`);
    }
    await local.start();
    return Object.freeze({running:true,mode:'governed-i4'});
  }
  async function execute(frame,{signal}={}){
    if(!started||closed)throw fail('UNAVAILABLE','Governed executor is not running');
    assertState();
    if(signal?.aborted)throw fail('CANCELLED','Operation cancelled before dispatch');
    if(!frame||frame.version!==1||frame.method!=='tools/call'||frame.deviceId!==deviceId||
       !UUID.test(frame.sessionId??'')||!UUID.test(frame.requestId??'')||
       !frame.params||Object.getPrototypeOf(frame.params)!==Object.prototype||
       !sameKeys(frame.params,['arguments','name'])||typeof frame.params.name!=='string'||
       !TOOL_NAMES.has(frame.params.name))throw fail('DENIED','Invalid authenticated operation frame');
    const authorization=frame.authorization;
    if(!validAuthorization(authorization)){
      throw fail('DENIED','Operation authorization receipt is missing or invalid');
    }
    const {name,arguments:args}=frame.params;
    checkedArguments(name,args);
    let grant;
    try{grant=verifyToolGrantCapability(authorization,gatewayPolicyPublicKey,{deviceId,
      requestId:frame.requestId,fingerprint,tool:name,arguments:args,allowedRoot:root});}
    catch{throw fail('DENIED','Operation lacks a valid Gateway signed tool grant');}
    const argumentHash=hash(JSON.stringify(canonical({tool:name,arguments:args})));
    let lockOwner;
    try{assertState();lockOwner=createDurableProcessLock(state,LOCK,'i4-agent-op');assertState();}
    catch(error){
      if(error?.code==='EEXIST'||/already exists|active/.test(error?.message??'')){
        throw fail('BUSY','Another agent execution is active or awaiting recovery');
      }
      throw fail('LOCK_UNAVAILABLE','Execution lock is unavailable');
    }
    let retainLock=false;
    try{
      const ledger=readCurrentLedger();
      const unresolved=Array.from(ledger.entries.values()).find(entry=>!entry.outcome);
      if(unresolved)throw fail('RECOVERY_REQUIRED','An earlier operation has no durable outcome');
      const previous=ledger.entries.get(frame.requestId);
      if(previous){
        if(previous.intent.deviceId!==frame.deviceId||previous.intent.tool!==name||
           previous.intent.argumentHash!==argumentHash){
          throw fail('REQUEST_ID_REUSE','Request id is already bound to a different operation');
        }
        throw fail('DUPLICATE_EXECUTION','Operation already has a durable outcome; it will not be replayed');
      }
      if(Array.from(ledger.entries.values()).some(entry=>entry.outcome?.status==='ambiguous')){
        throw fail('RECOVERY_REQUIRED','An earlier operation outcome is ambiguous');
      }
      if(ledger.count+2>MAX_LEDGER_RECORDS)throw fail('LEDGER_FULL','Execution ledger record limit reached');
      const occurredAt=new Date().toISOString();
      const intent={version:2,type:'intent',requestId:frame.requestId,deviceId:frame.deviceId,
        tool:name,argumentHash,authorization:{...authorization},occurredAt};
      const reservedOutcome={version:2,type:'outcome',requestId:frame.requestId,deviceId:frame.deviceId,
        tool:name,argumentHash,authorization:{...authorization},status:'ambiguous',resultHash:'f'.repeat(64),exitCode:null,
        occurredAt:'9999-12-31T23:59:59.999Z'};
      if(ledger.bytes+Buffer.byteLength(JSON.stringify(intent)+'\n')+
         Buffer.byteLength(JSON.stringify(reservedOutcome)+'\n')>MAX_LEDGER_BYTES){
        throw fail('LEDGER_FULL','Execution ledger has insufficient space for a complete outcome');
      }
      appendCurrentRecord(intent);
      let output;
      try{
        if(signal?.aborted)throw fail('CANCELLED','Operation cancelled after durable intent');
        if(name==='read_file'){
          const opened=openFileBeneath(rootFd,root,args.path,
            Math.min(maxFileBytes,grant.constraints.maxBytes));
          try{
            await testHooks?.afterFileOpen?.({tool:name,path:args.path});
            output=readPinnedText(opened,maxFileBytes,args.offset??0,args.length??1000);
          }finally{closeSync(opened.fd);}
        }else if(name==='list_directory'){
          output=boundedList(rootFd,root,args.path,
            Math.min(args.depth??0,grant.constraints.maxDepth),grant.constraints.maxEntries);
        }else if(name==='write_file'){
          if(Buffer.byteLength(args.content,'utf8')>grant.constraints.maxBytes){
            throw fail('DENIED','Write content exceeds the granted size');
          }
          output=createOnlyWrite(rootFd,root,args.path,args.content);
        }else if(name==='list_processes'){
          output=jsonResult({jobs:jobs.slice(-grant.constraints.maxJobs).map(job=>({...job}))});
        }else{
          output=await runCountLines({rootFd,root,filename:args.path,
            timeoutMs:Math.min(commandTimeoutMs,grant.constraints.maxRuntimeMs),
            maxOutputBytes:grant.constraints.maxOutputBytes,
            signal,jobs,activeChildren,onSpawn:testHooks?.onCommandSpawn,
            afterFileOpen:testHooks?.afterFileOpen,
            failTestCommand:testHooks?.failCommandForTest===true,
            slowTestCommand:testHooks?.sleepCommandForTimeout===true});
        }
        await testHooks?.afterOperationBeforeOutcome?.({deviceId:frame.deviceId,
          requestId:frame.requestId,tool:name});
        if(signal?.aborted)throw fail('AMBIGUOUS_CANCELLED','Operation finished after caller cancellation');
      }catch(error){
        const code=typeof error?.code==='string'&&/^[A-Z_]{1,48}$/.test(error.code)?error.code:'OPERATION_FAILED';
        const ambiguous=code.startsWith('AMBIGUOUS_')||code==='LEDGER_WRITE_FAILED';
        const outcome={version:2,type:'outcome',requestId:frame.requestId,deviceId:frame.deviceId,
          tool:name,argumentHash,authorization:{...authorization},status:ambiguous?'ambiguous':'failed',
          resultHash:hash(code),exitCode:null,occurredAt:new Date().toISOString()};
        try{appendCurrentRecord(outcome);}catch{retainLock=true;uncertain=true;
          throw fail('LEDGER_WRITE_FAILED','Operation outcome could not be committed; lock retained');}
        throw error;
      }
      const serialized=JSON.stringify(output);
      const exitCode=name==='run_command'?output?.structuredContent?.exitCode:null;
      const failed=output?.isError===true||name==='run_command'&&exitCode!==0;
      const outcome={version:2,type:'outcome',requestId:frame.requestId,deviceId:frame.deviceId,
        tool:name,argumentHash,authorization:{...authorization},status:failed?'failed':'success',resultHash:hash(serialized),
        exitCode,
        occurredAt:new Date().toISOString()};
      try{appendCurrentRecord(outcome);}catch{retainLock=true;uncertain=true;
        throw fail('LEDGER_WRITE_FAILED','Operation outcome could not be committed; lock retained');}
      return output;
    }catch(error){
      if(error?.code==='LEDGER_CORRUPT'||error?.code==='LEDGER_WRITE_FAILED'){
        retainLock=true;uncertain=true;
      }
      throw error;
    }finally{
      if(!retainLock&&lockOwner){
        try{assertState();removeOwnedDurableProcessLock({directory:state,name:LOCK,owner:lockOwner});assertState();}
        catch{uncertain=true;throw fail('AMBIGUOUS_LOCK_RELEASE','Operation completed but execution lock release is uncertain');}
      }
    }
  }
  const activeOperations=new Set();
  function handle(frame,options){
    const operation=execute(frame,options);
    activeOperations.add(operation);
    return operation.finally(()=>activeOperations.delete(operation));
  }
  async function close(){
    if(closed)return;
    closed=true;
    for(const child of activeChildren){
      try{process.kill(-child.pid,'SIGTERM');}catch{try{child.kill('SIGTERM');}catch{}}
    }
    try{await local.close();}
    finally{
      await Promise.allSettled([...activeOperations]);
      closeSync(rootFd);closeSync(stateFd);
    }
  }
  return Object.freeze({start,handle,close,
    diagnostics:()=>inspectCurrentRecovery(),
    get uncertain(){return uncertain;}});
}
