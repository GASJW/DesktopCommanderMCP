import path from 'node:path';
import { createHash } from 'node:crypto';
import {
  constants, closeSync, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync,
  readFileSync, readSync, readdirSync, rmdirSync, writeSync,
} from 'node:fs';

// G7 candidate: inert, not imported by the production Gateway.
// POSIX single-writer append-only WAL. Failure is fail-closed; no auto-repair.
const LOG = 'owner-decisions-v1.jsonl';
const LOCK = '.owner-decisions-writer.lock';
const DOMAIN_V1 = 'VPSC-G7-OWNER-DECISION-AUDIT-v1\n';
const DOMAIN_V2 = 'VPSC-G7-OWNER-DECISION-AUDIT-v2\n';
const MAX_BYTES = 4 * 1024 * 1024;
const MAX_LINE = 1024;
const HEX24 = /^[a-f0-9]{24}$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const EXACT_INTENT = 'at,event,eventId,operation,ownerId,phase,targetId,version';
const EXACT_OUTCOME = 'at,event,eventId,operation,outcome,ownerId,phase,targetId,version';
const EXACT_INTENT_V2 = 'at,event,eventId,fingerprint,operation,ownerId,phase,requestId,trustRevisionBefore,version';
const EXACT_OUTCOME_V2 = 'at,deviceId,event,eventId,fingerprint,operation,outcome,ownerId,phase,requestId,trustRevisionAfter,trustRevisionBefore,version';

function privateDirectory(directory,{create=true}={}) {
  if (process.platform === 'win32' || typeof process.getuid !== 'function') {
    throw new Error('POSIX owner-only audit storage required');
  }
  if (typeof directory !== 'string' || !path.isAbsolute(directory) ||
      path.normalize(directory) !== directory || directory === '/') {
    throw new TypeError('Audit directory must be a normalized absolute path');
  }
  const parts = directory.split(path.sep).filter(Boolean);
  let current = path.sep;
  for (const part of parts) {
    current = path.join(current, part);
    try {
      const st = lstatSync(current);
      if (st.isSymbolicLink() || !st.isDirectory()) throw new Error('Unsafe audit ancestor');
    } catch (err) {
      if (err?.code !== 'ENOENT') throw err;
      // Only the final component may be created, never an unknown ancestor.
      if (current !== directory) throw new Error('Missing audit parent directory');
      if(!create)return false;
      mkdirSync(current, { mode: 0o700 });
    }
  }
  const st = lstatSync(directory);
  if (!st.isDirectory() || st.isSymbolicLink() ||
      st.uid !== process.getuid() || (st.mode & 0o7777) !== 0o700) {
    throw new Error('Unsafe audit directory owner or mode');
  }
  return true;
}
function privateFile(fd) {
  const st = fstatSync(fd);
  if (!st.isFile() || st.nlink !== 1 ||
      st.uid !== process.getuid() || (st.mode & 0o7777) !== 0o600 ||
      st.size > MAX_BYTES) throw new Error('Unsafe audit file');
  return st;
}
function verifyPath(file, fd) {
  const st = privateFile(fd);
  const named = lstatSync(file);
  if (named.isSymbolicLink() || named.ino !== st.ino || named.dev !== st.dev) {
    throw new Error('Audit file replaced or symlinked');
  }
  return st;
}
function syncDirectory(directory) {
  const fd = openSync(directory, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try { fsyncSync(fd); } finally { closeSync(fd); }
}
function auditLockEvidence(directory){
  const lock=path.join(directory,LOCK);
  let st;
  try{st=lstatSync(lock);}catch(error){
    if(error?.code==='ENOENT')return {path:lock,present:false};
    throw error;
  }
  if(!st.isDirectory()||st.isSymbolicLink()||st.uid!==process.getuid()||
     (st.mode&0o7777)!==0o700||readdirSync(lock).length!==0){
    throw Error('Unsafe owner audit writer lock');
  }
  return {path:lock,present:true};
}
function assertNoReconciliationLock(directory){
  const lock=path.join(directory,'.owner-pairing-reconciliation.lock');
  try{lstatSync(lock);}catch(error){if(error?.code==='ENOENT')return;throw error;}
  throw Error('Owner pairing reconciliation in progress; audit unavailable');
}
function canonicalEvent(e) {
  if (!e || typeof e !== 'object' || Array.isArray(e)) {
    throw new TypeError('Invalid pairing audit event');
  }
  const keys=Object.keys(e).sort().join(',');
  if(e.version===1){
    if(keys!==(e.phase==='intent'?EXACT_INTENT:EXACT_OUTCOME)||
       e.event!=='g7_owner_pairing'||!UUID.test(e.eventId)||!HEX24.test(e.ownerId)||
       !HEX24.test(e.targetId)||!['approve','reject'].includes(e.operation)||
       !['intent','outcome'].includes(e.phase)||
       (e.phase==='outcome'&&!['accepted','denied'].includes(e.outcome))){
      throw new TypeError('Invalid pairing audit event');
    }
    if(typeof e.at!=='string'||
       !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(e.at)||
       !Number.isFinite(Date.parse(e.at))||new Date(e.at).toISOString()!==e.at){
      throw new TypeError('Invalid pairing audit event');
    }
    return {event:'g7_owner_pairing',version:1,at:e.at,eventId:e.eventId.toLowerCase(),
      operation:e.operation,ownerId:e.ownerId,targetId:e.targetId,phase:e.phase,
      ...(e.phase==='outcome'?{outcome:e.outcome}:{})};
  }
  if(e.version!==2||keys!==(e.phase==='intent'?EXACT_INTENT_V2:EXACT_OUTCOME_V2)||
     e.event!=='g7_owner_pairing'||!UUID.test(e.eventId)||!HEX24.test(e.ownerId)||
     !UUID.test(e.requestId)||!/^[a-f0-9]{64}$/.test(e.fingerprint)||
     !Number.isSafeInteger(e.trustRevisionBefore)||e.trustRevisionBefore<0||
     !['approve','reject'].includes(e.operation)||!['intent','outcome'].includes(e.phase)||
     (e.phase==='outcome'&&(!['accepted','denied','not_applied'].includes(e.outcome)||
       (e.outcome==='not_applied'&&e.operation!=='approve')||
       !(e.deviceId===null||UUID.test(e.deviceId))||
       !Number.isSafeInteger(e.trustRevisionAfter)||e.trustRevisionAfter<0))){
    throw new TypeError('Invalid pairing audit event');
  }
  if(e.phase==='outcome'){
    const approved=e.operation==='approve'&&e.outcome==='accepted';
    if(approved?(!e.deviceId||e.trustRevisionAfter!==e.trustRevisionBefore+1):
       (e.deviceId!==null||e.trustRevisionAfter!==e.trustRevisionBefore)){
      throw new TypeError('Invalid pairing audit revision outcome');
    }
  }
  if(typeof e.at!=='string'||
     !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(e.at)||
     !Number.isFinite(Date.parse(e.at))||new Date(e.at).toISOString()!==e.at){
    throw new TypeError('Invalid pairing audit event');
  }
  if(e.phase==='intent')return {event:'g7_owner_pairing',version:2,at:e.at,
    eventId:e.eventId.toLowerCase(),operation:e.operation,ownerId:e.ownerId,
    requestId:e.requestId.toLowerCase(),fingerprint:e.fingerprint,
    trustRevisionBefore:e.trustRevisionBefore,phase:e.phase};
  return {event:'g7_owner_pairing',version:2,at:e.at,eventId:e.eventId.toLowerCase(),
    operation:e.operation,ownerId:e.ownerId,requestId:e.requestId.toLowerCase(),
    fingerprint:e.fingerprint,trustRevisionBefore:e.trustRevisionBefore,phase:e.phase,
    outcome:e.outcome,deviceId:e.deviceId?.toLowerCase()??null,
    trustRevisionAfter:e.trustRevisionAfter};
}
function digest(seq, previous, event,version=event.version) {
  return createHash('sha256')
    .update(version===1?DOMAIN_V1:DOMAIN_V2).update(JSON.stringify({ seq, previous, event }))
    .digest('hex');
}
function advance(state, event) {
  if (event.phase === 'intent') {
    if (state.pending.size !== 0 || state.completed.has(event.eventId)) {
      throw new Error('Unresolved or duplicate pairing audit intent');
    }
    state.pending.set(event.eventId, event);
  } else {
    const prior = state.pending.get(event.eventId);
    const sameDecision=prior&&prior.version===event.version&&prior.ownerId===event.ownerId&&
      prior.operation===event.operation&&
      (event.version===1?prior.targetId===event.targetId:
        prior.requestId===event.requestId&&prior.fingerprint===event.fingerprint&&
        prior.trustRevisionBefore===event.trustRevisionBefore);
    if (!sameDecision) {
      throw new Error('Pairing audit outcome without matching intent');
    }
    state.pending.delete(event.eventId);
    state.completed.add(event.eventId);
  }
}
function readExact(fd, size) {
  const result = Buffer.alloc(size);
  let n = 0;
  while (n < size) {
    const count = readSync(fd, result, n, size - n, n);
    if (count <= 0) throw new Error('Audit WAL short read');
    n += count;
  }
  return result;
}
function replay(bytes) {
  if (bytes.length > MAX_BYTES) throw new Error('Audit WAL capacity exceeded');
  const state = { seq: 0, hash: '0'.repeat(64), pending: new Map(), completed: new Set(),events:[] };
  if (bytes.length === 0) return state;
  if (bytes.at(-1) !== 10) throw new Error('Truncated audit WAL tail');
  const lines = bytes.toString('utf8').split('\n');
  lines.pop();
  for (const line of lines) {
    if (!line || Buffer.byteLength(line) > MAX_LINE) throw new Error('Invalid audit WAL line size');
    let record;
    try { record = JSON.parse(line); } catch { throw new Error('Corrupt audit WAL JSON'); }
    if (!record || Array.isArray(record) ||
        Object.keys(record).sort().join(',') !== 'event,hash,previous,seq,version' ||
        ![1,2].includes(record.version) || !Number.isSafeInteger(record.seq) ||
        record.seq !== state.seq + 1 || record.previous !== state.hash ||
        typeof record.hash !== 'string' || !/^[a-f0-9]{64}$/.test(record.hash)) {
      throw new Error('Invalid audit WAL sequence or header');
    }
    const event = canonicalEvent(record.event);
    if (event.version!==record.version||JSON.stringify(event) !== JSON.stringify(record.event) ||
        record.hash !== digest(record.seq, record.previous, event,record.version)) {
      throw new Error('Audit WAL event integrity mismatch');
    }
    advance(state, event);
    state.events.push(event);
    state.seq = record.seq;
    state.hash = record.hash;
  }
  return state;
}
export function createDurableOwnerAudit({ directory } = {}) {
  privateDirectory(directory);
  assertNoReconciliationLock(directory);
  const lock = path.join(directory, LOCK);
  // Exclusive mkdir fences ALL writers, including other processes. On a
  // crash, the lock is deliberately left behind for manual reconciliation.
  mkdirSync(lock, { mode: 0o700 });
  let blocked = true;
  let closed = false;
  const file = path.join(directory, LOG);
  let fd;
  try {
    const nofollow = constants.O_NOFOLLOW ?? 0;
    try {
      fd = openSync(file, constants.O_RDWR | constants.O_CREAT | constants.O_EXCL | nofollow, 0o600);
      fsyncSync(fd);
      syncDirectory(directory);
    } catch (err) {
      if (err?.code !== 'EEXIST') throw err;
      fd = openSync(file, constants.O_RDWR | nofollow);
    }
    const first = verifyPath(file, fd);
    let state = replay(readFileSync(fd));
    if (state.pending.size) throw new Error('Unresolved owner decision; manual reconciliation required');
    // A new lock (created in the directory) must itself be durably visible.
    syncDirectory(directory);
    let size = first.size;
    blocked = false;
    function requireHealthy() {
      if (closed || blocked) throw new Error('Owner audit unavailable; manual reconciliation required');
      assertNoReconciliationLock(directory);
    }
    function auditWrite(value) {
      requireHealthy();
      // Validation errors have no side-effects. Uncertain storage errors poison.
      const event = canonicalEvent(value);
      const candidate = {
        seq: state.seq, hash: state.hash,
        pending: new Map(state.pending), completed: new Set(state.completed),
      };
      advance(candidate, event);
      if (state.seq === Number.MAX_SAFE_INTEGER) throw new Error('Audit sequence exhausted');
      const seq = state.seq + 1;
      const hash = digest(seq, state.hash, event,event.version);
      const record = { version:event.version, seq, previous: state.hash, event, hash };
      const line = Buffer.from(JSON.stringify(record) + '\n');
      if (line.length > MAX_LINE || size + line.length > MAX_BYTES) {
        throw new Error('Audit WAL full; manual rotation required');
      }
      blocked = true;
      try {
        const stat = verifyPath(file, fd);
        if (stat.size !== size) throw new Error('Audit WAL changed outside active writer');
        const observed = replay(readExact(fd, size));
        if (observed.seq !== state.seq || observed.hash !== state.hash ||
            observed.pending.size !== state.pending.size ||
            observed.completed.size !== state.completed.size) {
          throw new Error('Audit WAL changed outside active writer');
        }
        assertNoReconciliationLock(directory);
        // O_RDWR descriptor must be positioned at known end; with one writer
        // the file offset may be at start following readFileSync(fd).
        const offset = size;
        let written = 0;
        while (written < line.length) {
          const n = writeSync(fd, line, written, line.length - written, offset + written);
          if (n <= 0) throw new Error('Audit WAL short write');
          written += n;
        }
        fsyncSync(fd);
        size += line.length;
        state = candidate;
        state.seq = seq;
        state.hash = hash;
        blocked = false;
        return true;
      } catch (error) {
        // Fail-closed, retain lock and descriptor until explicit close; a failed
        // append may have persisted a partial/complete record.
        throw new Error('Owner audit durability uncertain; manual reconciliation required', { cause: error });
      }
    }
    function inspect() {
      requireHealthy();
      return Object.freeze({ sequence: state.seq, pending: state.pending.size, bytes: size });
    }
    function close() {
      if (closed) return;
      closed = true;
      if (fd !== undefined) { closeSync(fd); fd = undefined; }
      if (blocked) return; // preserve lock on any uncertainty
      const st = lstatSync(lock);
      if (!st.isDirectory() || st.isSymbolicLink() ||
          st.uid !== process.getuid() || (st.mode & 0o7777) !== 0o700) {
        throw new Error('Audit writer lock changed unexpectedly');
      }
      rmdirSync(lock);
      syncDirectory(directory);
    }
    return Object.freeze({ auditWrite, inspect, close });
  } catch (error) {
    if (fd !== undefined) closeSync(fd);
    // Never auto-remove lock after an uncertain startup/replay failure.
    throw error;
  }
}

// Read-only audit evidence inspection. A persistent writer lock is reported,
// never cleared or interpreted as proof that its owner is dead.
export function inspectDurableOwnerAudit({directory}={}){
  const exists=privateDirectory(directory,{create:false});
  if(!exists)return Object.freeze({exists:false,sequence:0,hash:'0'.repeat(64),
    bytes:0,events:Object.freeze([]),pending:Object.freeze([]),lockPresent:false});
  const file=path.join(directory,LOG);
  let bytes=Buffer.alloc(0),logExists=false;
  try{
    const named=lstatSync(file);
    if(!named.isFile()||named.isSymbolicLink())throw Error('Unsafe audit file');
    const fd=openSync(file,constants.O_RDONLY|(constants.O_NOFOLLOW??0));
    try{verifyPath(file,fd);bytes=readFileSync(fd);logExists=true;}finally{closeSync(fd);}
  }catch(error){if(error?.code!=='ENOENT')throw error;}
  const state=replay(bytes);
  const lock=auditLockEvidence(directory);
  return Object.freeze({exists:logExists,sequence:state.seq,hash:state.hash,bytes:bytes.length,
    events:Object.freeze(state.events.slice()),
    pending:Object.freeze(Array.from(state.pending.values())),lockPresent:lock.present});
}

// The recovery coordinator calls this only after obtaining its own exclusive
// reconciliation lock and an explicit operator quiescence confirmation.
export function appendRecoveredOwnerOutcome({directory,intent,outcome,
  operatorConfirmedNoActiveWriters}={}){
  if(operatorConfirmedNoActiveWriters!==true){
    throw Error('Operator confirmation that no writers are active is required');
  }
  privateDirectory(directory);
  const recoveryLock=path.join(directory,'.owner-pairing-reconciliation.lock');
  const recoveryStat=lstatSync(recoveryLock);
  if(!recoveryStat.isDirectory()||recoveryStat.isSymbolicLink()||
     recoveryStat.uid!==process.getuid()||(recoveryStat.mode&0o7777)!==0o700||
     readdirSync(recoveryLock).length!==0){
    throw Error('Reconciliation lock required to append recovered outcome');
  }
  const lockPath=path.join(directory,LOCK);
  try{mkdirSync(lockPath,{mode:0o700});syncDirectory(directory);}
  catch(error){if(error?.code!=='EEXIST')throw error;}
  const lock=auditLockEvidence(directory);
  if(!lock.present)throw Error('Owner audit writer lock unavailable');
  const file=path.join(directory,LOG);
  const fd=openSync(file,constants.O_RDWR|(constants.O_NOFOLLOW??0));
  try{
    const first=verifyPath(file,fd);
    const bytes=readFileSync(fd);
    const state=replay(bytes);
    const pending=state.pending.get(intent?.eventId);
    if(state.pending.size!==1||!pending||JSON.stringify(pending)!==JSON.stringify(canonicalEvent(intent))){
      throw Error('Pending owner audit intent changed during reconciliation');
    }
    const event=canonicalEvent(outcome);
    advance(state,event);
    if(state.seq>=Number.MAX_SAFE_INTEGER)throw Error('Audit sequence exhausted');
    const seq=state.seq+1;
    const hash=digest(seq,state.hash,event,event.version);
    const record={version:event.version,seq,previous:state.hash,event,hash};
    const line=Buffer.from(JSON.stringify(record)+'\n');
    if(line.length>MAX_LINE||first.size+line.length>MAX_BYTES){
      throw Error('Audit WAL full; manual rotation required');
    }
    let written=0;
    while(written<line.length){
      const n=writeSync(fd,line,written,line.length-written,first.size+written);
      if(n<=0)throw Error('Audit WAL short write');
      written+=n;
    }
    fsyncSync(fd);
    return Object.freeze({sequence:seq,hash});
  }finally{closeSync(fd);}
}

export function releaseOwnerAuditLockForReconciliation({directory,expectedSequence,
  expectedHash,operatorConfirmedNoActiveWriters}={}){
  if(operatorConfirmedNoActiveWriters!==true){
    throw Error('Operator confirmation that no writers are active is required');
  }
  const recoveryLock=path.join(directory,'.owner-pairing-reconciliation.lock');
  const recoveryStat=lstatSync(recoveryLock);
  if(!recoveryStat.isDirectory()||recoveryStat.isSymbolicLink()||
     recoveryStat.uid!==process.getuid()||(recoveryStat.mode&0o7777)!==0o700||
     readdirSync(recoveryLock).length!==0){
    throw Error('Reconciliation lock required to release owner audit lock');
  }
  const evidence=inspectDurableOwnerAudit({directory});
  if(evidence.sequence!==expectedSequence||evidence.hash!==expectedHash||evidence.pending.length){
    throw Error('Owner audit evidence changed during reconciliation');
  }
  if(!evidence.lockPresent)return false;
  const lock=auditLockEvidence(directory);
  rmdirSync(lock.path);
  syncDirectory(directory);
  return true;
}
