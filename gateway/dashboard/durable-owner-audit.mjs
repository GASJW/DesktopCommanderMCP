import path from 'node:path';
import { createHash } from 'node:crypto';
import {
  constants, closeSync, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync,
  readFileSync, readSync, rmdirSync, writeSync,
} from 'node:fs';

// G7 candidate: inert, not imported by the production Gateway.
// POSIX single-writer append-only WAL. Failure is fail-closed; no auto-repair.
const LOG = 'owner-decisions-v1.jsonl';
const LOCK = '.owner-decisions-writer.lock';
const DOMAIN = 'VPSC-G7-OWNER-DECISION-AUDIT-v1\n';
const MAX_BYTES = 4 * 1024 * 1024;
const MAX_LINE = 1024;
const HEX24 = /^[a-f0-9]{24}$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const EXACT_INTENT = 'at,event,eventId,operation,ownerId,phase,targetId,version';
const EXACT_OUTCOME = 'at,event,eventId,operation,outcome,ownerId,phase,targetId,version';

function privateDirectory(directory) {
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
      mkdirSync(current, { mode: 0o700 });
    }
  }
  const st = lstatSync(directory);
  if (!st.isDirectory() || st.isSymbolicLink() ||
      st.uid !== process.getuid() || (st.mode & 0o7777) !== 0o700) {
    throw new Error('Unsafe audit directory owner or mode');
  }
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
function canonicalEvent(e) {
  if (!e || typeof e !== 'object' || Array.isArray(e)) {
    throw new TypeError('Invalid pairing audit event');
  }
  const keys = Object.keys(e).sort().join(',');
  if (keys !== (e.phase === 'intent' ? EXACT_INTENT : EXACT_OUTCOME) ||
      e.event !== 'g7_owner_pairing' || e.version !== 1 ||
      !UUID.test(e.eventId) || !HEX24.test(e.ownerId) || !HEX24.test(e.targetId) ||
      !['approve', 'reject'].includes(e.operation) ||
      !['intent', 'outcome'].includes(e.phase) ||
      (e.phase === 'outcome' && !['accepted', 'denied'].includes(e.outcome)) ||
      typeof e.at !== 'string' ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(e.at) ||
      !Number.isFinite(Date.parse(e.at)) ||
      new Date(e.at).toISOString() !== e.at) {
    throw new TypeError('Invalid pairing audit event');
  }
  return {
    event: 'g7_owner_pairing', version: 1, at: e.at,
    eventId: e.eventId.toLowerCase(), operation: e.operation,
    ownerId: e.ownerId, targetId: e.targetId, phase: e.phase,
    ...(e.phase === 'outcome' ? { outcome: e.outcome } : {}),
  };
}
function digest(seq, previous, event) {
  return createHash('sha256')
    .update(DOMAIN).update(JSON.stringify({ seq, previous, event }))
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
    if (!prior || prior.ownerId !== event.ownerId || prior.targetId !== event.targetId ||
        prior.operation !== event.operation) {
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
  const state = { seq: 0, hash: '0'.repeat(64), pending: new Map(), completed: new Set() };
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
        record.version !== 1 || !Number.isSafeInteger(record.seq) ||
        record.seq !== state.seq + 1 || record.previous !== state.hash ||
        typeof record.hash !== 'string' || !/^[a-f0-9]{64}$/.test(record.hash)) {
      throw new Error('Invalid audit WAL sequence or header');
    }
    const event = canonicalEvent(record.event);
    if (JSON.stringify(event) !== JSON.stringify(record.event) ||
        record.hash !== digest(record.seq, record.previous, event)) {
      throw new Error('Audit WAL event integrity mismatch');
    }
    advance(state, event);
    state.seq = record.seq;
    state.hash = record.hash;
  }
  return state;
}
export function createDurableOwnerAudit({ directory } = {}) {
  privateDirectory(directory);
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
      const hash = digest(seq, state.hash, event);
      const record = { version: 1, seq, previous: state.hash, event, hash };
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
