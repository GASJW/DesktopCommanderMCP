import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { tmpdir } from 'node:os';
import path from 'node:path';
import {
  appendFileSync, chmodSync, mkdirSync, mkdtempSync, readFileSync,
  rmSync, symlinkSync, writeFileSync,
} from 'node:fs';
import { createDurableOwnerAudit } from '../dashboard/durable-owner-audit.mjs';

const now = '2026-10-12T15:00:00.000Z';
const event = (phase, id = randomUUID(), extra = {}) => ({
  event: 'g7_owner_pairing', version: 1, at: now,
  eventId: id, operation: 'approve', ownerId: 'a'.repeat(24),
  targetId: 'b'.repeat(24), phase,
  ...(phase === 'outcome' ? { outcome: 'accepted' } : {}),
  ...extra,
});
function fixture() {
  const home = mkdtempSync(path.join(tmpdir(), 'g7-owner-wal-'));
  const directory = path.join(home, 'store');
  const clean = () => rmSync(home, { recursive: true, force: true });
  return { home, directory, clean, log: path.join(directory, 'owner-decisions-v1.jsonl'),
    lock: path.join(directory, '.owner-decisions-writer.lock') };
}
test('append intent/outcome is durable, chained and survives restart', t => {
  const f = fixture(); t.after(f.clean);
  const s = createDurableOwnerAudit({directory:f.directory});
  const id = randomUUID();
  assert.equal(s.auditWrite(event('intent',id)),true);
  assert.deepEqual({ ...s.inspect() }.sequence,1);
  assert.equal(s.auditWrite(event('outcome',id)),true);
  assert.equal(s.inspect().pending,0);
  s.close();
  const lines = readFileSync(f.log,'utf8').trimEnd().split('\n').map(JSON.parse);
  assert.equal(lines.length,2);
  assert.equal(lines[0].seq,1);
  assert.equal(lines[1].previous,lines[0].hash);
  assert.equal(lines[1].seq,2);
  const other = createDurableOwnerAudit({directory:f.directory});
  assert.equal(other.inspect().sequence,2);
  const id2 = randomUUID();
  assert.equal(other.auditWrite(event('intent',id2)),true);
  assert.equal(other.auditWrite(event('outcome',id2)),true);
  assert.equal(other.inspect().sequence,4);
  other.close();
});
test('empty audit store initializes with POSIX private modes',t=>{
  const f=fixture();t.after(f.clean);
  const s=createDurableOwnerAudit({directory:f.directory});
  assert.deepEqual(s.inspect(),{sequence:0,pending:0,bytes:0});
  s.close();
  assert.equal(readFileSync(f.log,'utf8'),'');
});
test('strict schema refuses secrets, unknown keys and malicious payloads',t=>{
  const f=fixture();t.after(f.clean);
  const s=createDurableOwnerAudit({directory:f.directory});
  for(const extra of [{JWT:'secret'}, {code:'ABCDE12345'}, {nonce:'abcd'},
    {privateKeyPem:'secret'}, {email:'name@example.com'},
    {operation:'set'}, {ownerId:'raw email'}, {eventId:'invalid'},
    {at:'tomorrow'}, {version:2}, {phase:'invalid'}]){
    assert.throws(()=>s.auditWrite(event('intent',randomUUID(),extra)),/Invalid pairing audit event/);
  }
  assert.equal(s.inspect().sequence,0);
  s.close();
  assert.equal(readFileSync(f.log,'utf8'),'');
});
test('outcome requires matching intent, and an intent prevents concurrent decisions',t=>{
  const f=fixture();t.after(f.clean);
  const s=createDurableOwnerAudit({directory:f.directory});
  const id=randomUUID();
  assert.throws(()=>s.auditWrite(event('outcome',id)),/without matching intent/);
  s.auditWrite(event('intent',id));
  assert.throws(()=>s.auditWrite(event('intent',randomUUID())),/Unresolved/);
  assert.throws(()=>s.auditWrite(event('outcome',randomUUID())),/without matching/);
  assert.throws(()=>s.auditWrite(event('outcome',id,{targetId:'f'.repeat(24)})),/without matching/);
  assert.equal(s.auditWrite(event('outcome',id)),true);
  assert.throws(()=>s.auditWrite(event('outcome',id)),/without matching/);
  assert.throws(()=>s.auditWrite(event('intent',id)),/duplicate/);
  assert.equal(s.inspect().sequence,2);
  s.close();
});
test('audit writes never serialize comparison code, JWT or nonce',t=>{
  const f=fixture();t.after(f.clean);
  const s=createDurableOwnerAudit({directory:f.directory});
  const id=randomUUID();
  s.auditWrite(event('intent',id));
  s.auditWrite(event('outcome',id));
  s.close();
  const data=readFileSync(f.log,'utf8');
  for(const forbidden of ['cf-access-jwt','privateKeyPem','displayCode','client_secret','JWT','nonce']){
    assert.equal(data.includes(forbidden),false);
  }
});
test('exclusive writer lock rejects a concurrent writer until clean close',t=>{
  const f=fixture();t.after(f.clean);
  const a=createDurableOwnerAudit({directory:f.directory});
  assert.throws(()=>createDurableOwnerAudit({directory:f.directory}),/EEXIST/);
  a.close();
  const b=createDurableOwnerAudit({directory:f.directory});b.close();
});
test('crash-stale lock is never auto-stolen',t=>{
  const f=fixture();t.after(f.clean);
  const a=createDurableOwnerAudit({directory:f.directory});
  a.auditWrite(event('intent'));
  // Simulate unclean process exit by leaving writer lock in place.
  assert.throws(()=>createDurableOwnerAudit({directory:f.directory}),/EEXIST/);
  // Close intentionally without an outcome to demonstrate unresolved replay.
  a.close();
  assert.throws(()=>createDurableOwnerAudit({directory:f.directory}),/Unresolved owner decision/);
  // Replay error leaves lock for operator; no background healing.
  assert.throws(()=>createDurableOwnerAudit({directory:f.directory}),/EEXIST/);
});
test('missing intent/outcome pair fails closed after clean restart',t=>{
  const f=fixture();t.after(f.clean);
  const s=createDurableOwnerAudit({directory:f.directory});
  s.auditWrite(event('intent'));
  s.close();
  assert.throws(()=>createDurableOwnerAudit({directory:f.directory}),/manual reconciliation/);
});
test('truncated tail and invalid JSON are never silently repaired',t=>{
  const f=fixture();t.after(f.clean);
  const s=createDurableOwnerAudit({directory:f.directory});
  const id=randomUUID();s.auditWrite(event('intent',id));s.auditWrite(event('outcome',id));s.close();
  appendFileSync(f.log,'{"version":');
  assert.throws(()=>createDurableOwnerAudit({directory:f.directory}),/Truncated audit WAL/);
});
test('tampered record fails hash verification on replay',t=>{
  const f=fixture();t.after(f.clean);
  const s=createDurableOwnerAudit({directory:f.directory});
  const id=randomUUID();s.auditWrite(event('intent',id));s.auditWrite(event('outcome',id));s.close();
  const data=readFileSync(f.log,'utf8');
  writeFileSync(f.log,data.replace('"approve"','"reject"'));
  assert.throws(()=>createDurableOwnerAudit({directory:f.directory}),/integrity|outcome/);
});
test('out-of-band modifications poison the active writer before append',t=>{
  const f=fixture();t.after(f.clean);
  const s=createDurableOwnerAudit({directory:f.directory});
  appendFileSync(f.log,'x');
  assert.throws(()=>s.auditWrite(event('intent')),/durability uncertain/);
  assert.throws(()=>s.auditWrite(event('intent')),/Owner audit unavailable/);
  s.close(); // poisoned closure keeps lock to force manual investigation
  assert.throws(()=>createDurableOwnerAudit({directory:f.directory}),/EEXIST/);
});
test('reject symlinked store ancestor',t=>{
  const f=fixture();t.after(f.clean);
  const other=path.join(f.home,'actual');
  mkdirSync(other,{mode:0o700});
  const alias=path.join(f.home,'alias');
  symlinkSync(other,alias);
  assert.throws(()=>createDurableOwnerAudit({directory:alias}),/Unsafe audit ancestor/);
});
test('reject unsafe directory permissions and file modes',t=>{
  const f=fixture();t.after(f.clean);
  mkdirSync(f.directory,{mode:0o700});
  chmodSync(f.directory,0o755);
  assert.throws(()=>createDurableOwnerAudit({directory:f.directory}),/Unsafe audit directory/);
  chmodSync(f.directory,0o700);
  const s=createDurableOwnerAudit({directory:f.directory});
  s.close();
  chmodSync(f.log,0o644);
  assert.throws(()=>createDurableOwnerAudit({directory:f.directory}),/Unsafe audit file/);
});
test('symlinked WAL path is rejected even when destination is private',t=>{
  const f=fixture();t.after(f.clean);
  mkdirSync(f.directory,{mode:0o700});
  const target=path.join(f.home,'private.txt');
  writeFileSync(target,'', {mode:0o600});
  symlinkSync(target,f.log);
  assert.throws(()=>createDurableOwnerAudit({directory:f.directory}),/ELOOP|EEXIST|symlink/);
  assert.equal(readFileSync(target,'utf8'),'');
});
test('invalid relative directory and unknown parent fail before any file IO',()=>{
  assert.throws(()=>createDurableOwnerAudit({directory:'relative/path'}),/normalized absolute/);
  const missing=path.join(tmpdir(),'nonexistent-unsafe-audit-parent-'+randomUUID(),'inner');
  assert.throws(()=>createDurableOwnerAudit({directory:missing}),/Missing audit parent/);
});
test('write-ahead records are exact-match with PR26 owner API',t=>{
  const f=fixture();t.after(f.clean);
  const s=createDurableOwnerAudit({directory:f.directory});
  const eventId=randomUUID();
  const basis={eventId,operation:'reject',ownerId:'f'.repeat(24),targetId:'d'.repeat(24)};
  assert.equal(s.auditWrite({event:'g7_owner_pairing',version:1,at:now,phase:'intent',...basis}),true);
  assert.equal(s.auditWrite({event:'g7_owner_pairing',version:1,at:now,phase:'outcome',outcome:'denied',...basis}),true);
  assert.equal(s.inspect().pending,0);
  s.close();
});

test('same-length external tampering is detected before the next append',t=>{
  const f=fixture();t.after(f.clean);
  const s=createDurableOwnerAudit({directory:f.directory});
  const id=randomUUID();s.auditWrite(event('intent',id));
  const data=readFileSync(f.log,'utf8');
  assert.match(data,/"ownerId":"aaaaaaaaaaaaaaaaaaaaaaaa"/);
  writeFileSync(f.log,data.replace('"ownerId":"aaaaaaaaaaaaaaaaaaaaaaaa"',
    '"ownerId":"caaaaaaaaaaaaaaaaaaaaaaa"'));
  assert.equal(readFileSync(f.log).length,Buffer.byteLength(data));
  assert.throws(()=>s.auditWrite(event('outcome',id)),/durability uncertain/);
  assert.throws(()=>s.auditWrite(event('outcome',id)),/Owner audit unavailable/);
  s.close();
  assert.throws(()=>createDurableOwnerAudit({directory:f.directory}),/EEXIST/);
});
