import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { tmpdir } from 'node:os';
import path from 'node:path';
import {
  appendFileSync, chmodSync, mkdirSync, mkdtempSync, readFileSync,
  rmSync, symlinkSync, writeFileSync,
} from 'node:fs';
import { createDurableOwnerAudit, readDurableOwnerMachineBindingDecision,
  readDurableOwnerMachineBindingHistory } from '../dashboard/durable-owner-audit.mjs';

const now = '2026-10-12T15:00:00.000Z';
const event = (phase, id = randomUUID(), extra = {}) => ({
  event: 'g7_owner_pairing', version: 1, at: now,
  eventId: id, operation: 'approve', ownerId: 'a'.repeat(24),
  targetId: 'b'.repeat(24), phase,
  ...(phase === 'outcome' ? { outcome: 'accepted' } : {}),
  ...extra,
});
const correlatedEvent = (phase, id = randomUUID(), extra = {}) => ({
  event:'g7_owner_pairing',version:2,at:now,eventId:id,operation:'approve',
  ownerId:'a'.repeat(24),requestId:'8f15a479-cc22-448d-a0ca-918a9c67d5f5',
  fingerprint:'b'.repeat(64),trustRevisionBefore:4,phase,
  ...(phase==='outcome'?{outcome:'accepted',deviceId:'f69ec00e-f225-43df-bdc7-c2cbf8f4a9f3',
    trustRevisionAfter:5}:{}),
  ...extra,
});
const machineBindingEvent = (phase, id = randomUUID(), extra = {}) => ({
  event:'g7_owner_machine_binding',version:3,at:now,eventId:id,operation:'bind',
  ownerId:'a'.repeat(24),ownerDigest:'c'.repeat(64),clientId:'vpsc-test-client-0001',
  deviceId:'f69ec00e-f225-43df-bdc7-c2cbf8f4a9f3',fingerprint:'b'.repeat(64),
  approvalEventId:'e3d3147b-9325-4d42-a4e1-e9b219e5b02d',trustRevisionBefore:4,
  trustRevisionAfter:5,trustRevision:5,bindingRevisionBefore:8,phase,
  ...(phase==='outcome'?{outcome:'accepted',bindingRevisionAfter:9}:{}),
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
test('isolated realm approval audit rejects unknown phases',t=>{
  const f=fixture();t.after(f.clean);
  const s=createDurableOwnerAudit({directory:f.directory});
  const eventId=randomUUID(),realmId='95bdac79-90de-4abc-b667-401087631b37';
  assert.throws(()=>s.auditWrite({event:'g7_realm_owner_approval',version:1,
    at:now,eventId,realmId,operation:'grant.issue',ownerId:'c'.repeat(24),
    ownerDigest:'c'.repeat(64),deviceId:'f69ec00e-f225-43df-bdc7-c2cbf8f4a9f3',
    fingerprint:'b'.repeat(64),expectedRevision:0,targetDigest:'d'.repeat(64),verifiedAt:2,
    approval:{version:1,eventId,operation:'grant.issue',realmId,
      ownerDigest:'c'.repeat(64),expectedRevision:0,targetDigest:'d'.repeat(64),
      issuedAt:1,expiresAt:301,keyId:'test-key',signature:'A'.repeat(86)},
    phase:'pending',outcome:'applied'}),/Invalid isolated realm Owner approval event/);
  assert.equal(s.inspect().sequence,0);
  s.close();
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

test('v2 WAL preserves request, fingerprint, device and exact trust revision binding across restart',t=>{
  const f=fixture();t.after(f.clean);
  const s=createDurableOwnerAudit({directory:f.directory});
  const id='e3d3147b-9325-4d42-a4e1-e9b219e5b02d';
  assert.equal(s.auditWrite(correlatedEvent('intent',id)),true);
  assert.equal(s.auditWrite(correlatedEvent('outcome',id)),true);
  s.close();
  const records=readFileSync(f.log,'utf8').trimEnd().split('\n').map(JSON.parse);
  assert.deepEqual(records.map(x=>x.event.phase),['intent','outcome']);
  assert.equal(records[0].event.requestId,'8f15a479-cc22-448d-a0ca-918a9c67d5f5');
  assert.equal(records[0].event.fingerprint,'b'.repeat(64));
  assert.equal(records[1].event.deviceId,'f69ec00e-f225-43df-bdc7-c2cbf8f4a9f3');
  assert.equal(records[1].event.trustRevisionBefore,4);
  assert.equal(records[1].event.trustRevisionAfter,5);
  const restarted=createDurableOwnerAudit({directory:f.directory});
  assert.equal(restarted.inspect().sequence,2);
  restarted.close();
});
test('not_applied cannot certify an ephemeral rejection result',t=>{
  const f=fixture();t.after(f.clean);
  const s=createDurableOwnerAudit({directory:f.directory});
  const id=randomUUID();
  assert.equal(s.auditWrite(correlatedEvent('intent',id,{operation:'reject'})),true);
  assert.throws(()=>s.auditWrite(correlatedEvent('outcome',id,{operation:'reject',
    outcome:'not_applied',deviceId:null,trustRevisionAfter:4})),/Invalid pairing audit event/);
  assert.equal(s.inspect().sequence,1);
  s.close();
});

test('v3 machine binding intent/outcome pair is exact, append-only and survives restart',t=>{
  const f=fixture();t.after(f.clean);
  const s=createDurableOwnerAudit({directory:f.directory});
  const id=randomUUID();
  const intent=machineBindingEvent('intent',id);
  const outcome=machineBindingEvent('outcome',id);
  assert.equal(s.auditWrite(intent),true);
  assert.equal(s.auditWrite(outcome),true);
  assert.equal(s.inspect().pending,0);
  s.close();
  const records=readFileSync(f.log,'utf8').trimEnd().split('\n').map(JSON.parse);
  assert.deepEqual(records.map(record=>record.version),[3,3]);
  assert.deepEqual(records.map(record=>record.event.phase),['intent','outcome']);
  assert.equal(records[0].event.event,'g7_owner_machine_binding');
  assert.equal(records[1].event.eventId,id);
  assert.equal(records[1].event.ownerDigest,'c'.repeat(64));
  assert.equal(records[1].event.approvalEventId,'e3d3147b-9325-4d42-a4e1-e9b219e5b02d');
  assert.equal(records[1].event.bindingRevisionBefore,8);
  assert.equal(records[1].event.bindingRevisionAfter,9);
  assert.equal(records[1].previous,records[0].hash);
  const read=readDurableOwnerMachineBindingDecision({directory:f.directory,eventId:id});
  assert.equal(read.state,'COMPLETE');
  assert.equal(read.intent.eventId,id);
  assert.equal(read.outcome.bindingRevisionAfter,9);
  assert.equal(readDurableOwnerMachineBindingDecision({directory:f.directory,
    eventId:randomUUID()}).state,'NOT_FOUND');
  const restarted=createDurableOwnerAudit({directory:f.directory});
  assert.equal(restarted.inspect().sequence,2);
  restarted.close();
});

test('machine binding outcome cannot be paired with a different identity or revision',t=>{
  const f=fixture();t.after(f.clean);
  const s=createDurableOwnerAudit({directory:f.directory});
  const id=randomUUID();
  s.auditWrite(machineBindingEvent('intent',id));
  assert.equal(readDurableOwnerMachineBindingDecision({directory:f.directory,eventId:id}).state,
    'PENDING');
  for(const extra of [{ownerDigest:'d'.repeat(64)},
    {clientId:'vpsc-test-client-0002'},
    {deviceId:'25e1ccbf-ed9b-4cb0-8292-6b43d9b7704a'},
    {fingerprint:'e'.repeat(64)},
    {approvalEventId:'25e1ccbf-ed9b-4cb0-8292-6b43d9b7704a'},
    {trustRevision:6},
    {bindingRevisionBefore:9,bindingRevisionAfter:10}]){
    assert.throws(()=>s.auditWrite(machineBindingEvent('outcome',id,extra)),
      /without matching intent/);
  }
  assert.equal(s.auditWrite(machineBindingEvent('outcome',id)),true);
  assert.equal(s.inspect().pending,0);
  s.close();
});

test('machine binding event accepts the existing maximum Client-ID length',t=>{
  const f=fixture();t.after(f.clean);
  const s=createDurableOwnerAudit({directory:f.directory});
  const id=randomUUID();
  const clientId='c'.repeat(256);
  assert.equal(s.auditWrite(machineBindingEvent('intent',id,{clientId})),true);
  assert.equal(s.auditWrite(machineBindingEvent('outcome',id,{clientId})),true);
  s.close();
});

test('machine binding history enumerates complete and pending decisions from the validated WAL',t=>{
  const f=fixture();t.after(f.clean);
  const s=createDurableOwnerAudit({directory:f.directory});
  const completeId=randomUUID(),pendingId=randomUUID();
  s.auditWrite(machineBindingEvent('intent',completeId));
  s.auditWrite(machineBindingEvent('outcome',completeId));
  s.auditWrite(machineBindingEvent('intent',pendingId));
  s.close();
  const history=readDurableOwnerMachineBindingHistory({directory:f.directory});
  assert.deepEqual(history.completed.map(item=>item.eventId),[completeId]);
  assert.deepEqual(history.pending.map(item=>item.eventId),[pendingId]);
});
