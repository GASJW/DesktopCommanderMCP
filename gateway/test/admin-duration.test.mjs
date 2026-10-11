import test from 'node:test';
import assert from 'node:assert/strict';
import { ADMIN_DURATION_OPTIONS, adminWindowStatus, planAdminAccessWindow } from '../admin/privilege-duration.mjs';

const START = 1_800_000_000_000;

test('four fixed durations, including explicit indefinite, are immutable', () => {
  assert.deepEqual(ADMIN_DURATION_OPTIONS.map(x => x.id), ['10m','30m','60m','indefinite']);
  assert.deepEqual(ADMIN_DURATION_OPTIONS.map(x => x.milliseconds), [600_000,1_800_000,3_600_000,null]);
  assert.match(ADMIN_DURATION_OPTIONS[3].label, /Indefinida.*revogação manual/);
  assert.equal(Object.isFrozen(ADMIN_DURATION_OPTIONS), true);
  assert.equal(ADMIN_DURATION_OPTIONS.every(Object.isFrozen), true);
});

for (const [id, milliseconds] of [['10m',600_000],['30m',1_800_000],['60m',3_600_000]]) {
  test('finite window ' + id + ' expires at deadline', () => {
    const plan = planAdminAccessWindow(id, START);
    assert.equal(plan.expiresAt, START + milliseconds);
    assert.equal(adminWindowStatus(plan, {now: START + milliseconds - 1}), 'within_window');
    assert.equal(adminWindowStatus(plan, {now: START + milliseconds}), 'expired');
    assert.equal(adminWindowStatus(plan, {now: START + milliseconds + 1}), 'expired');
  });
}
test('indefinite never expires based on elapsed time but is revocable', () => {
  const plan = planAdminAccessWindow('indefinite', START);
  assert.deepEqual(plan, { durationId:'indefinite', approvedAt:START, expiresAt:null });
  assert.equal(adminWindowStatus(plan, {now:START}), 'within_window');
  assert.equal(adminWindowStatus(plan, {now:START + 1_000_000_000}), 'within_window');
  assert.equal(adminWindowStatus(plan, {now:START + 1_000_000_000, revokedAt:START + 10}), 'revoked');
});
test('revocation wins over all active or expired durations', () => {
  for (const id of ['10m','indefinite']) {
    const plan = planAdminAccessWindow(id, START);
    assert.equal(adminWindowStatus(plan, {now:START,revokedAt:START}), 'revoked');
    assert.equal(adminWindowStatus(plan, {now:START + 9_000_000, revokedAt:START + 100}), 'revoked');
  }
});
test('future approval is not yet valid', () => {
  assert.equal(adminWindowStatus(planAdminAccessWindow('indefinite', START), {now:START-1}), 'not_started');
});
test('forged and inconsistent expiry are invalid', () => {
  const infinite = planAdminAccessWindow('indefinite', START);
  assert.equal(adminWindowStatus({...infinite,expiresAt:START+12}, {now:START}), 'invalid');
  const finite = planAdminAccessWindow('10m', START);
  assert.equal(adminWindowStatus({...finite,expiresAt:null}, {now:START}), 'invalid');
  assert.equal(adminWindowStatus({...finite,expiresAt:START+600_001}, {now:START}), 'invalid');
});
test('unknown duration, incorrect timestamp or expiry overflow fail closed', () => {
  for (const value of ['forever','root','none','0',null,undefined,30]) {
    assert.throws(() => planAdminAccessWindow(value, START), /Invalid administrative duration/);
  }
  for (const time of [NaN,Infinity,-1,1.5,'100',Number.MAX_SAFE_INTEGER]) {
    assert.throws(() => planAdminAccessWindow('10m', time));
    assert.equal(adminWindowStatus(planAdminAccessWindow('10m',START), {now:time}), 'invalid');
  }
  assert.throws(() => planAdminAccessWindow('60m', 8_640_000_000_000_000-1), /overflow/);
});
test('plans do not create grants or contain device credentials', () => {
  const result = planAdminAccessWindow('indefinite', START);
  assert.deepEqual(Object.keys(result).sort(), ['approvedAt','durationId','expiresAt']);
  assert.equal('token' in result, false);
  assert.equal('grant' in result, false);
  assert.equal(Object.isFrozen(result), true);
});
test('invalid windows cannot be active', () => {
  const plan = planAdminAccessWindow('indefinite', START);
  for (const bad of [null,undefined,{},[],{...plan,durationId:'root'},{...plan,approvedAt:START+.5}]) {
    assert.equal(adminWindowStatus(bad, {now:START}), 'invalid');
  }
  assert.equal(adminWindowStatus(plan, {}), 'invalid');
  assert.equal(adminWindowStatus(plan, {now:START,revokedAt:-1}), 'invalid');
});
