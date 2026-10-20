import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomUUID } from 'node:crypto';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createIsolatedG7Realm, validateIsolatedG7RealmConfig }
  from '../owner/isolated-realm.mjs';

function fixture() {
  const home = mkdtempSync(path.join(tmpdir(), 'g7-i8f-realm-'));
  const storageRoot = path.join(home, 'i8f');
  const legacyRoot = path.join(home, 'i7');
  mkdirSync(storageRoot);
  mkdirSync(legacyRoot);
  const paths = { storageRoot, configFile: path.join(storageRoot, 'config.json') };
  for (const name of ['auditDirectory', 'bindingDirectory', 'grantDirectory', 'ledgerDirectory',
    'ownerAuthorityDirectory', 'policyDirectory', 'provisioningDirectory', 'runtimeDirectory', 'trustDirectory']) {
    paths[name] = path.join(storageRoot, name);
    mkdirSync(paths[name]);
  }
  writeFileSync(paths.configFile, '{}\n');
  const control = generateKeyPairSync('ed25519');
  const publicKeyPem = control.publicKey.export({ type: 'spki', format: 'pem' });
  const fingerprint = createHash('sha256').update(control.publicKey.export({ type: 'spki', format: 'der' })).digest('hex');
  const realmId = randomUUID();
  const config = { version: 1, realmId, listen: { host: '127.0.0.1', port: 19443 }, paths,
    controlIdentity: { algorithm: 'Ed25519', keyId: 'i8f-control-test', publicKeyPem, fingerprint },
    protectedKeyFingerprints: ['f'.repeat(64)], protectedPaths: [legacyRoot] };
  const ownerAuthority = { directory: paths.ownerAuthorityDirectory, realmId,
    inspect: () => ({ status: 'active', pendingCount: 0, lockPresent: false, healthy: true,
      owner: { ownerId: 'a'.repeat(24) } }),
    verifyReadPrincipal: () => null, verifyAdminPrincipal: () => null };
  const storeInspectors = Object.fromEntries(['audit', 'binding', 'grant', 'ledger', 'policy', 'trust']
    .map(name => [name, () => ({ healthy: true, pending: 0, revision: 0 })]));
  storeInspectors.provisioning = () => ({ healthy: true, pending: 0, revision: 0, readyDeviceCount: 1 });
  return { home, config, ownerAuthority, storeInspectors, storageRoot, legacyRoot,
    cleanup: () => rmSync(home, { recursive: true, force: true }) };
}

test('isolated realm refuses legacy overlap and overlapping store paths', t => {
  const f = fixture(); t.after(f.cleanup);
  assert.throws(() => validateIsolatedG7RealmConfig({ ...f.config,
    protectedPaths: [f.storageRoot] }), /overlaps an existing G7 realm/);
  assert.throws(() => validateIsolatedG7RealmConfig({ ...f.config, paths: {
    ...f.config.paths, grantDirectory: f.config.paths.bindingDirectory,
  } }), /overlap or share/);
  assert.throws(() => validateIsolatedG7RealmConfig({ ...f.config, paths: {
    ...f.config.paths, ledgerDirectory: path.join(f.home, 'outside-ledger'),
  } }), /remain under their storage root/);
});

test('isolated realm activation is fail-closed and starts only loopback read_file after all inspectors pass', async t => {
  const f = fixture(); t.after(f.cleanup);
  let allowOwner = false;
  let started = 0;
  const ownerAuthority = { ...f.ownerAuthority, inspect: () => ({
    status: allowOwner ? 'active' : 'empty', pendingCount: 0, lockPresent: false,
    healthy: true, owner: allowOwner ? { ownerId: 'a'.repeat(24) } : null,
  }) };
  let storeReady = false;
  const inspectors = Object.fromEntries(Object.keys(f.storeInspectors).map(name => [name, () => ({
    healthy: storeReady, pending: 0, revision: 0,
    ...(name==='provisioning'?{readyDeviceCount:storeReady?1:0}:{}),
  })]));
  const realm = createIsolatedG7Realm({ config: f.config, ownerAuthority, storeInspectors: inspectors,
    startLoopback: async options => { started++; return { ...options, close: () => {} }; } });
  assert.equal(realm.inspectActivation().ready, false);
  await assert.rejects(realm.activate(), error => error.code === 'REALM_ACTIVATION_BLOCKED');
  assert.equal(started, 0);
  allowOwner = true;
  storeReady = true;
  const server = await realm.activate();
  assert.equal(server.host, '127.0.0.1');
  assert.deepEqual(server.tools, ['read_file']);
  assert.equal(server.port, 19443);
  assert.equal(started, 1);
  assert.equal(await realm.activate(), server);
  assert.equal(started, 1);
});

test('Owner revocation during listener startup closes the listener before activation returns', async t => {
  const f = fixture(); t.after(f.cleanup);
  let ownerActive = true;
  let closed = false;
  const ownerAuthority = { ...f.ownerAuthority, inspect: () => ({
    status: ownerActive ? 'active' : 'revoked', pendingCount: 0,
    lockPresent: false, healthy: true, owner: ownerActive ? { ownerId: 'a'.repeat(24) } : null,
  }) };
  const realm = createIsolatedG7Realm({ config: f.config, ownerAuthority,
    storeInspectors: f.storeInspectors,
    startLoopback: async options => {
      const listener = { ...options, close: () => { closed = true; } };
      ownerActive = false;
      return listener;
    } });
  await assert.rejects(realm.activate(), error => error.code === 'REALM_ACTIVATION_BLOCKED');
  assert.equal(closed, true);
  assert.equal(realm.inspectActivation().ready, false);
});

test('activation remains closed without a read grant and closes if provisioning changes during startup',async t=>{
  const f=fixture();t.after(f.cleanup);
  let readyDeviceCount=0,closed=false,started=0;
  const inspectors={...f.storeInspectors,
    provisioning:()=>({healthy:true,pending:0,revision:0,readyDeviceCount})};
  const realm=createIsolatedG7Realm({config:f.config,ownerAuthority:f.ownerAuthority,
    storeInspectors:inspectors,startLoopback:async options=>{
      started++;readyDeviceCount=1;
      return {...options,close:()=>{closed=true;}};
    }});
  await assert.rejects(realm.activate(),error=>error.code==='REALM_ACTIVATION_BLOCKED'&&
    error.blockers.includes('NO_APPROVED_READ_ONLY_DEVICE'));
  assert.equal(started,0);
  readyDeviceCount=1;
  const later=createIsolatedG7Realm({config:f.config,ownerAuthority:f.ownerAuthority,
    storeInspectors:inspectors,startLoopback:async options=>{
      started++;readyDeviceCount=0;
      return {...options,close:()=>{closed=true;}};
    }});
  await assert.rejects(later.activate(),error=>error.code==='REALM_ACTIVATION_BLOCKED'&&
    error.blockers.includes('NO_APPROVED_READ_ONLY_DEVICE'));
  assert.equal(closed,true);
});

test('an interrupted activation attempt leaves no cached listener and rechecks the barrier on retry',async t=>{
  const f=fixture();t.after(f.cleanup);
  let attempts=0,closed=false;
  const realm=createIsolatedG7Realm({config:f.config,ownerAuthority:f.ownerAuthority,
    storeInspectors:f.storeInspectors,startLoopback:async options=>{
      attempts++;
      if(attempts===1)throw Error('injected activation interruption');
      return {...options,close:()=>{closed=true;}};
    }});
  await assert.rejects(realm.activate(),/injected activation interruption/);
  assert.equal(realm.inspectActivation().ready,true);
  const server=await realm.activate();
  assert.equal(server.host,'127.0.0.1');
  assert.equal(attempts,2);
  assert.equal(closed,false);
});
