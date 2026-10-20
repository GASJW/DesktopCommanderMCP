import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createAuth0OwnerVerifier } from '../owner/auth0-owner-auth.mjs';
import { createDurableOwnerAuthority, ownerAuthorityApprovalSigningBytes,
  ownerAuthorityRecoveryTargetDigest, ownerAuthorityTargetDigest }
  from '../owner/durable-owner-authority.mjs';
import { inspectDurableOwnerAudit } from '../dashboard/durable-owner-audit.mjs';
import { createIsolatedG7Realm } from '../owner/isolated-realm.mjs';

const linuxUnprivileged = process.platform === 'linux' && typeof process.getuid === 'function' && process.getuid() !== 0;
const ISSUER = 'https://auth.example.test/';
const RESOURCE = 'https://g7.example.test/chatgpt/mcp';
const CLIENT = 'chatgpt-cimd-test';
const REALM = '2ef5ae2e-bcf0-4bd2-8f2c-4f5c5edab982';
const NOW = Date.now();
const seconds = Math.floor(NOW / 1000);

function b64(value) { return Buffer.from(JSON.stringify(value)).toString('base64url'); }

function fixture() {
  const root = mkdtempSync(path.join(tmpdir(), 'g7-i8f-owner-'));
  chmodSync(root, 0o700);
  const directory = path.join(root, 'authority');
  mkdirSync(directory, { mode: 0o700 });
  chmodSync(directory, 0o700);
  const auth = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const approval = generateKeyPairSync('ed25519');
  const authJwk = { ...auth.publicKey.export({ format: 'jwk' }), kid: 'auth0-test', alg: 'RS256', use: 'sig' };
  const approvalJwk = { ...approval.publicKey.export({ format: 'jwk' }), kid: 'operator-test' };
  const verifierConfig = { issuer: ISSUER, resource: RESOURCE, authorizedClientIds: [CLIENT],
    readScope: 'g7.read', ownerScope: 'g7.owner', jwks: [authJwk] };
  const verifier = createAuth0OwnerVerifier(verifierConfig, { now: () => NOW });
  const payload = { iss: ISSUER, sub: 'google-oauth2|synthetic-owner', aud: RESOURCE,
    client_id: CLIENT, scope: 'g7.read', iat: seconds, exp: seconds + 600 };
  const makeToken = (scope = 'g7.read', subject = payload.sub) => {
    const header = b64({ alg: 'RS256', kid: authJwk.kid, typ: 'JWT' });
    const claims = b64({ ...payload, scope, sub: subject });
    const input = `${header}.${claims}`;
    return `${input}.${sign('RSA-SHA256', Buffer.from(input), auth.privateKey).toString('base64url')}`;
  };
  const accessToken = makeToken();
  const principal = verifier.verifyPrincipal(accessToken);
  const authorityConfig = { directory, realmId: REALM, issuer: ISSUER, verifier,
    approvalJwks: [approvalJwk], now: () => NOW };
  const authority = createDurableOwnerAuthority(authorityConfig);
  const makeApproval = ({ operation, eventId = randomUUID(), expectedRevision,
    ownerDigest, targetDigest, key = approval.privateKey, keyId = approvalJwk.kid }) => {
    const fields = { version: 1, realmId: REALM, eventId, operation, expectedRevision,
      ownerDigest, targetDigest, issuedAt: seconds, expiresAt: seconds + 120, keyId };
    return { ...fields, signature: sign(null, ownerAuthorityApprovalSigningBytes(
      { ...fields, signature: 'A'.repeat(86) }), key).toString('base64url') };
  };
  return { root, directory, verifierConfig, verifier, accessToken, principal, authority, makeToken,
    approvalPrivateKey: approval.privateKey, approvalJwk, approvalJwks: [approvalJwk], makeApproval,
    cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

function bootstrapApproval(f, eventId = randomUUID()) {
  return f.makeApproval({ operation: 'bootstrap', eventId, expectedRevision: 0,
    ownerDigest: f.principal.ownerDigest,
    targetDigest: ownerAuthorityTargetDigest('bootstrap', {
      issuer: f.principal.issuer, ownerDigest: f.principal.ownerDigest,
    }) });
}

function createActivationRealm(f) {
  const paths = { storageRoot: f.root, configFile: path.join(f.root, 'config.json'),
    ownerAuthorityDirectory: f.directory };
  for (const name of ['auditDirectory', 'bindingDirectory', 'grantDirectory', 'ledgerDirectory',
    'policyDirectory', 'runtimeDirectory', 'trustDirectory']) {
    paths[name] = path.join(f.root, name);
    mkdirSync(paths[name], { mode: 0o700 });
    chmodSync(paths[name], 0o700);
  }
  writeFileSync(paths.configFile, '{}\n', { mode: 0o600 });
  const legacyRoot = path.join(tmpdir(), `g7-i8f-legacy-${randomUUID()}`);
  mkdirSync(legacyRoot, { mode: 0o700 });
  const control = generateKeyPairSync('ed25519');
  const publicKeyPem = control.publicKey.export({ type: 'spki', format: 'pem' });
  const fingerprint = createHash('sha256')
    .update(control.publicKey.export({ type: 'spki', format: 'der' })).digest('hex');
  const config = { version: 1, realmId: REALM, listen: { host: '127.0.0.1', port: 19443 }, paths,
    controlIdentity: { algorithm: 'Ed25519', keyId: 'i8f-control-test', publicKeyPem, fingerprint },
    protectedKeyFingerprints: ['f'.repeat(64)], protectedPaths: [legacyRoot] };
  const inspectors = Object.fromEntries(['audit', 'binding', 'grant', 'ledger', 'policy', 'trust']
    .map(name => [name, () => ({ healthy: true, pending: 0, revision: 0 })]));
  let starts = 0;
  const realm = createIsolatedG7Realm({ config, ownerAuthority: f.authority,
    storeInspectors: inspectors, startLoopback: async options => {
      starts++;
      return { ...options, close: () => {} };
    } });
  return { realm, legacyRoot, started: () => starts };
}

test('isolated Owner authority is Linux-only and requires unprivileged private storage',
  { skip: !linuxUnprivileged && 'requires nonroot Linux durable lock semantics' }, () => {
    const f = fixture();
    try {
      assert.deepEqual({ status: f.authority.inspect().status, revision: f.authority.inspect().revision },
        { status: 'empty', revision: 0 });
      assert.equal(f.authority.verifyReadPrincipal(f.accessToken), null);
      const approval = bootstrapApproval(f);
      const result = f.authority.bootstrap({ accessToken: f.accessToken, approval });
      assert.equal(result.status, 'active');
      assert.equal(result.revision, 1);
      assert.equal(f.authority.verifyReadPrincipal(f.accessToken).ownerDigest, f.principal.ownerDigest);
      assert.equal(f.authority.bootstrap({ accessToken: f.accessToken, approval }).alreadyApplied, true);
      assert.equal(f.authority.inspect().events.length, 2);
      const raw = requireAudit(f.directory);
      assert.equal(raw.includes(f.principal.subject), false);
      assert.equal(raw.includes(f.accessToken), false);
      assert.equal(raw.includes(f.approvalPrivateKey.export({ type: 'pkcs8', format: 'pem' })), false);
    } finally { f.cleanup(); }
  });

test('g7.read alone cannot revoke or authorize administration; revision and owner fences apply',
  { skip: !linuxUnprivileged && 'requires nonroot Linux durable lock semantics' }, () => {
    const f = fixture();
    try {
      const bootstrap = bootstrapApproval(f);
      assert.throws(() => f.authority.bootstrap({
        accessToken: f.makeToken('g7.read', 'google-oauth2|different-owner'), approval: bootstrap,
      }), error => error.code === 'OWNER_APPROVAL_REQUIRED');
      assert.equal(f.authority.inspect().revision, 0);
      f.authority.bootstrap({ accessToken: f.accessToken, approval: bootstrap });
      assert.throws(() => f.authority.revoke({ accessToken: f.accessToken,
        approval: f.makeApproval({ operation: 'revoke', expectedRevision: 1,
          ownerDigest: f.principal.ownerDigest,
          targetDigest: ownerAuthorityTargetDigest('revoke', {
            issuer: ISSUER, ownerDigest: f.principal.ownerDigest,
          }) }) }), error => error.code === 'OWNER_ADMIN_AUTH_REQUIRED');
      assert.equal(f.authority.verifyAdminPrincipal(f.accessToken), null);
      assert.equal(f.authority.authorizeOwnerAction, undefined);
      assert.throws(() => f.authority.bootstrap({ accessToken: f.accessToken,
        approval: { ...bootstrap, eventId: randomUUID() } }),
      error => ['OWNER_APPROVAL_REQUIRED', 'EVENT_ID_CONFLICT'].includes(error.code));
      assert.equal(f.authority.inspect().revision, 1);
    } finally { f.cleanup(); }
  });

test('concurrent bootstrap attempts serialize and only one expectedRevision-0 transition wins',
  { skip: !linuxUnprivileged && 'requires nonroot Linux durable lock semantics' }, async () => {
    const f = fixture();
    try {
      const fixturePath = fileURLToPath(new URL('./fixtures-owner-authority-bootstrap.mjs', import.meta.url));
      const launch = approval => new Promise(resolve => {
        const child = spawn(process.execPath, [fixturePath], { env: {
          ...process.env, G7_I8F_BOOTSTRAP_FIXTURE: JSON.stringify({
            directory: f.directory, realmId: REALM, verifierConfig: f.verifierConfig,
            approvalJwks: f.approvalJwks, now: NOW, accessToken: f.accessToken, approval,
          }),
        } });
        let stdout = '', stderr = '';
        child.stdout.setEncoding('utf8').on('data', chunk => { stdout += chunk; });
        child.stderr.setEncoding('utf8').on('data', chunk => { stderr += chunk; });
        child.once('close', code => resolve({ code, stdout, stderr }));
      });
      const left = bootstrapApproval(f);
      const right = bootstrapApproval(f);
      const results = await Promise.all([launch(left), launch(right)]);
      assert.equal(results.filter(result => result.code === 0).length, 1, JSON.stringify(results));
      assert.equal(f.authority.inspect().revision, 1);
      assert.equal(f.authority.inspect().events.length, 2);
      assert.equal(f.authority.inspect().healthy, true);
    } finally { f.cleanup(); }
  });

test('crash after lock creation leaves an empty realm offline until signed lock reconciliation',
  { skip: !linuxUnprivileged && 'requires nonroot Linux durable lock semantics' }, () => {
    const f = fixture();
    try {
      const approval = bootstrapApproval(f);
      const fixturePath = fileURLToPath(new URL('./fixtures-owner-authority-crash.mjs', import.meta.url));
      const child = spawnSync(process.execPath, [fixturePath], { encoding: 'utf8', env: {
        ...process.env, NODE_TEST_CONTEXT: 'child-v8', G7_I8F_CRASH_FIXTURE: JSON.stringify({
          directory: f.directory, realmId: REALM, verifierConfig: f.verifierConfig,
          now: NOW, accessToken: f.accessToken, approval, stage: 'after-lock',
          authorityConfig: { approvalJwks: f.approvalJwks },
        }),
      } });
      assert.equal(child.status, 73, child.stderr);
      const before = f.authority.inspect();
      assert.equal(before.status, 'empty');
      assert.equal(before.pendingCount, 0);
      assert.equal(before.healthy, false);
      const evidence = inspectDurableOwnerAudit({ directory: f.directory });
      const recovery = f.makeApproval({ operation: 'owner.recover', expectedRevision: 0,
        ownerDigest: '0'.repeat(64),
        targetDigest: ownerAuthorityRecoveryTargetDigest({ sequence: evidence.sequence,
          hash: evidence.hash, pendingEventId: null, lockDigest: evidence.lockDigest,
          recoveryLockDigest: '0'.repeat(64) }) });
      const result = f.authority.recover({ approval: recovery,
        operatorConfirmedNoActiveWriters: true });
      assert.equal(result.status, 'empty');
      assert.equal(result.healthy, true);
      assert.equal(result.revision, 0);
    } finally { f.cleanup(); }
  });

test('crash after Owner intent remains inactive until signed explicit recovery',
  { skip: !linuxUnprivileged && 'requires nonroot Linux durable lock semantics' }, async () => {
    const f = fixture();
    let activation;
    try {
      const approval = bootstrapApproval(f);
      activation = createActivationRealm(f);
      assert.equal(activation.realm.inspectActivation().ready, false);
      const fixturePath = fileURLToPath(new URL('./fixtures-owner-authority-crash.mjs', import.meta.url));
      const child = spawnSync(process.execPath, [fixturePath], { encoding: 'utf8', env: {
        ...process.env, NODE_TEST_CONTEXT: 'child-v8', G7_I8F_CRASH_FIXTURE: JSON.stringify({
          directory: f.directory, realmId: REALM, verifierConfig: f.verifierConfig,
          now: NOW, accessToken: f.accessToken, approval, stage: 'after-intent',
          authorityConfig: { approvalJwks: [f.approvalJwk] },
        }),
      } });
      assert.equal(child.status, 73, child.stderr);
      const before = f.authority.inspect();
      assert.equal(before.status, 'empty');
      assert.equal(before.pendingCount, 1);
      assert.equal(before.healthy, false);
      assert.equal(activation.realm.inspectActivation().ready, false);
      await assert.rejects(activation.realm.activate(), error => error.code === 'REALM_ACTIVATION_BLOCKED');
      assert.equal(activation.started(), 0);
      assert.throws(() => f.authority.verifyReadPrincipal(f.accessToken),
        error => error.code === 'OWNER_AUTHORITY_RECOVERY_REQUIRED');
      const evidence = inspectDurableOwnerAudit({ directory: f.directory });
      const targetDigest = ownerAuthorityRecoveryTargetDigest({ sequence: evidence.sequence,
        hash: evidence.hash, pendingEventId: evidence.pending[0].eventId,
        lockDigest: evidence.lockDigest, recoveryLockDigest: '0'.repeat(64) });
      const recovery = f.makeApproval({ operation: 'owner.recover', expectedRevision: 0,
        ownerDigest: f.principal.ownerDigest, targetDigest });
      assert.throws(() => f.authority.recover({ approval: recovery }),
        error => error.code === 'OPERATOR_REQUIRED');
      const result = f.authority.recover({ approval: recovery, operatorConfirmedNoActiveWriters: true });
      assert.equal(result.status, 'active');
      assert.equal(result.revision, 1);
      assert.equal(f.authority.verifyReadPrincipal(f.accessToken).ownerDigest, f.principal.ownerDigest);
      const recovered = inspectDurableOwnerAudit({ directory: f.directory });
      assert.equal(recovered.pending.length, 0);
      assert.equal(recovered.events.at(-1).recoveryApproval.operation, 'owner.recover');
      const activated = await activation.realm.activate();
      assert.equal(activated.host, '127.0.0.1');
      assert.deepEqual(activated.tools, ['read_file']);
      assert.equal(activation.started(), 1);
    } finally {
      if (activation?.legacyRoot) rmSync(activation.legacyRoot, { recursive: true, force: true });
      f.cleanup();
    }
  });

test('crash after committed outcome remains behind the activation barrier until lock reconciliation',
  { skip: !linuxUnprivileged && 'requires nonroot Linux durable lock semantics' }, async () => {
    const f = fixture();
    let activation;
    try {
      const approval = bootstrapApproval(f);
      activation = createActivationRealm(f);
      const fixturePath = fileURLToPath(new URL('./fixtures-owner-authority-crash.mjs', import.meta.url));
      const child = spawnSync(process.execPath, [fixturePath], { encoding: 'utf8', env: {
        ...process.env, NODE_TEST_CONTEXT: 'child-v8', G7_I8F_CRASH_FIXTURE: JSON.stringify({
          directory: f.directory, realmId: REALM, verifierConfig: f.verifierConfig,
          now: NOW, accessToken: f.accessToken, approval, stage: 'after-outcome',
          authorityConfig: { approvalJwks: [f.approvalJwk] },
        }),
      } });
      assert.equal(child.status, 73, child.stderr);
      const before = f.authority.inspect();
      assert.equal(before.status, 'active');
      assert.equal(before.revision, 1);
      assert.equal(before.healthy, false);
      assert.equal(activation.realm.inspectActivation().ready, false);
      const evidence = inspectDurableOwnerAudit({ directory: f.directory });
      const recovery = f.makeApproval({ operation: 'owner.recover', expectedRevision: 1,
        ownerDigest: f.principal.ownerDigest,
        targetDigest: ownerAuthorityRecoveryTargetDigest({ sequence: evidence.sequence,
          hash: evidence.hash, pendingEventId: null, lockDigest: evidence.lockDigest,
          recoveryLockDigest: '0'.repeat(64) }) });
      const result = f.authority.recover({ approval: recovery,
        operatorConfirmedNoActiveWriters: true });
      assert.equal(result.status, 'active');
      assert.equal(result.revision, 1);
      assert.equal(activation.realm.inspectActivation().ready, true);
      await activation.realm.activate();
      assert.equal(activation.started(), 1);
    } finally {
      if (activation?.legacyRoot) rmSync(activation.legacyRoot, { recursive: true, force: true });
      f.cleanup();
    }
  });

test('Owner revocation is append-only, revision-bound, and removes read authority',
  { skip: !linuxUnprivileged && 'requires nonroot Linux durable lock semantics' }, () => {
    const f = fixture();
    try {
      f.authority.bootstrap({ accessToken: f.accessToken, approval: bootstrapApproval(f) });
      const adminToken = signedToken(f, 'g7.owner');
      const admin = f.verifier.verifyAdminPrincipal(adminToken);
      assert.equal(admin.ownerDigest, f.principal.ownerDigest);
      const approval = f.makeApproval({ operation: 'revoke', expectedRevision: 1,
        ownerDigest: admin.ownerDigest, targetDigest: ownerAuthorityTargetDigest('revoke', {
          issuer: ISSUER, ownerDigest: admin.ownerDigest,
        }) });
      assert.equal(f.authority.revoke({ accessToken: adminToken, approval }).status, 'revoked');
      assert.equal(f.authority.inspect().revision, 2);
      assert.equal(f.authority.verifyReadPrincipal(f.accessToken), null);
      assert.equal(f.authority.verifyAdminPrincipal(adminToken), null);
      assert.equal(f.authority.inspect().events.length, 4);
    } finally { f.cleanup(); }
  });

test('Owner authority WAL tampering is rejected without repair or revision reset',
  { skip: !linuxUnprivileged && 'requires nonroot Linux durable lock semantics' }, () => {
    const f = fixture();
    try {
      f.authority.bootstrap({ accessToken: f.accessToken, approval: bootstrapApproval(f) });
      const log = path.join(f.directory, 'owner-decisions-v1.jsonl');
      const lines = readFileSync(log, 'utf8').trimEnd().split('\n');
      const record = JSON.parse(lines[0]);
      record.event.at = new Date(Date.parse(record.event.at) + 1000).toISOString();
      lines[0] = JSON.stringify(record);
      writeFileSync(log, lines.join('\n') + '\n');
      assert.throws(() => f.authority.inspect(), /integrity mismatch/);
      assert.throws(() => f.authority.verifyReadPrincipal(f.accessToken), /integrity mismatch/);
    } finally { f.cleanup(); }
  });

function signedToken(f, scope) {
  return f.makeToken(scope);
}

function requireAudit(directory) {
  return JSON.stringify(inspectDurableOwnerAudit({ directory }).events);
}
