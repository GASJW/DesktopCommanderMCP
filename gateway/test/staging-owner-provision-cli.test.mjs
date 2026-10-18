import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { chmodSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { generateKeyPairSync, verify } from 'node:crypto';
import { createServer } from 'node:https';
import { execFileSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const CLI = path.join(ROOT, 'scripts/g7-staging-owner-provision.mjs');
const HOST = 'g7-staging.test';
const ISSUER = 'https://g7-owner-staging.cloudflareaccess.com';
const AUDIENCE = 'a'.repeat(64);
const EMAIL = 'g7-staging-owner@example.test';
const SUBJECT = 'synthetic-owner-i5d';
const CLIENT_ID = 'g7-staging-agent.synthetic';
const REQUEST_ID = '9f1d25a4-2b2b-4d70-8ab2-b5c12b2711ef';
const FINGERPRINT = 'c'.repeat(64);
const CODE = 'A1B2C3D4E5';
const CSRF = 'eyJhdCI6MTc5MjI5MDAwMDAwMCwibm9uY2UiOiJub25jZSJ9.' + 'x'.repeat(43);
const CONTROL = 'd'.repeat(64);
const APPROVAL_EVENT_ID = '2ab10d18-4d72-49fc-b0f0-082911a8c73c';
const BINDING_EVENT_ID = 'f453ad3a-ffda-43db-9c32-bb52a5c247f6';

test('Owner signing key path policy rejects Gateway release/config/state and G6 trees', async () => {
  const { validateOwnerSigningKeyPath } = await import('../../scripts/g7-staging-owner-provision.mjs');
  assert.equal(validateOwnerSigningKeyPath('/home/itagil/.config/g7-staging-owner/owner.key'), true);
  for (const filename of [
    '/opt/vps-commander/g7-staging/owner-signing.key',
    '/etc/vpsc-g7-staging-gateway/owner-signing.key',
    '/var/lib/vpsc-g7-staging-gateway/owner-signing.key',
    '/etc/vpsc-g7-staging-agent/owner-signing.key',
    '/var/lib/vpsc-g7-staging-agent/owner-signing.key',
    '/opt/vps-commander/code/owner-signing.key',
  ]) {
    assert.throws(() => validateOwnerSigningKeyPath(filename), error => error?.code === 'CONFIG');
  }
});

function privateWrite(filename, value) {
  writeFileSync(filename, value, { mode: 0o600, flag: 'wx' });
  chmodSync(filename, 0o600);
}

async function bodyOf(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  return Buffer.concat(chunks).toString('utf8');
}

function jwtParts(token) {
  const pieces = token.split('.');
  assert.equal(pieces.length, 3);
  const header = JSON.parse(Buffer.from(pieces[0], 'base64url').toString('utf8'));
  const claims = JSON.parse(Buffer.from(pieces[1], 'base64url').toString('utf8'));
  return { pieces, header, claims };
}

async function fixture({ pendingFingerprint = FINGERPRINT, proofVerified = true,
  abortApproval = false, approvalStatus = 200 } = {}) {
  const scratch = mkdtempSync(path.join(os.tmpdir(), 'g7-staging-owner-cli-'));
  chmodSync(scratch, 0o700);
  const allowedRoot = path.join(scratch, 'g7-staging-approved-root');
  mkdirSync(allowedRoot, { mode: 0o700 });
  const tlsKeyPath = path.join(scratch, 'tls.key');
  const tlsCertPath = path.join(scratch, 'tls.crt');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
    '-subj', `/CN=${HOST}`, '-addext', `subjectAltName=DNS:${HOST}`,
    '-keyout', tlsKeyPath, '-out', tlsCertPath], { stdio: 'ignore' });
  chmodSync(tlsKeyPath, 0o600);
  chmodSync(tlsCertPath, 0o600);

  const owner = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const ownerKid = 'g7-staging-owner-i5d';
  const publicJwk = { ...owner.publicKey.export({ format: 'jwk' }), kid: ownerKid, alg: 'RS256' };
  const privateKeyPath = path.join(scratch, 'owner-signing.key');
  privateWrite(privateKeyPath, owner.privateKey.export({ format: 'pem', type: 'pkcs8' }));
  const configPath = path.join(scratch, 'owner-client.json');
  const config = {
    version: 1,
    origin: `https://${HOST}`,
    connectAddress: '127.0.0.1',
    connectPort: 18443,
    tlsServerName: HOST,
    caPath: tlsCertPath,
    stageControlToken: CONTROL,
    owner: {
      issuer: ISSUER,
      audience: AUDIENCE,
      email: EMAIL,
      subject: SUBJECT,
      kid: ownerKid,
      publicJwk,
      privateKeyPath,
    },
    machineClientId: CLIENT_ID,
    allowedRoot,
  };
  const requests = [];
  const server = createServer({ key: readFileSync(tlsKeyPath), cert: readFileSync(tlsCertPath) }, async (req, res) => {
    const rawBody = await bodyOf(req);
    let body;
    try { body = rawBody ? JSON.parse(rawBody) : null; } catch { body = null; }
    requests.push({ method: req.method, url: req.url, headers: req.headers, body });
    if (req.url === '/healthz' && req.method === 'GET') {
      return send(res, 200, { status: 'ready', runtime: 'g7-staging', trustRevision: 0,
        policyRevision: 0, bindingRevision: 0 });
    }
    const auth = req.headers['cf-access-jwt-assertion'];
    if (!auth || !validOwnerJwt(auth, owner.publicKey)) return send(res, 401, { error: 'Owner required' });
    if (req.url === '/dashboard/api/g7/pairing/pending' && req.method === 'GET') {
      return send(res, 200, { enabled: true, csrf: CSRF, pending: [{ requestId: REQUEST_ID,
        name: 'synthetic-agent', platform: 'linux', fingerprint: pendingFingerprint,
        proofVerified, createdAt: new Date().toISOString() }] });
    }
    if (req.method === 'POST' && !validOwnerHeaders(req.headers)) return send(res, 403, { error: 'Owner headers required' });
    if (req.url === '/dashboard/api/g7/pairing/approve') {
      if (abortApproval) return req.socket.destroy();
      if (approvalStatus !== 200) return send(res, approvalStatus, { error: 'Pairing outcome requires reconciliation' });
      return send(res, 200, { deviceId: '1041e5c1-74b8-45d1-8f61-dca1e8468239',
        fingerprint: FINGERPRINT, status: 'approved_offline' });
    }
    if (req.url === '/stage/bind') {
      return send(res, 200, { revision: 1, binding: { clientId: CLIENT_ID,
        deviceId: '1041e5c1-74b8-45d1-8f61-dca1e8468239', fingerprint: FINGERPRINT,
        approvalEventId: APPROVAL_EVENT_ID, bindingEventId: BINDING_EVENT_ID,
        bindingRevision: 1, ownerId: 'a'.repeat(24), ownerDigest: 'b'.repeat(64),
        trustRevisionBefore: 0, trustRevisionAfter: 1, trustRevision: 1 } });
    }
    if (req.url === '/stage/grant') {
      return send(res, 201, { revision: 1, grant: { grantId: 'ee5f8150-a2a6-4e2d-a217-744060ce9682',
        deviceId: '1041e5c1-74b8-45d1-8f61-dca1e8468239', tool: 'read_file',
        scope: { root: allowedRoot }, constraints: { maxBytes: 65536, maxLength: 1000, maxOffset: 100000 },
        revision: 1 } });
    }
    return send(res, 404, { error: 'Not found' });
  });
  function send(res, status, value) {
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(JSON.stringify(value));
  }
  function validOwnerHeaders(headers) {
    return headers.origin === `https://${HOST}` &&
      (headers['x-vpsc-csrf'] === undefined || headers['x-vpsc-csrf'] === CSRF) &&
      headers['x-vpsc-stage-control'] === CONTROL && !headers.cookie;
  }
  function validOwnerJwt(token, publicKey) {
    try {
      const { pieces, header, claims } = jwtParts(token);
      return header.alg === 'RS256' && header.kid === ownerKid && claims.iss === ISSUER &&
        claims.aud === AUDIENCE && claims.email === EMAIL && claims.sub === SUBJECT &&
        Number.isSafeInteger(claims.iat) && Number.isSafeInteger(claims.exp) &&
        claims.exp > Math.floor(Date.now() / 1000) && claims.exp - claims.iat <= 3600 &&
        verify('RSA-SHA256', Buffer.from(`${pieces[0]}.${pieces[1]}`), publicKey,
          Buffer.from(pieces[2], 'base64url'));
    } catch { return false; }
  }
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  config.connectPort = server.address().port;
  privateWrite(configPath, JSON.stringify(config));
  const input = JSON.stringify({ requestId: REQUEST_ID, code: CODE, fingerprint: FINGERPRINT }) + '\n';
  return {
    scratch, server, requests, config, configPath, input, owner,
    run: async () => {
      const child = spawn(process.execPath, [CLI, '--config', configPath], {
        cwd: ROOT,
        env: { PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: scratch, TMPDIR: scratch, LANG: 'C.UTF-8' },
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      let stdout = '', stderr = '';
      child.stdout.setEncoding('utf8').on('data', chunk => { stdout += chunk; });
      child.stderr.setEncoding('utf8').on('data', chunk => { stderr += chunk; });
      child.stdin.end(input);
      const [code, signal] = await once(child, 'exit');
      return { code, signal, stdout, stderr };
    },
    close: async () => {
      if (server.listening) await new Promise(resolve => server.close(resolve));
      rmSync(scratch, { recursive: true, force: true });
    },
  };
}

test('Owner CLI completes first approval, durable binding and one restricted read grant over verified TLS', async () => {
  const x = await fixture();
  try {
    const result = await x.run();
    assert.deepEqual(x.requests.map(item => `${item.method} ${item.url}`), [
      'GET /healthz',
      'GET /dashboard/api/g7/pairing/pending',
      'POST /dashboard/api/g7/pairing/approve',
      'POST /stage/bind',
      'POST /stage/grant',
    ]);
    assert.equal(result.code, 0, result.stderr);
    assert.ok(x.requests.slice(1).every(item => item.headers['cf-access-jwt-assertion']));
    for (const item of x.requests.slice(1)) {
      const { pieces, header, claims } = jwtParts(item.headers['cf-access-jwt-assertion']);
      assert.equal(header.kid, 'g7-staging-owner-i5d');
      assert.equal(claims.iss, ISSUER);
      assert.equal(claims.aud, AUDIENCE);
      assert.equal(claims.email, EMAIL);
      assert.equal(claims.sub, SUBJECT);
      assert.ok(verify('RSA-SHA256', Buffer.from(`${pieces[0]}.${pieces[1]}`), x.owner.publicKey,
        Buffer.from(pieces[2], 'base64url')));
      assert.equal(item.headers.cookie, undefined);
    }
    const [approve, bind, grant] = x.requests.slice(2);
    assert.deepEqual(approve.body, { requestId: REQUEST_ID, code: CODE, expectedFingerprint: FINGERPRINT });
    assert.equal(approve.headers.origin, `https://${HOST}`);
    assert.equal(approve.headers['x-vpsc-csrf'], CSRF);
    assert.equal(approve.headers['x-vpsc-stage-control'], CONTROL);
    assert.deepEqual(bind.body, { clientId: CLIENT_ID,
      deviceId: '1041e5c1-74b8-45d1-8f61-dca1e8468239', expectedRevision: 0 });
    assert.deepEqual(grant.body, { deviceId: '1041e5c1-74b8-45d1-8f61-dca1e8468239',
      expectedRevision: 0, tool: 'read_file', scope: { root: x.config.allowedRoot },
      constraints: { maxBytes: 65536, maxLength: 1000, maxOffset: 100000 } });
    assert.doesNotMatch(result.stdout + result.stderr, new RegExp(CODE));
    assert.doesNotMatch(result.stdout + result.stderr, new RegExp(CONTROL));
    assert.doesNotMatch(result.stdout + result.stderr, /eyJ|cf-access-jwt/);
    const summary = JSON.parse(result.stdout.trim());
    assert.equal(summary.status, 'provisioned');
    assert.equal(summary.deviceId, '1041e5c1-74b8-45d1-8f61-dca1e8468239');
    assert.equal(summary.tool, 'read_file');
    assert.deepEqual(summary.grant, {
      grantId: 'ee5f8150-a2a6-4e2d-a217-744060ce9682',
      deviceId: '1041e5c1-74b8-45d1-8f61-dca1e8468239', tool: 'read_file',
      scope: { root: x.config.allowedRoot },
      constraints: { maxBytes: 65536, maxLength: 1000, maxOffset: 100000 }, revision: 1,
    });
    assert.deepEqual(summary.binding, {
      deviceId: '1041e5c1-74b8-45d1-8f61-dca1e8468239', clientId: CLIENT_ID,
      fingerprint: FINGERPRINT, approvalEventId: APPROVAL_EVENT_ID,
      bindingEventId: BINDING_EVENT_ID, bindingRevision: 1, ownerId: 'a'.repeat(24),
      ownerDigest: 'b'.repeat(64), trustRevisionBefore: 0, trustRevisionAfter: 1,
      trustRevision: 1,
    });
  } finally { await x.close(); }
});

test('Owner CLI refuses a pending request with a mismatched fingerprint or unproved identity before mutation', async t => {
  for (const options of [{ pendingFingerprint: 'e'.repeat(64) }, { proofVerified: false }]) {
    await t.test(JSON.stringify(options), async () => {
      const x = await fixture(options);
      try {
        const result = await x.run();
        assert.notEqual(result.code, 0);
        assert.deepEqual(x.requests.map(item => item.url), ['/healthz', '/dashboard/api/g7/pairing/pending']);
        assert.doesNotMatch(result.stderr + result.stdout, new RegExp(CODE));
      } finally { await x.close(); }
    });
  }
});

test('Owner CLI does not retry or continue after an ambiguous approval response', async () => {
  const x = await fixture({ abortApproval: true });
  try {
    const result = await x.run();
    assert.notEqual(result.code, 0);
    assert.equal(x.requests.filter(item => item.url === '/dashboard/api/g7/pairing/approve').length, 1);
    assert.equal(x.requests.some(item => item.url === '/stage/bind' || item.url === '/stage/grant'), false);
    assert.doesNotMatch(result.stderr + result.stdout, new RegExp(CODE));
    assert.match(result.stderr, /inspect.*state|ambiguous/i);
  } finally { await x.close(); }
});

test('Owner CLI classifies a Gateway 503 during approval as ambiguous and stops', async () => {
  const x = await fixture({ approvalStatus: 503 });
  try {
    const result = await x.run();
    assert.notEqual(result.code, 0);
    assert.equal(x.requests.filter(item => item.url === '/dashboard/api/g7/pairing/approve').length, 1);
    assert.equal(x.requests.some(item => item.url === '/stage/bind' || item.url === '/stage/grant'), false);
    assert.match(result.stderr, /ambiguous/i);
  } finally { await x.close(); }
});

test('Owner CLI classifies an unexpected successful approval status as ambiguous', async () => {
  const x = await fixture({ approvalStatus: 201 });
  try {
    const result = await x.run();
    assert.notEqual(result.code, 0);
    assert.equal(x.requests.filter(item => item.url === '/dashboard/api/g7/pairing/approve').length, 1);
    assert.equal(x.requests.some(item => item.url === '/stage/bind' || item.url === '/stage/grant'), false);
    assert.match(result.stderr, /ambiguous/i);
  } finally { await x.close(); }
});

test('Owner CLI rejects production identity, a mismatched signing key, and non-loopback configuration before networking', async t => {
  const x = await fixture();
  try {
    const invalidConfigs = [
      ['production issuer', config => { config.owner.issuer = 'https://actual-tenant.cloudflareaccess.com'; }],
      ['non-loopback connection', config => { config.connectAddress = '0.0.0.0'; }],
      ['production origin', config => { config.origin = 'https://gateway.example.com'; }],
      ['mismatched Owner signing key', config => {
        const other = generateKeyPairSync('rsa', { modulusLength: 2048 });
        config.owner.publicJwk = { ...other.publicKey.export({ format: 'jwk' }),
          kid: config.owner.kid, alg: 'RS256' };
      }],
      ['weak Owner signing key', config => {
        const weak = generateKeyPairSync('rsa', { modulusLength: 1024 });
        const keyPath = path.join(x.scratch, 'weak-owner-signing.key');
        privateWrite(keyPath, weak.privateKey.export({ format: 'pem', type: 'pkcs8' }));
        config.owner.privateKeyPath = keyPath;
        config.owner.publicJwk = { ...weak.publicKey.export({ format: 'jwk' }),
          kid: config.owner.kid, alg: 'RS256' };
      }],
      ['Owner key path in Gateway state', config => {
        config.owner.privateKeyPath = '/var/lib/vpsc-g7-staging-gateway/owner-signing.key';
      }],
      ['Owner key path in Gateway release tree', config => {
        config.owner.privateKeyPath = '/opt/vps-commander/g7-staging/owner-signing.key';
      }],
      ['non-staging file scope', config => { config.allowedRoot = '/opt/vps-commander/code'; }],
    ];
    for (const [label, corrupt] of invalidConfigs) {
      await t.test(label, async () => {
        const config = structuredClone(x.config);
        corrupt(config);
        x.requests.length = 0;
        writeFileSync(x.configPath, JSON.stringify(config), { mode: 0o600, flag: 'w' });
        chmodSync(x.configPath, 0o600);
        const result = await x.run();
        assert.notEqual(result.code, 0);
        assert.equal(x.requests.length, 0);
        assert.match(result.stderr, /configuration/i);
      });
    }
  } finally { await x.close(); }
});
