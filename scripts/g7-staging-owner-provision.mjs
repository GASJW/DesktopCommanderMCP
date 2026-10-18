#!/usr/bin/env node
import { createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { constants, closeSync, fstatSync, lstatSync, openSync, readFileSync } from 'node:fs';
import { request as httpsRequest } from 'node:https';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const HOST = 'g7-staging.test';
const OWNER_ISSUER = 'https://g7-owner-staging.cloudflareaccess.com';
const OWNER_EMAIL = 'g7-staging-owner@example.test';
const MACHINE_CLIENT_ID = 'g7-staging-agent.synthetic';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HEX64 = /^[a-f0-9]{64}$/;
const CODE = /^[A-F0-9]{10}$/;
const CSRF = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$/;
const MAX_INPUT_BYTES = 4096;
const MAX_RESPONSE_BYTES = 64 * 1024;
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.getPrototypeOf(value) === Object.prototype &&
  Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const failure = (code) => Object.assign(new Error(code), { code });

function readSafeFile(filename, { privateOnly = true } = {}) {
  if (typeof filename !== 'string' || !path.isAbsolute(filename) || path.normalize(filename) !== filename) {
    throw failure('CONFIG');
  }
  let cursor = path.dirname(filename);
  while (true) {
    const parent = lstatSync(cursor);
    if (!parent.isDirectory() || parent.isSymbolicLink() ||
        ((parent.mode & 0o022) !== 0 && !(parent.uid === 0 && (parent.mode & 0o1000) !== 0))) {
      throw failure('CONFIG');
    }
    const next = path.dirname(cursor);
    if (next === cursor) break;
    cursor = next;
  }
  const before = lstatSync(filename);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 ||
      before.uid !== process.getuid() || (before.mode & 0o022) !== 0 ||
      (privateOnly && (before.mode & 0o077) !== 0)) throw failure('CONFIG');
  const fd = openSync(filename, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) |
    (constants.O_CLOEXEC ?? 0));
  try {
    const opened = fstatSync(fd);
    if (!opened.isFile() || opened.dev !== before.dev || opened.ino !== before.ino ||
        opened.uid !== before.uid || opened.nlink !== 1 || (opened.mode & 0o022) !== 0 ||
        (privateOnly && (opened.mode & 0o077) !== 0)) throw failure('CONFIG');
    return readFileSync(fd);
  } finally { closeSync(fd); }
}

function validateScopeRoot(directory) {
  const components = typeof directory === 'string' ? directory.split(path.sep) : [];
  const stagingScoped = components.some(component => component === 'g7-staging' ||
    component.startsWith('g7-staging-') || component.startsWith('vpsc-g7-staging-'));
  if (typeof directory !== 'string' || !path.isAbsolute(directory) || path.normalize(directory) !== directory ||
      directory === path.parse(directory).root || !stagingScoped) {
    throw failure('CONFIG');
  }
  if (directory === '/opt/vps-commander/code' || directory.startsWith('/opt/vps-commander/code/')) {
    throw failure('CONFIG');
  }
}

export function validateOwnerSigningKeyPath(filename) {
  if (typeof filename !== 'string' || !path.isAbsolute(filename) || path.normalize(filename) !== filename ||
      ['/etc/vpsc-g7-staging-gateway', '/var/lib/vpsc-g7-staging-gateway',
        '/etc/vpsc-g7-staging-agent', '/var/lib/vpsc-g7-staging-agent',
        '/opt/vps-commander/g7-staging', '/opt/vps-commander/code']
        .some(root => filename === root || filename.startsWith(root + path.sep))) {
    throw failure('CONFIG');
  }
  return true;
}

function validateConfig(config) {
  if (!exact(config, ['allowedRoot', 'caPath', 'connectAddress', 'connectPort', 'machineClientId',
      'origin', 'owner', 'stageControlToken', 'tlsServerName', 'version']) || config.version !== 1 ||
      config.origin !== `https://${HOST}` || config.connectAddress !== '127.0.0.1' ||
      config.tlsServerName !== HOST || !Number.isSafeInteger(config.connectPort) ||
      config.connectPort < 1 || config.connectPort > 65535 ||
      config.machineClientId !== MACHINE_CLIENT_ID || !HEX64.test(config.stageControlToken ?? '') ||
      !exact(config.owner, ['audience', 'email', 'issuer', 'kid', 'privateKeyPath', 'publicJwk', 'subject']) ||
      config.owner.issuer !== OWNER_ISSUER || !HEX64.test(config.owner.audience ?? '') ||
      config.owner.email !== OWNER_EMAIL ||
      typeof config.owner.subject !== 'string' || !/^synthetic-[A-Za-z0-9_.-]{1,120}$/.test(config.owner.subject) ||
      typeof config.owner.kid !== 'string' || !/^g7-staging-owner-[A-Za-z0-9_.-]{1,128}$/.test(config.owner.kid) ||
      !exact(config.owner.publicJwk, ['alg', 'e', 'kid', 'kty', 'n']) ||
      config.owner.publicJwk.kty !== 'RSA' || config.owner.publicJwk.alg !== 'RS256' ||
      config.owner.publicJwk.kid !== config.owner.kid ||
      typeof config.owner.publicJwk.n !== 'string' || typeof config.owner.publicJwk.e !== 'string' ||
      typeof config.owner.privateKeyPath !== 'string') throw failure('CONFIG');
  const ownerKeyPath = config.owner.privateKeyPath;
  validateOwnerSigningKeyPath(ownerKeyPath);
  const origin = new URL(config.origin);
  if (origin.protocol !== 'https:' || origin.hostname !== HOST || origin.port || origin.pathname !== '/' ||
      origin.search || origin.hash || origin.username || origin.password || origin.origin !== config.origin) {
    throw failure('CONFIG');
  }
  validateScopeRoot(config.allowedRoot);
  const ca = readSafeFile(config.caPath, { privateOnly: false });
  const privateKeyBytes = readSafeFile(config.owner.privateKeyPath);
  let privateKey;
  try { privateKey = createPrivateKey(privateKeyBytes); } catch { throw failure('CONFIG'); }
  if (privateKey.asymmetricKeyType !== 'rsa' ||
      !Number.isSafeInteger(privateKey.asymmetricKeyDetails?.modulusLength) ||
      privateKey.asymmetricKeyDetails.modulusLength < 2048) throw failure('CONFIG');
  let publicJwk;
  try { publicJwk = createPublicKey(privateKey).export({ format: 'jwk' }); }
  catch { throw failure('CONFIG'); }
  if (publicJwk.n !== config.owner.publicJwk.n || publicJwk.e !== config.owner.publicJwk.e) {
    throw failure('CONFIG');
  }
  return Object.freeze({ config, ca, privateKey });
}

function parseConfirmation(value) {
  if (!exact(value, ['code', 'fingerprint', 'requestId']) || !UUID.test(value.requestId ?? '') ||
      typeof value.fingerprint !== 'string' || !HEX64.test(value.fingerprint) ||
      typeof value.code !== 'string') throw failure('CONFIRMATION');
  const code = value.code.replace(/[\s-]/g, '').toUpperCase();
  if (!CODE.test(code)) throw failure('CONFIRMATION');
  return Object.freeze({ requestId: value.requestId, code, fingerprint: value.fingerprint });
}

function mintOwnerJwt(config, privateKey) {
  const now = Math.floor(Date.now() / 1000);
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', kid: config.owner.kid })).toString('base64url');
  const claims = Buffer.from(JSON.stringify({ iss: config.owner.issuer, aud: config.owner.audience,
    email: config.owner.email, sub: config.owner.subject, iat: now, exp: now + 600 })).toString('base64url');
  const unsigned = `${header}.${claims}`;
  return `${unsigned}.${sign('RSA-SHA256', Buffer.from(unsigned), privateKey).toString('base64url')}`;
}

function requestJson({ config, ca, token, pathname, method = 'GET', body, csrf }) {
  return new Promise((resolve, reject) => {
    const headers = { accept: 'application/json', host: `${HOST}:${config.connectPort}` };
    if (token) headers['cf-access-jwt-assertion'] = token;
    if (method === 'POST') {
      headers['content-type'] = 'application/json';
      headers.origin = config.origin;
      headers['x-vpsc-stage-control'] = config.stageControlToken;
      if (csrf) headers['x-vpsc-csrf'] = csrf;
    }
    let settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      error ? reject(error) : resolve(value);
    };
    const req = httpsRequest({ hostname: config.connectAddress, port: config.connectPort,
      servername: config.tlsServerName, method, path: pathname, headers, ca,
      rejectUnauthorized: true, timeout: 10_000 }, res => {
      if (!res.socket.authorized) {
        res.resume();
        finish(failure('TLS'));
        return;
      }
      const chunks = [];
      let length = 0;
      res.on('data', chunk => {
        length += chunk.length;
        if (length > MAX_RESPONSE_BYTES) {
          req.destroy();
          finish(failure(method === 'POST' ? 'AMBIGUOUS' : 'RESPONSE'));
        } else chunks.push(chunk);
      });
      res.on('end', () => {
        if (settled) return;
        let parsed;
        try { parsed = JSON.parse(Buffer.concat(chunks, length).toString('utf8')); }
        catch { return finish(failure(method === 'POST' ? 'AMBIGUOUS' : 'RESPONSE')); }
        finish(null, { status: res.statusCode, body: parsed });
      });
      res.on('error', () => finish(failure(method === 'POST' ? 'AMBIGUOUS' : 'NETWORK')));
    });
    req.setTimeout(10_000, () => req.destroy(failure(method === 'POST' ? 'AMBIGUOUS' : 'NETWORK')));
    req.on('error', () => finish(failure(method === 'POST' ? 'AMBIGUOUS' : 'NETWORK')));
    req.end(body === undefined ? undefined : JSON.stringify(body));
  });
}

function requireStatus(response, status, { mutation = false } = {}) {
  if (mutation && (response.status >= 500 ||
      response.status >= 200 && response.status < 300 && response.status !== status)) {
    throw failure('AMBIGUOUS');
  }
  if (response.status !== status) throw failure('DENIED');
  return response.body;
}

async function runProvisioning({ config, ca, privateKey }, confirmation) {
  const token = mintOwnerJwt(config, privateKey);
  const health = requireStatus(await requestJson({ config, ca, pathname: '/healthz' }), 200);
  if (health?.status !== 'ready' || health.runtime !== 'g7-staging' || health.trustRevision !== 0 ||
      health.bindingRevision !== 0 || health.policyRevision !== 0) throw failure('NOT_FRESH');

  const pendingResponse = requireStatus(await requestJson({ config, ca, token,
    pathname: '/dashboard/api/g7/pairing/pending' }), 200);
  const pending = pendingResponse?.pending?.find(item => item?.requestId === confirmation.requestId);
  if (pendingResponse.enabled !== true || !CSRF.test(pendingResponse.csrf ?? '') || !pending ||
      pending.proofVerified !== true || pending.fingerprint !== confirmation.fingerprint) {
    throw failure('PAIRING_MISMATCH');
  }

  // Every mutation is issued once. Any timeout, socket loss, or unexpected
  // response stops this client; the operator must inspect persisted state.
  const approval = requireStatus(await requestJson({ config, ca, token,
    pathname: '/dashboard/api/g7/pairing/approve', method: 'POST', csrf: pendingResponse.csrf,
    body: { requestId: confirmation.requestId, code: confirmation.code,
      expectedFingerprint: confirmation.fingerprint } }), 200, { mutation: true });
  if (approval?.status !== 'approved_offline' || !UUID.test(approval.deviceId ?? '') ||
      approval.fingerprint !== confirmation.fingerprint) throw failure('AMBIGUOUS');

  const bindingResponse = requireStatus(await requestJson({ config, ca, token,
    pathname: '/stage/bind', method: 'POST',
    body: { clientId: config.machineClientId, deviceId: approval.deviceId, expectedRevision: 0 } }), 200,
  { mutation: true });
  const binding = bindingResponse?.binding;
  if (bindingResponse.revision !== 1 || !exact(binding, ['approvalEventId', 'bindingEventId',
      'bindingRevision', 'clientId', 'deviceId', 'fingerprint', 'ownerDigest', 'ownerId',
      'trustRevision', 'trustRevisionAfter', 'trustRevisionBefore']) ||
      binding?.clientId !== config.machineClientId ||
      binding.deviceId !== approval.deviceId || binding.fingerprint !== confirmation.fingerprint ||
      !UUID.test(binding.approvalEventId ?? '') || !UUID.test(binding.bindingEventId ?? '') ||
      binding.bindingRevision !== 1 || !/^[a-f0-9]{24}$/.test(binding.ownerId ?? '') ||
      !HEX64.test(binding.ownerDigest ?? '') || binding.trustRevisionBefore !== 0 ||
      binding.trustRevisionAfter !== 1 || binding.trustRevision < binding.trustRevisionAfter) {
    throw failure('AMBIGUOUS');
  }

  const grantResponse = requireStatus(await requestJson({ config, ca, token,
    pathname: '/stage/grant', method: 'POST',
    body: { deviceId: approval.deviceId, expectedRevision: 0, tool: 'read_file',
      scope: { root: config.allowedRoot },
      constraints: { maxBytes: 65_536, maxLength: 1_000, maxOffset: 100_000 } } }), 201,
  { mutation: true });
  const grant = grantResponse?.grant;
  if (grantResponse.revision !== 1 || !UUID.test(grant?.grantId ?? '') ||
      grant.deviceId !== approval.deviceId || grant.tool !== 'read_file' ||
      !exact(grant.scope, ['root']) || grant.scope.root !== config.allowedRoot ||
      !exact(grant.constraints, ['maxBytes', 'maxLength', 'maxOffset']) ||
      grant.constraints.maxBytes !== 65_536 || grant.constraints.maxLength !== 1_000 ||
      grant.constraints.maxOffset !== 100_000 || grant.revision !== 1) throw failure('AMBIGUOUS');
  return Object.freeze({ status: 'provisioned', deviceId: approval.deviceId,
    fingerprint: confirmation.fingerprint, clientId: config.machineClientId,
    bindingRevision: bindingResponse.revision, grantId: grant.grantId,
    grantRevision: grantResponse.revision, tool: 'read_file', scopeRoot: config.allowedRoot,
    binding: Object.freeze({ ...binding }),
    grant: Object.freeze({ grantId: grant.grantId, deviceId: grant.deviceId,
      tool: grant.tool, scope: Object.freeze({ root: grant.scope.root }),
      constraints: Object.freeze({ ...grant.constraints }), revision: grant.revision }) });
}

function readStdin() {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let bytes = 0;
    process.stdin.on('data', chunk => {
      bytes += chunk.length;
      if (bytes > MAX_INPUT_BYTES) {
        process.stdin.destroy();
        reject(failure('CONFIRMATION'));
      } else chunks.push(chunk);
    });
    process.stdin.once('error', () => reject(failure('CONFIRMATION')));
    process.stdin.once('end', () => {
      try { resolve(JSON.parse(Buffer.concat(chunks, bytes).toString('utf8'))); }
      catch { reject(failure('CONFIRMATION')); }
    });
  });
}

function parseArgs(args) {
  if (args.length !== 2 || args[0] !== '--config' || !path.isAbsolute(args[1]) ||
      path.normalize(args[1]) !== args[1]) throw failure('USAGE');
  return args[1];
}

export async function runOwnerProvisionCli(args = process.argv.slice(2)) {
  try {
    if (process.platform !== 'linux' || typeof process.getuid !== 'function' || process.getuid() === 0) {
      throw failure('CONFIG');
    }
    const configPath = parseArgs(args);
    const config = JSON.parse(readSafeFile(configPath).toString('utf8'));
    const validated = validateConfig(config);
    const confirmation = parseConfirmation(await readStdin());
    const result = await runProvisioning(validated, confirmation);
    process.stdout.write(JSON.stringify(result) + '\n');
    return 0;
  } catch (error) {
    if (error?.code === 'AMBIGUOUS') {
      process.stderr.write('Provisioning result is ambiguous; inspect durable staging state before any retry.\n');
    } else if (error?.code === 'CONFIG' || error?.code === 'USAGE') {
      process.stderr.write('Invalid synthetic staging Owner client configuration or invocation.\n');
    } else if (error?.code === 'CONFIRMATION') {
      process.stderr.write('Invalid Owner confirmation input; provide requestId, code, and fingerprint on stdin.\n');
    } else {
      process.stderr.write('Staging provisioning stopped; inspect observed state before another attempt.\n');
    }
    return 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  process.exitCode = await runOwnerProvisionCli();
}
