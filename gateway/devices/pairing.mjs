import { createHash, createPublicKey, randomBytes, randomUUID, verify } from 'node:crypto';

// Inert G7.2b pairing state machine: NOT bound to any public endpoint.
// Only the future cryptographically authenticated owner control plane may
// invoke approvePairing/rejectPairing. Proving possession is never approval.
const NAME = /^[^\u0000-\u001f\u007f]{1,64}$/u;
const PLATFORMS = new Set(['linux', 'win32', 'darwin']);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const NONCE = /^[A-Za-z0-9_-]{43}$/;
const SIGNATURE = /^[A-Za-z0-9_-]{86}$/;
const FINGERPRINT = /^[a-f0-9]{64}$/;
const DOMAIN = 'VPSC-DEVICE-PAIRING-v1';

function keyIdentity(publicKeyPem) {
  if (typeof publicKeyPem !== 'string' ||
      Buffer.byteLength(publicKeyPem, 'utf8') > 1024) throw new TypeError('Invalid key material');
  let publicKey;
  try { publicKey = createPublicKey(publicKeyPem); } catch {
    throw new TypeError('Invalid key material');
  }
  if (publicKey.asymmetricKeyType !== 'ed25519') throw new TypeError('Ed25519 required');
  const fingerprint = createHash('sha256')
    .update(publicKey.export({ type: 'spki', format: 'der' })).digest('hex');
  return { publicKey, fingerprint };
}

export function pairingProofMessage(requestId, nonce, fingerprint) {
  if (typeof requestId !== 'string' || !UUID.test(requestId) ||
      typeof nonce !== 'string' || !NONCE.test(nonce) ||
      typeof fingerprint !== 'string' || !FINGERPRINT.test(fingerprint)) {
    throw new TypeError('Invalid pairing proof components');
  }
  return Buffer.from([DOMAIN, requestId, nonce, fingerprint].join('\n'), 'utf8');
}

export function createPairingCoordinator({
  registry, now = Date.now, ttlMs = 120_000, maxPending = 16,
  preallocateDeviceId = false,
} = {}) {
  if (!registry || typeof registry.trustDevice !== 'function' ||
      typeof now !== 'function' || typeof preallocateDeviceId !== 'boolean' ||
      !Number.isSafeInteger(ttlMs) || ttlMs < 10_000 || ttlMs > 600_000 ||
      !Number.isSafeInteger(maxPending) || maxPending < 1 || maxPending > 128) {
    throw new TypeError('Invalid pairing coordinator options');
  }
  const pending = new Map();
  const current = () => {
    const t = now();
    if (!Number.isSafeInteger(t) || t < 0) throw new TypeError('Invalid clock');
    return t;
  };
  function prune() {
    const time = current();
    for (const [id, item] of pending) {
      if (time < item.createdAt || time - item.createdAt >= ttlMs) pending.delete(id);
    }
  }
  function startPairing({name, platform, publicKeyPem} = {}) {
    prune();
    if (typeof name !== 'string' || !NAME.test(name.trim()) ||
        !PLATFORMS.has(platform)) throw new TypeError('Invalid pairing metadata');
    const {publicKey,fingerprint} = keyIdentity(publicKeyPem);
    if (Array.from(pending.values()).some(x => x.fingerprint === fingerprint)) {
      throw new Error('Key already has pending pairing');
    }
    if (pending.size >= maxPending) throw new Error('Pairing capacity reached');
    const requestId = randomUUID();
    const nonce = randomBytes(32).toString('base64url');
    const displayCode = randomBytes(5).toString('hex').toUpperCase();
    const createdAt = current();
    const deviceId=preallocateDeviceId?randomUUID():null;
    pending.set(requestId,{name:name.trim(),platform,publicKeyPem,publicKey,deviceId,
      fingerprint,nonce,displayCode,createdAt,proved:false});
    // The code is comparison-only and cannot authorize pairing.
    return Object.freeze({requestId,nonce,fingerprint,displayCode,expiresInMs:ttlMs,
      ...(deviceId?{deviceId}:{})});
  }
  function provePossession(requestId, signatureBase64url) {
    prune();
    const record = pending.get(requestId);
    if (!record || record.proved) return false;
    // A malformed or incorrect proof consumes the pairing request.
    if (typeof signatureBase64url !== 'string' || !SIGNATURE.test(signatureBase64url)) {
      pending.delete(requestId);
      return false;
    }
    const valid = verify(null, pairingProofMessage(requestId,record.nonce,record.fingerprint),
      record.publicKey,Buffer.from(signatureBase64url,'base64url'));
    if (!valid) {
      pending.delete(requestId);
      return false;
    }
    record.proved = true;
    record.nonce = null;
    return true;
  }
  function listPending() {
    prune();
    return Array.from(pending, ([requestId,item]) => Object.freeze({
      requestId,name:item.name,platform:item.platform,
      ...(item.deviceId?{deviceId:item.deviceId}:{}),
      fingerprint:item.fingerprint,displayCode:item.displayCode,
      proofVerified:item.proved,createdAt:new Date(item.createdAt).toISOString(),
    })).sort((a,b)=>a.createdAt.localeCompare(b.createdAt));
  }
  function inspectPairing(requestId) {
    prune();
    const record=pending.get(requestId);
    if(!record)return null;
    return Object.freeze({requestId,fingerprint:record.fingerprint,proofVerified:record.proved,
      ...(record.deviceId?{deviceId:record.deviceId}:{}),
      name:record.name,platform:record.platform,createdAt:new Date(record.createdAt).toISOString()});
  }
  function trustRevision() {
    if(typeof registry.revision!=='function')throw Error('Durable trust revision required');
    return registry.revision();
  }
  function approvePairing(requestId, expectedFingerprint, decision) {
    prune();
    const record = pending.get(requestId);
    if (!record || !record.proved || typeof expectedFingerprint !== 'string' ||
        expectedFingerprint !== record.fingerprint) {
      throw new Error('Pairing requires verified proof and matching owner-reviewed fingerprint');
    }
    // A failed registry trust does not auto-retry or approve the request.
    let trustOptions;
    if(decision!==undefined){
      if(!decision||typeof decision!=='object'||Array.isArray(decision)||
         Object.keys(decision).sort().join(',')!=='eventId,trustRevisionBefore'||
         !UUID.test(decision.eventId)||!Number.isSafeInteger(decision.trustRevisionBefore)||
         decision.trustRevisionBefore<0){
        throw new TypeError('Invalid owner pairing decision');
      }
      trustOptions={expectedRevision:decision.trustRevisionBefore,decision:{
        eventId:decision.eventId,requestId,fingerprint:record.fingerprint,
      }};
    }
    const trusted = registry.trustDevice({
      name:record.name,platform:record.platform,publicKeyPem:record.publicKeyPem,
      ...(record.deviceId?{deviceId:record.deviceId}:{}),
    },trustOptions);
    pending.delete(requestId);
    return trusted;
  }
  function rejectPairing(requestId) {
    prune();
    return pending.delete(requestId);
  }
  return Object.freeze({registry,preallocateDeviceId,startPairing,provePossession,listPending,inspectPairing,
    trustRevision,approvePairing,rejectPairing});
}
