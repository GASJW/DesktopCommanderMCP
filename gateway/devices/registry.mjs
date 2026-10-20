import { createHash, createPublicKey, randomBytes, randomUUID, timingSafeEqual, verify } from 'node:crypto';

// G7.1: inert, in-process registry. No HTTP route, executor dispatch or persistence.
// Transport, operator approval and durable storage are future gated changes.
const PLATFORMS = new Set(['linux', 'win32', 'darwin']);
const NAME_RE = /^[^\u0000-\u001f\u007f]{1,64}$/u;
const SIGN_DOMAIN = 'VPSC-AGENT-CHALLENGE-v1';
const challengeText = (deviceId, nonce) => Buffer.from(SIGN_DOMAIN + '\n' + deviceId + '\n' + nonce, 'utf8');
const validUuid = value => typeof value === 'string' &&
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
const sameSession = (actual, expected) => {
  if (typeof actual !== 'string' || typeof expected !== 'string') return false;
  const a = Buffer.from(actual, 'utf8');
  const b = Buffer.from(expected, 'utf8');
  return a.length === b.length && timingSafeEqual(a, b);
};

export function deviceChallengeMessage(deviceId, nonce) {
  if (!validUuid(deviceId) || typeof nonce !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(nonce)) {
    throw new TypeError('Invalid device challenge');
  }
  return challengeText(deviceId, nonce);
}

export function createDeviceRegistry({
  now = Date.now,
  heartbeatTtlMs = 45_000,
  challengeTtlMs = 30_000,
  maxDevices = 32,
  initialTrustedDevices = [],
} = {}) {
  if (typeof now !== 'function' ||
      !Number.isSafeInteger(heartbeatTtlMs) || heartbeatTtlMs < 1_000 || heartbeatTtlMs > 300_000 ||
      !Number.isSafeInteger(challengeTtlMs) || challengeTtlMs < 1_000 || challengeTtlMs > 120_000 ||
      !Number.isSafeInteger(maxDevices) || maxDevices < 1 || maxDevices > 256) {
    throw new TypeError('Invalid registry options');
  }
  const devices = new Map();
  const fingerprints = new Set();
  const timestamp = () => {
    const value = now();
    if (!Number.isSafeInteger(value) || value < 0) throw new TypeError('Invalid registry clock');
    return value;
  };
  const entry = deviceId => devices.get(deviceId);
  function trustedEntry(record,existing){
    if (!record || typeof record !== 'object' || Array.isArray(record) ||
        Object.keys(record).sort().join(',') !== 'deviceId,fingerprint,name,platform,publicKeyPem' ||
        !validUuid(record.deviceId) || typeof record.name !== 'string' ||
        !NAME_RE.test(record.name.trim()) || record.name !== record.name.trim() ||
        !PLATFORMS.has(record.platform) || typeof record.publicKeyPem !== 'string' ||
        Buffer.byteLength(record.publicKeyPem,'utf8') > 1024 ||
        typeof record.fingerprint !== 'string' || !/^[a-f0-9]{64}$/.test(record.fingerprint)) {
      throw new TypeError('Invalid initial trusted device');
    }
    let key;
    try {key=createPublicKey(record.publicKeyPem);}
    catch {throw new TypeError('Invalid initial trusted public key');}
    if (key.asymmetricKeyType !== 'ed25519')throw new TypeError('Trusted key must be Ed25519');
    const fingerprint=createHash('sha256').update(key.export({type:'spki',format:'der'})).digest('hex');
    if(fingerprint!==record.fingerprint)throw new Error('Invalid trusted identity fingerprint');
    return existing?.fingerprint===fingerprint
      ?{...existing,name:record.name,platform:record.platform,key}
      :{deviceId:record.deviceId,name:record.name,platform:record.platform,key,fingerprint,
        trustedAt:timestamp(),challenge:null,session:null,lastSeenAt:null};
  }

  // Only an already-authorized owner workflow may call this operation in G7.2.
  // Never expose registration directly to an unauthenticated agent.
  function trustDevice({ name, platform, publicKeyPem, deviceId: requestedDeviceId } = {}) {
    if (typeof name !== 'string' || !NAME_RE.test(name.trim()) ||
        !PLATFORMS.has(platform) || typeof publicKeyPem !== 'string' ||
        Buffer.byteLength(publicKeyPem, 'utf8') > 1024) throw new TypeError('Invalid device metadata');
    if (devices.size >= maxDevices) throw new Error('Device capacity reached');
    let key;
    try { key = createPublicKey(publicKeyPem); } catch { throw new TypeError('Invalid device public key'); }
    if (key.asymmetricKeyType !== 'ed25519') throw new TypeError('Ed25519 public key required');
    const fingerprint = createHash('sha256').update(key.export({ type: 'spki', format: 'der' })).digest('hex');
    if (fingerprints.has(fingerprint)) throw new Error('Duplicate device public key');
    const deviceId = requestedDeviceId ?? randomUUID();
    if (!validUuid(deviceId) || devices.has(deviceId)) throw new Error('Invalid or duplicate device ID');
    devices.set(deviceId, {
      deviceId, name: name.trim(), platform, key, fingerprint,
      trustedAt: timestamp(), challenge: null, session: null, lastSeenAt: null,
    });
    fingerprints.add(fingerprint);
    return Object.freeze({ deviceId, name: name.trim(), platform, fingerprint });
  }

  function beginHandshake(deviceId) {
    const d = entry(deviceId);
    if (!d) throw new Error('Device not trusted');
    const nonce = randomBytes(32).toString('base64url');
    d.challenge = { nonce, issuedAt: timestamp() };
    return Object.freeze({ deviceId, nonce, expiresInMs: challengeTtlMs });
  }

  function completeHandshake(deviceId, signatureBase64url) {
    const d = entry(deviceId);
    if (!d || !d.challenge) throw new Error('No pending challenge');
    const challenge = d.challenge;
    d.challenge = null; // Consume even on an invalid signature; never replay.
    if (timestamp() - challenge.issuedAt > challengeTtlMs || timestamp() < challenge.issuedAt) {
      throw new Error('Challenge expired');
    }
    if (typeof signatureBase64url !== 'string' ||
        !/^[A-Za-z0-9_-]{86}$/.test(signatureBase64url)) throw new Error('Invalid signature');
    const valid = verify(null, deviceChallengeMessage(deviceId, challenge.nonce), d.key,
      Buffer.from(signatureBase64url, 'base64url'));
    if (!valid) throw new Error('Invalid signature');
    const sessionId = randomUUID();
    d.session = { sessionId, connectedAt: timestamp(), lastSequence: 0 };
    d.lastSeenAt = null;
    return Object.freeze({ deviceId, sessionId });
  }

  function heartbeat(deviceId, sessionId, sequence) {
    const d = entry(deviceId);
    const session = d?.session;
    if (!session || !sameSession(sessionId, session.sessionId)) return false;
    const t = timestamp();
    const lastAt = d.lastSeenAt ?? session.connectedAt;
    if (t < lastAt || t - lastAt > heartbeatTtlMs) {
      d.session = null; // Expired channels require fresh challenge/signature.
      return false;
    }
    if (!Number.isSafeInteger(sequence) || sequence <= session.lastSequence || sequence <= 0) return false;
    session.lastSequence = sequence;
    d.lastSeenAt = t;
    return true;
  }

  function disconnect(deviceId, sessionId) {
    const d = entry(deviceId);
    if (!d?.session || !sameSession(sessionId, d.session.sessionId)) return false;
    d.session = null;
    d.challenge = null;
    return true;
  }

  function revokeDevice(deviceId) {
    const d = entry(deviceId);
    if (!d) return false;
    d.session = null;
    d.challenge = null;
    devices.delete(deviceId);
    fingerprints.delete(d.fingerprint);
    return true;
  }

  // G7.2: server-internal session validation for routing, never exposed to clients.
  // A new handshake, revocation, disconnect or stale heartbeat fences old channels.
  function isLiveSession(deviceId, sessionId) {
    const d = entry(deviceId);
    if (!d?.session || d.lastSeenAt === null ||
        !sameSession(sessionId, d.session.sessionId)) return false;
    const t = timestamp();
    return t >= d.lastSeenAt && t - d.lastSeenAt <= heartbeatTtlMs;
  }

  // G7.2c: authenticate a signed transport frame, with replay protection.
  // Signature is bound to method, route, body digest and monotonically increasing sequence
  // by the caller-supplied canonical frame. No session token alone authorizes a request.
  function acceptSignedFrame(deviceId, sessionId, sequence, frameBytes, signatureBase64url) {
    const d = entry(deviceId);
    const session = d?.session;
    if (!session || !sameSession(sessionId, session.sessionId) ||
        !Number.isSafeInteger(sequence) || sequence <= session.lastSequence || sequence < 1 ||
        !Buffer.isBuffer(frameBytes) || frameBytes.length < 32 || frameBytes.length > 1024 ||
        typeof signatureBase64url !== 'string' ||
        !/^[A-Za-z0-9_-]{86}$/.test(signatureBase64url)) return false;
    const t = timestamp();
    const lastAt = d.lastSeenAt ?? session.connectedAt;
    if (t < lastAt || t - lastAt > heartbeatTtlMs) {
      d.session = null;
      return false;
    }
    if (!verify(null, frameBytes, d.key, Buffer.from(signatureBase64url, 'base64url'))) return false;
    session.lastSequence = sequence;
    d.lastSeenAt = t;
    return true;
  }

  // Trusted records are public-key-only durable identities. Restoring them
  // NEVER restores an old transport session, challenge or online status.
  function snapshotTrustedDevices() {
    return Array.from(devices.values(), d => Object.freeze({
      deviceId:d.deviceId, name:d.name, platform:d.platform,
      publicKeyPem:d.key.export({type:'spki',format:'pem'}),
      fingerprint:d.fingerprint,
    })).sort((a,b)=>a.deviceId.localeCompare(b.deviceId));
  }

  function replaceTrustedDevices(records){
    if(!Array.isArray(records)||records.length>maxDevices)throw new TypeError('Invalid trusted devices');
    const next=new Map(),nextFingerprints=new Set();
    for(const record of records){
      const d=trustedEntry(record,devices.get(record?.deviceId));
      if(next.has(d.deviceId)||nextFingerprints.has(d.fingerprint)){
        throw new Error('Invalid or duplicated trusted identity');
      }
      next.set(d.deviceId,d);nextFingerprints.add(d.fingerprint);
    }
    devices.clear();fingerprints.clear();
    for(const [deviceId,d]of next)devices.set(deviceId,d);
    for(const fingerprint of nextFingerprints)fingerprints.add(fingerprint);
  }

  if (!Array.isArray(initialTrustedDevices) || initialTrustedDevices.length > maxDevices) {
    throw new TypeError('Invalid initial trusted devices');
  }
  for (const record of initialTrustedDevices) {
    const d=trustedEntry(record,null);
    if(devices.has(d.deviceId)||fingerprints.has(d.fingerprint))
      throw new Error('Invalid or duplicated trusted identity');
    devices.set(d.deviceId,d);fingerprints.add(d.fingerprint);
  }

  function listDevices() {
    const t = timestamp();
    return Array.from(devices.values(), d => {
      const session = d.session;
      const lastAt = d.lastSeenAt;
      const online = Boolean(session && lastAt !== null && t >= lastAt &&
        t - lastAt <= heartbeatTtlMs);
      return Object.freeze({
        deviceId: d.deviceId, name: d.name, platform: d.platform,
        online, lastSeenAt: lastAt === null ? null : new Date(lastAt).toISOString(),
      });
    }).sort((a, b) => a.name.localeCompare(b.name) || a.deviceId.localeCompare(b.deviceId));
  }

  return Object.freeze({ trustDevice, beginHandshake, completeHandshake,
    heartbeat, disconnect, revokeDevice, listDevices, isLiveSession, acceptSignedFrame,
    snapshotTrustedDevices,replaceTrustedDevices });
}
