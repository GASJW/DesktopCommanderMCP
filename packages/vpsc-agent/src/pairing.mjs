import { createHash, generateKeyPairSync, sign } from 'node:crypto';

// Agent-side ephemeral proof only. Does not store a private key, open a network
// connection or execute any shell/MCP tool. Not a persistent install identity.
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const NONCE = /^[A-Za-z0-9_-]{43}$/;
const DOMAIN = 'VPSC-DEVICE-PAIRING-v1';

export function createEphemeralPairingIdentity() {
  const {publicKey,privateKey} = generateKeyPairSync('ed25519');
  const publicKeyPem = publicKey.export({type:'spki',format:'pem'});
  const fingerprint = createHash('sha256')
    .update(publicKey.export({type:'spki',format:'der'})).digest('hex');
  const used = new Set();
  function prove({requestId,nonce,fingerprint:serverFingerprint} = {}) {
    if (typeof requestId !== 'string' || !UUID.test(requestId) ||
        typeof nonce !== 'string' || !NONCE.test(nonce) ||
        serverFingerprint !== fingerprint) throw new TypeError('Pairing challenge mismatch');
    const challengeKey = requestId + ':' + nonce;
    if (used.has(challengeKey)) throw new Error('Pairing proof already used');
    used.add(challengeKey);
    return sign(null,Buffer.from([DOMAIN,requestId,nonce,fingerprint].join('\n'),'utf8'),
      privateKey).toString('base64url');
  }
  function proveDeviceChallenge({deviceId, nonce} = {}) {
    if (typeof deviceId !== 'string' ||
        !UUID.test(deviceId) || typeof nonce !== 'string' || !NONCE.test(nonce)) {
      throw new TypeError('Invalid device challenge');
    }
    return sign(null,Buffer.from(['VPSC-AGENT-CHALLENGE-v1',deviceId,nonce].join('\n'),'utf8'),
      privateKey).toString('base64url');
  }
  function signFrame(frameBytes) {
    if (!Buffer.isBuffer(frameBytes) || frameBytes.length < 32 || frameBytes.length > 1024) {
      throw new TypeError('Invalid transport frame');
    }
    return sign(null,frameBytes,privateKey).toString('base64url');
  }
  return Object.freeze({publicKeyPem,fingerprint,prove,proveDeviceChallenge,signFrame});
}
