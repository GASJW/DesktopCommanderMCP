import { createHash, createPublicKey, verify as verifySignature } from 'node:crypto';

const PRIVATE_JWK_MEMBERS = new Set(['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth']);
const VERIFIED = new WeakSet();
const REFERENCES = new WeakSet();
const MAX_TOKEN_SECONDS = 3600;
const CLOCK_SKEW_SECONDS = 30;
const HEX24 = /^[a-f0-9]{24}$/;
const HEX64 = /^[a-f0-9]{64}$/;

function exact(value, keys) {
  return value && typeof value === 'object' && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype &&
    Object.keys(value).sort().join(',') === keys;
}

function httpsUrl(value, { issuer = false } = {}) {
  if (typeof value !== 'string' || value.length > 2048) return false;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && !url.username && !url.password &&
      !url.search && !url.hash && url.href === value &&
      (!issuer || value.endsWith('/'));
  } catch { return false; }
}

function decodeJson(segment) {
  if (typeof segment !== 'string' || !segment ||
      !/^[A-Za-z0-9_-]+$/.test(segment) || segment.length > 16 * 1024) {
    throw new Error('Invalid JWT segment');
  }
  const bytes = Buffer.from(segment, 'base64url');
  if (bytes.toString('base64url') !== segment) throw new Error('Invalid JWT encoding');
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
}

function ownerReference(issuer, subject) {
  const digest = createHash('sha256')
    .update('VPSC-I8F-AUTH0-OWNER-v1\n')
    .update(JSON.stringify([issuer, subject]))
    .digest('hex');
  return { ownerId: digest.slice(0, 24), ownerDigest: digest };
}

export function isAuth0OwnerPrincipal(value) {
  return !!value && VERIFIED.has(value);
}

export function auth0OwnerPrincipalId(value) {
  if (!isAuth0OwnerPrincipal(value)) throw new TypeError('Verified Auth0 Owner principal required');
  return value.ownerId;
}

export function auth0OwnerIdentityDigest(value) {
  if (!isAuth0OwnerPrincipal(value)) throw new TypeError('Verified Auth0 Owner principal required');
  return value.ownerDigest;
}

export function createAuth0OwnerIdentityReference({ issuer, ownerId, ownerDigest } = {}) {
  if (!httpsUrl(issuer, { issuer: true }) || !HEX24.test(ownerId ?? '') ||
      !HEX64.test(ownerDigest ?? '') || ownerId !== ownerDigest.slice(0, 24)) {
    throw new TypeError('Invalid durable Auth0 Owner reference');
  }
  const reference = Object.freeze({ issuer, ownerId, ownerDigest });
  REFERENCES.add(reference);
  return reference;
}

export function isAuth0OwnerIdentityReference(value) {
  return !!value && REFERENCES.has(value);
}

export function createAuth0OwnerVerifier(config, { now = Date.now } = {}) {
  if (!exact(config, 'authorizedClientIds,issuer,jwks,ownerScope,readScope,resource') ||
      !httpsUrl(config.issuer, { issuer: true }) || !httpsUrl(config.resource) ||
      config.readScope !== 'g7.read' || config.ownerScope !== 'g7.owner' ||
      typeof now !== 'function' || !Array.isArray(config.authorizedClientIds) ||
      config.authorizedClientIds.length < 1 || config.authorizedClientIds.length > 16 ||
      config.authorizedClientIds.some(id => typeof id !== 'string' || id.length < 1 ||
        id.length > 256 || /[\s\0]/.test(id)) ||
      new Set(config.authorizedClientIds).size !== config.authorizedClientIds.length ||
      !Array.isArray(config.jwks) || config.jwks.length < 1 || config.jwks.length > 32) {
    throw new TypeError('Invalid Auth0 Owner verifier configuration');
  }

  const keys = new Map();
  for (const jwk of config.jwks) {
    if (!jwk || jwk.kty !== 'RSA' || jwk.alg !== 'RS256' ||
        jwk.use !== undefined && jwk.use !== 'sig' ||
        typeof jwk.kid !== 'string' || !jwk.kid || jwk.kid.length > 256 ||
        /[\0\r\n]/.test(jwk.kid) || typeof jwk.n !== 'string' ||
        jwk.n.length > 4096 || typeof jwk.e !== 'string' || jwk.e.length > 32 ||
        [...PRIVATE_JWK_MEMBERS].some(member => Object.hasOwn(jwk, member)) ||
        keys.has(jwk.kid)) {
      throw new TypeError('Auth0 JWKS must contain unique public RS256 keys');
    }
    let publicKey;
    try { publicKey = createPublicKey({ key: jwk, format: 'jwk' }); }
    catch { throw new TypeError('Invalid Auth0 public key'); }
    if (publicKey.asymmetricKeyType !== 'rsa' ||
        (publicKey.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) {
      throw new TypeError('Auth0 RSA keys must be at least 2048 bits');
    }
    keys.set(jwk.kid, publicKey);
  }

  const clients = new Set(config.authorizedClientIds);
  function verifyAccessToken(token, { requiredScope = config.readScope } = {}) {
    if (!['g7.read', 'g7.owner'].includes(requiredScope) ||
        typeof token !== 'string' || token.length < 30 || token.length > 16 * 1024) return null;
    const segments = token.split('.');
    if (segments.length !== 3) return null;
    try {
      const [encodedHeader, encodedPayload, encodedSignature] = segments;
      const header = decodeJson(encodedHeader);
      const payload = decodeJson(encodedPayload);
      if (!exact(header, Object.keys(header ?? {}).sort().join(',')) ||
          Object.keys(header).some(name => !['alg', 'kid', 'typ'].includes(name)) ||
          header.alg !== 'RS256' || typeof header.kid !== 'string' ||
          !['at+jwt', 'jwt'].includes(String(header.typ ?? '').toLowerCase()) ||
          !payload || Object.getPrototypeOf(payload) !== Object.prototype) return null;
      const key = keys.get(header.kid);
      if (!key) return null;
      const timestamp = now();
      if (!Number.isSafeInteger(timestamp)) return null;
      const seconds = Math.floor(timestamp / 1000);
      const audience = payload.aud;
      const audienceMatches = audience === config.resource ||
        Array.isArray(audience) && audience.length > 0 && audience.includes(config.resource) &&
          audience.every(value => typeof value === 'string') &&
          new Set(audience).size === audience.length;
      const clientId = payload.client_id ?? payload.azp;
      const scopes = typeof payload.scope === 'string'
        ? payload.scope.split(/\s+/).filter(Boolean) : [];
      if (payload.iss !== config.issuer || !audienceMatches ||
          typeof payload.sub !== 'string' || payload.sub.length < 1 || payload.sub.length > 1024 ||
          /[\0-\x1f\x7f]/.test(payload.sub) || !Number.isSafeInteger(payload.exp) ||
          payload.exp <= seconds || !Number.isSafeInteger(payload.iat) ||
          payload.iat > seconds + CLOCK_SKEW_SECONDS || payload.exp <= payload.iat ||
          payload.exp - payload.iat > MAX_TOKEN_SECONDS ||
          payload.nbf !== undefined && (!Number.isSafeInteger(payload.nbf) ||
            payload.nbf > seconds + CLOCK_SKEW_SECONDS) ||
          typeof clientId !== 'string' || !clients.has(clientId) ||
          payload.client_id !== undefined && payload.client_id !== clientId ||
          payload.azp !== undefined && payload.azp !== clientId ||
          !scopes.includes(requiredScope) || new Set(scopes).size !== scopes.length) return null;
      const signature = Buffer.from(encodedSignature, 'base64url');
      if (!signature.length || signature.toString('base64url') !== encodedSignature ||
          !verifySignature('RSA-SHA256', Buffer.from(`${encodedHeader}.${encodedPayload}`), key, signature)) {
        return null;
      }
      const ref = ownerReference(payload.iss, payload.sub);
      const principal = {
        issuer: payload.iss,
        ...ref,
        clientId,
        scopes: Object.freeze(scopes.slice()),
        keyId: header.kid,
        expiresAt: payload.exp,
      };
      Object.defineProperty(principal, 'subject', { value: payload.sub, enumerable: false });
      Object.freeze(principal);
      VERIFIED.add(principal);
      return principal;
    } catch { return null; }
  }

  return Object.freeze({
    issuer: config.issuer,
    resource: config.resource,
    authorizedClientIds: Object.freeze(config.authorizedClientIds.slice()),
    readScope: config.readScope,
    ownerScope: config.ownerScope,
    verifyAccessToken,
    verifyPrincipal: token => verifyAccessToken(token, { requiredScope: config.readScope }),
    verifyAdminPrincipal: token => verifyAccessToken(token, { requiredScope: config.ownerScope }),
  });
}
