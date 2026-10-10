// Validate Cloudflare Access signed origin assertions. Never trust a header alone.
import { createPublicKey, verify as verifySignature } from 'node:crypto';

const MAX_JWT_LENGTH = 16 * 1024;
const KEY_CACHE_MS = 5 * 60 * 1000;
const ALLOW_CLOCK_SKEW = 30;

function segmentJson(segment) {
  if (typeof segment !== 'string' || !/^[A-Za-z0-9_-]+$/.test(segment) || segment.length > MAX_JWT_LENGTH) {
    throw new Error('Invalid JWT segment');
  }
  const bytes = Buffer.from(segment, 'base64url');
  if (!bytes.length || bytes.toString('base64url') !== segment) throw new Error('Invalid JWT base64url');
  return JSON.parse(bytes.toString('utf8'));
}

function getConfig({ issuer, audience, allowedEmails, keyProvider }) {
  if (typeof issuer !== 'string' || !/^https:\/\/[a-z0-9-]+\.cloudflareaccess\.com$/.test(issuer))
    throw new Error('Invalid Cloudflare Access issuer');
  if (typeof audience !== 'string' || !/^[a-f0-9]{64}$/i.test(audience))
    throw new Error('Missing or invalid Cloudflare Access audience');
  if (typeof allowedEmails !== 'string' || !allowedEmails.trim())
    throw new Error('VPS_COMMANDER_ALLOWED_EMAILS must contain authorized identities');
  const emails = new Set(allowedEmails.split(',').map(s => s.trim().toLowerCase()).filter(Boolean));
  if (![...emails].every(e => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e)))
    throw new Error('Invalid allowed email list');
  if (keyProvider !== undefined && typeof keyProvider !== 'function')
    throw new Error('Invalid key provider');
  return { issuer, audience: audience.toLowerCase(), emails, keyProvider };
}

export function createAccessVerifier(options = {}) {
  const c = getConfig(options);
  const keysEndpoint = c.issuer + '/cdn-cgi/access/certs';
  let cache = null;
  let cachedAt = 0;
  async function getKeys(force = false) {
    if (!force && cache && Date.now() - cachedAt < KEY_CACHE_MS) return cache;
    let data;
    if (c.keyProvider) {
      data = await c.keyProvider();
    } else {
      const ac = new AbortController();
      const timer = setTimeout(() => ac.abort(), 4500);
      try {
        const response = await fetch(keysEndpoint, { signal: ac.signal, redirect: 'error',
          headers: { accept: 'application/json' } });
        if (!response.ok) throw new Error('Cloudflare key endpoint error');
        data = await response.json();
      } finally { clearTimeout(timer); }
    }
    if (!data || !Array.isArray(data.keys) || data.keys.length === 0 || data.keys.length > 100)
      throw new Error('Invalid Cloudflare key set');
    const accepted = data.keys.filter(k => k && k.kty === 'RSA' && k.alg !== 'HS256' &&
      typeof k.kid === 'string' && k.kid.length < 256 && typeof k.n === 'string' && typeof k.e === 'string');
    if (!accepted.length) throw new Error('No valid Cloudflare signing keys');
    cache = accepted;
    cachedAt = Date.now();
    return cache;
  }

  return async function verifyAccess(assertion) {
    if (typeof assertion !== 'string' || assertion.length < 30 || assertion.length > MAX_JWT_LENGTH)
      return false;
    const segments = assertion.split('.');
    if (segments.length !== 3) return false;
    try {
      const [h, p, s] = segments;
      const header = segmentJson(h);
      if (!header || header.alg !== 'RS256' || typeof header.kid !== 'string' ||
          header.kid.length === 0 || header.kid.length >= 256) return false;
      const payload = segmentJson(p);
      if (!payload || typeof payload !== 'object') return false;
      const now = Math.floor(Date.now() / 1000);
      if (payload.iss !== c.issuer ||
          !(payload.aud === c.audience || (Array.isArray(payload.aud) && payload.aud.includes(c.audience))) ||
          !Number.isInteger(payload.exp) || payload.exp <= now - ALLOW_CLOCK_SKEW ||
          !Number.isInteger(payload.iat) || payload.iat > now + ALLOW_CLOCK_SKEW ||
          (payload.nbf != null && (!Number.isInteger(payload.nbf) || payload.nbf > now + ALLOW_CLOCK_SKEW)) ||
          typeof payload.email !== 'string' || !c.emails.has(payload.email.toLowerCase()) ||
          typeof payload.sub !== 'string' || payload.sub.length < 1) return false;
      let keys = await getKeys();
      let jwk = keys.find(k => k.kid === header.kid);
      if (!jwk) {
        keys = await getKeys(true);
        jwk = keys.find(k => k.kid === header.kid);
      }
      if (!jwk) return false;
      const signature = Buffer.from(s, 'base64url');
      if (signature.toString('base64url') !== s) return false;
      return verifySignature('RSA-SHA256', Buffer.from(h + '.' + p),
        createPublicKey({ key: jwk, format: 'jwk' }), signature);
    } catch {
      return false; // Every parsing, network, signature and clock failure denies access.
    }
  };
}
