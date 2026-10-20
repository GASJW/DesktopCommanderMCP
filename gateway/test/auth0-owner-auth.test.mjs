import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { createAuth0OwnerVerifier, createAuth0OwnerIdentityReference,
  isAuth0OwnerIdentityReference, isAuth0OwnerPrincipal } from '../owner/auth0-owner-auth.mjs';
import { isOwnerPrincipal, ownerIdentityDigest, ownerPrincipalId,
  STAGING_OWNER_ISSUER } from '../dashboard/owner-identity.mjs';

const ISSUER = 'https://auth.example.test/';
const RESOURCE = 'https://g7.example.test/chatgpt/mcp';
const CLIENT = 'chatgpt-cimd-test';
const NOW = Date.now();
const seconds = Math.floor(NOW / 1000);

function rsa(kid) {
  const pair = generateKeyPairSync('rsa', { modulusLength: 2048 });
  return { ...pair, jwk: { ...pair.publicKey.export({ format: 'jwk' }),
    kid, alg: 'RS256', use: 'sig' } };
}

const current = rsa('current');
const next = rsa('next');
const verifier = createAuth0OwnerVerifier({ issuer: ISSUER, resource: RESOURCE,
  authorizedClientIds: [CLIENT], readScope: 'g7.read', ownerScope: 'g7.owner',
  jwks: [current.jwk, next.jwk] }, { now: () => NOW });

function token(claims = {}, header = {}, key = current.privateKey) {
  const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url');
  const h = encode({ alg: 'RS256', kid: 'current', typ: 'JWT', ...header });
  const p = encode({ iss: ISSUER, sub: 'google-oauth2|synthetic-subject',
    aud: RESOURCE, client_id: CLIENT, scope: 'g7.read', iat: seconds,
    exp: seconds + 600, ...claims });
  const input = `${h}.${p}`;
  return `${input}.${sign('RSA-SHA256', Buffer.from(input), key).toString('base64url')}`;
}

test('Auth0 verifier brands only signed principals and keeps the subject out of enumerable state', () => {
  const accessToken = token();
  const principal = verifier.verifyPrincipal(accessToken);
  assert.ok(principal);
  assert.ok(isAuth0OwnerPrincipal(principal));
  assert.ok(isOwnerPrincipal(principal));
  assert.equal(principal.subject, 'google-oauth2|synthetic-subject');
  assert.equal(Object.keys(principal).includes('subject'), false);
  assert.equal(JSON.stringify(principal).includes(principal.subject), false);
  assert.equal(principal.ownerId, createHash('sha256').update(
    `VPSC-I8F-AUTH0-OWNER-v1\n${JSON.stringify([ISSUER, principal.subject])}`)
    .digest('hex').slice(0, 24));
  assert.equal(ownerPrincipalId(principal), principal.ownerId);
  assert.equal(ownerIdentityDigest(principal).length, 64);
  assert.equal(verifier.verifyAdminPrincipal(accessToken), null);

  const reference = createAuth0OwnerIdentityReference({ issuer: ISSUER,
    ownerId: principal.ownerId, ownerDigest: ownerIdentityDigest(principal) });
  assert.ok(isAuth0OwnerIdentityReference(reference));
  assert.equal(JSON.stringify(reference).includes(principal.subject), false);
  assert.throws(() => ownerIdentityDigest({ issuer: ISSUER, subject: principal.subject }),
    /Verified owner principal required/);
});

test('Auth0 verifier distinguishes read and owner scopes and accepts overlapping public keys', () => {
  const read = verifier.verifyPrincipal(token({ aud: [RESOURCE, 'https://userinfo.example.test/'] },
    { kid: 'current', typ: 'at+jwt' }));
  const admin = verifier.verifyAdminPrincipal(token({ scope: 'g7.owner' }, { kid: 'next' }, next.privateKey));
  assert.ok(read);
  assert.ok(admin);
  assert.deepEqual(verifier.authorizedClientIds, [CLIENT]);
  assert.equal(verifier.resource, RESOURCE);
  assert.equal(verifier.issuer, ISSUER);
  assert.equal(verifier.verifyPrincipal(token({ scope: 'g7.owner' })), null);
  assert.equal(verifier.verifyAdminPrincipal(token({ scope: 'g7.read' })), null);
});

test('Auth0 verifier rejects wrong issuer, subject, audience, client, scope, time, key and signature', () => {
  const invalid = [
    token({ iss: 'https://attacker.example.test/' }),
    token({ sub: '' }),
    token({ aud: 'https://other.example.test/' }),
    token({ aud: [RESOURCE, RESOURCE] }),
    token({ client_id: 'other-client' }),
    token({ azp: 'other-client' }),
    token({ scope: 'profile' }),
    token({ scope: 'g7.read g7.read' }),
    token({ exp: seconds }),
    token({ iat: seconds + 31 }),
    token({ nbf: seconds + 31 }),
    token({}, { kid: 'unknown' }),
    token({}, { crit: ['b64'] }),
    token({}, {}, generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey),
  ];
  for (const candidate of invalid) assert.equal(verifier.verifyPrincipal(candidate), null);
  const principal = verifier.verifyPrincipal(token());
  const mismatched = token({ sub: 'different-subject' });
  assert.notEqual(verifier.verifyPrincipal(mismatched).ownerDigest, principal.ownerDigest);
  assert.equal(isOwnerPrincipal({ issuer: 'https://auth.example.test/', subject: 'spoofed' }), false);
  assert.equal(isOwnerPrincipal({ issuer: STAGING_OWNER_ISSUER, subject: 'staging' }), true);
});
