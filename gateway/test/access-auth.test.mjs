import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createAccessVerifier } from '../access-auth.mjs';
import { startGateway } from '../server.mjs';

const root = path.dirname(fileURLToPath(import.meta.url));
const mock = path.join(root, 'fixtures', 'mock-executor.mjs');
const issuer = 'https://example.cloudflareaccess.com';
const audience = 'd'.repeat(64);
const email = 'owner@example.test';
const keys = generateKeyPairSync('rsa', { modulusLength: 2048 });
const publicJwk = { ...keys.publicKey.export({ format: 'jwk' }), use: 'sig', alg: 'RS256', kid: 'test-kid-1' };
const jwks = async () => ({ keys: [publicJwk] });
const now = () => Math.floor(Date.now() / 1000);
function jwt(overrides={}, extra={}) {
  const claims = { iss: issuer, aud: [audience], sub: 'identity-id', email, iat: now(), exp: now()+300, ...overrides };
  const head = { alg: 'RS256', typ: 'JWT', kid: 'test-kid-1', ...extra };
  const data = Buffer.from(JSON.stringify(head)).toString('base64url') + '.' + Buffer.from(JSON.stringify(claims)).toString('base64url');
  return data + '.' + sign('RSA-SHA256', Buffer.from(data), keys.privateKey).toString('base64url');
}
const auth = () => createAccessVerifier({ issuer, audience, allowedEmails: email, keyProvider: jwks });

test('Access verifier rejects invalid config (fail closed)', () => {
  assert.throws(() => createAccessVerifier({issuer:'https://evil.test',audience,allowedEmails:email}), /issuer/);
  assert.throws(() => createAccessVerifier({issuer,audience:'abc',allowedEmails:email}), /audience/);
  assert.throws(() => createAccessVerifier({issuer,audience,allowedEmails:''}), /authorized identities/);
});

test('Access JWT verification accepts only signed, fresh, audience-bound owner tokens', async () => {
  const verify = auth();
  assert.equal(await verify(jwt()), true);
  const missingOrWrong = [
    '', 'not-a-token', 'x.y.z',
    jwt({iss:'https://other.cloudflareaccess.com'}),
    jwt({aud:['f'.repeat(64)]}),
    jwt({sub:''}),
    jwt({email:'intruder@example.test'}),
    jwt({exp:now()-3600}),
    jwt({iat:now()+3600}),
    jwt({nbf:now()+3600}),
    jwt({}, {alg:'none'}),
    jwt({}, {kid:'unknown-key'}),
    jwt().replace(/.$/, x=>x==='A'?'B':'A'),
  ];
  for(const candidate of missingOrWrong) assert.equal(await verify(candidate), false, candidate.slice(0,25));
  const deadKeys = createAccessVerifier({issuer,audience,allowedEmails:email,keyProvider:async()=>{throw Error('offline');}});
  assert.equal(await deadKeys(jwt()),false);
});

test('Access gateway does not accept static local bearer or spoofed JWT headers', async () => {
  const app = await startGateway({ authMode:'access', accessIssuer:issuer, accessAudience:audience,
    allowedEmails:email, accessKeyProvider:jwks, executorFile:mock, port:0 });
  const body = JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/list',params:{}});
  const req = async(headers={}) => fetch(app.address+'/mcp',{method:'POST',
    headers:{'content-type':'application/json', ...headers},body});
  try {
    assert.equal((await req()).status,401);
    assert.equal((await req({authorization:'Bearer '+'a'.repeat(80)})).status,401);
    assert.equal((await req({'cf-access-jwt-assertion':jwt({email:'evil@example.test'})})).status,401);
    assert.equal((await req({'cf-access-jwt-assertion':jwt({aud:'f'.repeat(64)})})).status,401);
    const good = await req({'cf-access-jwt-assertion':jwt()});
    assert.equal(good.status,200);
    assert.equal((await good.json()).result.tools[0].name,'echo');
  } finally { await app.close(); }
});
