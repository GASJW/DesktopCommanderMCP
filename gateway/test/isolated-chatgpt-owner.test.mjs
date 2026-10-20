import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { generateKeyPairSync, sign } from 'node:crypto';
import { createAuth0OwnerVerifier } from '../owner/auth0-owner-auth.mjs';
import { ownerIdentityDigest } from '../dashboard/owner-identity.mjs';
import { createChatGptReadOnlyBridge, CHATGPT_MCP_ROUTE,
  getChatGptResourceMetadataPath, validateIsolatedChatGptBridgeConfig }
  from '../chatgpt/read-only-bridge.mjs';

const ISSUER = 'https://auth.i8f.example.test/';
const RESOURCE = 'https://g7-i8f.example.test/chatgpt/mcp';
const CLIENT = 'chatgpt-cimd-i8f';
const DEVICE = 'b7e92caf-f591-44c4-8fb7-6c489ea573f4';
const SESSION = 'ab000000-0000-4000-8000-000000000001';
const APPROVAL = 'b7e92caf-f591-44c4-8fb7-6c489ea573f6';
const FINGERPRINT = 'b'.repeat(64);
const GRANT = 'b7e92caf-f591-44c4-8fb7-6c489ea573f7';

test('isolated ChatGPT bridge authenticates only the active Auth0 Owner and exposes read_file', async t => {
  const auth = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...auth.publicKey.export({ format: 'jwk' }), kid: 'i8f-auth0', alg: 'RS256', use: 'sig' };
  const now = Math.floor(Date.now() / 1000);
  const verifier = createAuth0OwnerVerifier({ issuer: ISSUER, resource: RESOURCE,
    authorizedClientIds: [CLIENT], readScope: 'g7.read', ownerScope: 'g7.owner', jwks: [jwk] });
  const makeToken = ({ sub = 'google-oauth2|synthetic-owner', scope = 'g7.read',
    client_id = CLIENT, aud = RESOURCE } = {}) => {
    const header = Buffer.from(JSON.stringify({ alg: 'RS256', kid: jwk.kid, typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ iss: ISSUER, sub, aud, client_id, scope,
      iat: now, exp: now + 600 })).toString('base64url');
    const input = `${header}.${payload}`;
    return `${input}.${sign('RSA-SHA256', Buffer.from(input), auth.privateKey).toString('base64url')}`;
  };
  const active = verifier.verifyPrincipal(makeToken());
  let ownerActive = true;
  const bridgeConfig = { issuer: ISSUER, resource: RESOURCE,
    resourceMetadataUrl: 'https://g7-i8f.example.test/.well-known/oauth-protected-resource/chatgpt/mcp' };
  const calls = [];
  const ownerAuthority = { issuer: ISSUER, resource: RESOURCE,
    authorizedClientIds: [CLIENT],
    verifyReadPrincipal(token) {
      const principal = verifier.verifyPrincipal(token);
      return ownerActive && principal?.ownerDigest === active.ownerDigest ? principal : null;
    },
    isCurrentReadPrincipal(principal) {
      return ownerActive && principal.ownerDigest === active.ownerDigest &&
        principal.expiresAt > Math.floor(Date.now() / 1000);
    } };
  assert.equal(validateIsolatedChatGptBridgeConfig(bridgeConfig, ownerAuthority), true);
  assert.throws(() => validateIsolatedChatGptBridgeConfig({ ...bridgeConfig,
    resource: 'https://other.example.test/mcp' }, ownerAuthority), /Invalid isolated ChatGPT bridge/);

  const router = { callDevice: async ({ beforeDispatch, ...frame }) => {
    const permit = await beforeDispatch({ deviceId: frame.deviceId, requestId: frame.requestId, sessionId: SESSION });
    try {
      calls.push(frame);
      if (frame.arguments.path === '/approved/revoke-during-read.txt') ownerActive = false;
      return { content: [{ type: 'text', text: 'synthetic approved proof' }] };
    } finally { permit.release(); }
  } };
  const deviceRegistry = { listDevices: () => [{ deviceId: DEVICE }],
    isLiveSession: (_deviceId, sessionId) => sessionId === SESSION };
  const trustStore = { acquireDispatchPermit: () => ({ release: () => true }),
    withCurrentSession: (_context, callback) => callback({ sessionId: SESSION }) };
  const grantStore = {
    authorizeAndPermit: async ({ deviceId, fingerprint, tool, arguments: args }) => {
      if (deviceId !== DEVICE || fingerprint !== FINGERPRINT || tool !== 'read_file' ||
          !args.path.startsWith('/approved/')) throw Object.assign(Error('scope denied'), { code: 'DENIED' });
      return { grantId: GRANT, policyRevision: 1, authorization: { claims: { tool } }, release: () => true };
    },
    withCurrentAuthorization: (_context, callback) => callback(),
  };
  const handler = createChatGptReadOnlyBridge({ oauth: bridgeConfig, ownerAuthority,
    deviceRegistry, trustStore, router,
    authorizeDevice: async (owner, deviceId) => ownerIdentityDigest(owner) === active.ownerDigest && deviceId === DEVICE,
    grantStore, policySigningKey: generateKeyPairSync('ed25519').privateKey,
    getTrustRevision: () => 1,
    getDeviceApprovalReceipt: () => ({ eventId: APPROVAL, deviceId: DEVICE, fingerprint: FINGERPRINT,
      trustRevisionBefore: 0, trustRevisionAfter: 1, trustRevision: 1 }),
  });
  const server = createServer(handler);
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  t.after(() => new Promise(resolve => server.close(resolve)));
  const endpoint = `http://127.0.0.1:${server.address().port}`;
  const invoke = async (message, accessToken = makeToken()) => fetch(endpoint + CHATGPT_MCP_ROUTE, {
    method: 'POST', headers: { accept: 'application/json, text/event-stream',
      'content-type': 'application/json', 'mcp-protocol-version': '2025-11-25',
      authorization: `Bearer ${accessToken}` }, body: JSON.stringify(message),
  });
  const read = { jsonrpc: '2.0', id: 'read-1', method: 'tools/call', params: {
    name: 'read_file', arguments: { deviceId: DEVICE, path: '/approved/proof.txt' },
    _meta: { 'openai/session': 'i8f-synthetic-conversation' },
  } };
  const denial = await invoke(read, makeToken({ scope: 'profile' }));
  assert.equal(denial.status, 200);
  assert.equal((await denial.json()).result.isError, true);
  assert.equal(calls.length, 0);

  const listed = await invoke({ jsonrpc: '2.0', id: 'list', method: 'tools/list' });
  assert.deepEqual((await listed.json()).result.tools.map(tool => tool.name), ['read_file']);
  const metadataResponse = await fetch(endpoint + getChatGptResourceMetadataPath(RESOURCE));
  assert.equal(metadataResponse.status, 200);
  assert.deepEqual(await metadataResponse.json(), { resource: RESOURCE,
    authorization_servers: [ISSUER], scopes_supported: ['g7.read'], bearer_methods_supported: ['header'] });

  const success = await invoke(read);
  assert.equal(success.status, 200);
  assert.equal((await success.json()).result.content[0].text, 'synthetic approved proof');
  assert.equal(calls.length, 1);
  const escalated = await invoke({ jsonrpc: '2.0', id: 'write', method: 'tools/call', params: {
    name: 'write_file', arguments: { deviceId: DEVICE, path: '/approved/no.txt', content: 'x', mode: 'create' },
  } });
  assert.equal(escalated.status, 400);
  assert.equal(calls.length, 1);
  const revoked = await invoke({ ...read, id: 'read-revoked', params: { ...read.params,
    arguments: { deviceId: DEVICE, path: '/approved/revoke-during-read.txt' } } });
  assert.equal(revoked.status, 503);
  assert.equal((await revoked.json()).error.data.code, 'AMBIGUOUS_AUTHORIZATION_FENCE');
  assert.equal(calls.length, 2);
  const afterRevoke = await invoke({ ...read, id: 'read-after-revoke' });
  assert.equal(afterRevoke.status, 200);
  assert.equal((await afterRevoke.json()).result.isError, true);
  assert.equal(calls.length, 2);
});
