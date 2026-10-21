import { createHash, createPrivateKey, createPublicKey, randomUUID, sign, timingSafeEqual, X509Certificate } from 'node:crypto';
import { createServer as createHttpsServer } from 'node:https';
import { Readable } from 'node:stream';
import { createDurableOwnerDeviceAuthorizer } from '../dashboard/durable-owner-device-authorization.mjs';
import { createAuthenticatedMachineIngress } from '../devices/persistent-machine-ingress.mjs';
import { createMachineAccessVerifier } from '../devices/machine-access.mjs';
import { CHATGPT_MCP_ROUTE, createChatGptReadOnlyBridge, getChatGptResourceMetadataPath,
  validateIsolatedChatGptBridgeConfig } from '../chatgpt/read-only-bridge.mjs';
import { validateIsolatedG7RealmConfig } from './isolated-realm.mjs';

const AGENT_PATHS = new Set(['/agent/challenge', '/agent/connect', '/agent/heartbeat',
  '/agent/poll', '/agent/result', '/agent/cancel-ack', '/agent/disconnect']);
const CLIENT = /^[A-Za-z0-9_.-]{8,256}$/;
const HEX64 = /^[a-f0-9]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.getPrototypeOf(value) === Object.prototype && Object.keys(value).sort().join(',') === keys;
const reply = (res, status, body) => {
  if (res.writableEnded || res.destroyed) return;
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
  res.end(JSON.stringify(body));
};

function secretMatches(expected, actual) {
  if (typeof actual !== 'string') return false;
  const expectedBytes = Buffer.from(expected);
  const actualBytes = Buffer.from(actual);
  return expectedBytes.length === actualBytes.length && timingSafeEqual(expectedBytes, actualBytes);
}

function mintMachineJwt(machine, signer, clientId) {
  const now = Math.floor(Date.now() / 1000);
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', kid: machine.jwks[0].kid })).toString('base64url');
  const claims = Buffer.from(JSON.stringify({ type: 'app', sub: '', common_name: clientId,
    iss: machine.issuer, aud: machine.audience, iat: now, exp: now + 60 })).toString('base64url');
  const input = `${header}.${claims}`;
  return `${input}.${sign('RSA-SHA256', Buffer.from(input), signer).toString('base64url')}`;
}

async function readBody(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 256 * 1024) throw Object.assign(Error('Request too large'), { code: 'TOO_LARGE' });
    chunks.push(chunk);
  }
  return Buffer.concat(chunks, size);
}

// This is an explicit I8-only listener. Call it only from the isolated realm
// activation barrier; it owns and closes the realm-local router and ingress.
export async function startIsolatedG7AgentGateway({ config, realmConfig, ownerAuthority,
  trustStore, machineBindingStore, grantStore, router, policySigningKey,
  getTrustRevision, getDeviceApprovalReceipt } = {}) {
  if (!exact(config, 'chatgpt,hostname,listen,machine,tls') ||
      !exact(config.chatgpt, 'resourceMetadataUrl') ||
      typeof config.chatgpt.resourceMetadataUrl !== 'string' ||
      typeof config.hostname !== 'string' || !/^[a-z0-9.-]{6,255}$/.test(config.hostname) ||
      !config.hostname.includes('.') || config.hostname === 'localhost' || config.hostname.endsWith('.local') ||
      !exact(config.listen, 'host,port') || config.listen.host !== '127.0.0.1' ||
      !Number.isSafeInteger(config.listen.port) || config.listen.port < 1 || config.listen.port > 65535 ||
      !exact(config.tls, 'certificate,key') || !Buffer.isBuffer(config.tls.certificate) ||
      !Buffer.isBuffer(config.tls.key) || !exact(config.machine,
        'audience,clients,issuer,jwks,signingKey') ||
      typeof config.machine.audience !== 'string' || !HEX64.test(config.machine.audience) ||
      !Array.isArray(config.machine.jwks) || config.machine.jwks.length !== 1 ||
      !Array.isArray(config.machine.clients) || config.machine.clients.length < 1 ||
      config.machine.clients.length > 64 || config.machine.clients.some(client =>
        !exact(client, 'clientId,serviceSecret') || !CLIENT.test(client.clientId ?? '') ||
        typeof client.serviceSecret !== 'string' || client.serviceSecret.length < 24 ||
        /[\r\n\0]/.test(client.serviceSecret)) ||
      new Set(config.machine.clients.map(client => client.clientId)).size !== config.machine.clients.length ||
      new Set(config.machine.clients.map(client => client.serviceSecret)).size !== config.machine.clients.length ||
      !ownerAuthority || ownerAuthority.realmId !== realmConfig?.realmId ||
      typeof ownerAuthority.verifyReadPrincipal !== 'function' ||
      typeof ownerAuthority.isCurrentReadPrincipal !== 'function' ||
      !trustStore?.registry || typeof trustStore.revision !== 'function' ||
      !machineBindingStore || typeof machineBindingStore.resolve !== 'function' ||
      !grantStore || typeof grantStore.authorizeAndPermit !== 'function' ||
      typeof grantStore.withCurrentAuthorization !== 'function' || !router ||
      typeof router.callDevice !== 'function' || typeof router.close !== 'function' ||
      typeof getTrustRevision !== 'function' || typeof getDeviceApprovalReceipt !== 'function') {
    throw new TypeError('Invalid isolated G7 agent Gateway configuration');
  }

  const realm = validateIsolatedG7RealmConfig(realmConfig, { requireExisting: true });
  const chatgptOAuth = Object.freeze({issuer:ownerAuthority.issuer,resource:ownerAuthority.resource,
    resourceMetadataUrl:config.chatgpt.resourceMetadataUrl});
  validateIsolatedChatGptBridgeConfig(chatgptOAuth,ownerAuthority);
  if (config.listen.host !== realm.listen.host || config.listen.port !== realm.listen.port) {
    throw Object.assign(new Error('Isolated Gateway listener must match the realm configuration'), {
      code: 'REALM_LISTENER_MISMATCH',
    });
  }
  if (ownerAuthority.directory !== realm.paths.ownerAuthorityDirectory ||
      trustStore.directory !== realm.paths.trustDirectory ||
      machineBindingStore.directory !== realm.paths.bindingDirectory ||
      grantStore.directory !== realm.paths.grantDirectory) {
    throw new Error('Isolated Gateway stores do not belong to the selected realm');
  }

  const certificate = new X509Certificate(config.tls.certificate);
  const tlsKey = createPrivateKey(config.tls.key);
  if (!certificate.checkHost(config.hostname) || tlsKey.asymmetricKeyType !== 'rsa' ||
      !createPublicKey(tlsKey).export({ type: 'spki', format: 'der' }).equals(
        certificate.publicKey.export({ type: 'spki', format: 'der' }))) {
    throw new Error('Isolated Gateway TLS certificate does not match its private key and hostname');
  }

  const machine = config.machine;
  const machineSigner = machine.signingKey?.type === 'private'
    ? machine.signingKey : createPrivateKey(machine.signingKey);
  const machinePublic = createPublicKey(machineSigner).export({ format: 'jwk' });
  const machineJwk = machine.jwks[0];
  if (machineSigner.asymmetricKeyType !== 'rsa' || !machineJwk || machineJwk.kty !== 'RSA' ||
      machineJwk.alg !== 'RS256' || typeof machineJwk.kid !== 'string' ||
      machineJwk.n !== machinePublic.n || machineJwk.e !== machinePublic.e || 'd' in machineJwk) {
    throw new Error('Isolated Gateway machine signing key does not match its public verifier key');
  }
  const policyPrivateKey = policySigningKey?.type === 'private'
    ? policySigningKey : createPrivateKey(policySigningKey);
  if (policyPrivateKey.asymmetricKeyType !== 'ed25519' ||
      realmConfig.protectedKeyFingerprints.includes(createHash('sha256')
        .update(createPublicKey(policyPrivateKey).export({ type: 'spki', format: 'der' })).digest('hex'))) {
    throw new Error('Isolated Gateway policy key is invalid or reused from a protected realm');
  }

  const verifyMachineToken = createMachineAccessVerifier({ issuer: machine.issuer,
    audience: machine.audience, allowedClientIds: machine.clients.map(client => client.clientId),
    keyProvider: async () => ({ keys: machine.jwks }) });
  const machineIngress = createAuthenticatedMachineIngress({ registry: trustStore.registry,
    router, verifyMachineToken, machineBindingStore, getTrustRevision,
    shouldCancelOperation: frame => {
      const claims = frame?.authorization?.claims;
      if (!claims || claims.deviceId !== frame.deviceId || claims.requestId !== frame.requestId) return false;
      try {
        return grantStore.withCurrentAuthorization({ grantId: claims.grantId,
          ownerDigest: claims.ownerDigest, deviceId: claims.deviceId, fingerprint: claims.fingerprint,
          tool: claims.tool, policyRevision: claims.policyRevision }, () =>
          trustStore.registry.isLiveSession(frame.deviceId, frame.sessionId)) === true;
      } catch { return false; }
    } });
  const authorizeDevice = createDurableOwnerDeviceAuthorizer({
    auditDirectory: realm.paths.auditDirectory, trustDirectory: realm.paths.trustDirectory });
  const mcpHandler = createChatGptReadOnlyBridge({oauth:chatgptOAuth,ownerAuthority,
    deviceRegistry: trustStore.registry, trustStore, router, authorizeDevice,
    grantStore, policySigningKey: policyPrivateKey, getTrustRevision,
    getDeviceApprovalReceipt,
  });
  const resourceMetadataPath=getChatGptResourceMetadataPath(chatgptOAuth.resource);

  const handle = async (req, res) => {
    if (req.url === resourceMetadataPath || req.url === CHATGPT_MCP_ROUTE || !AGENT_PATHS.has(req.url)) {
      if (req.url !== resourceMetadataPath && (req.headers['cf-access-jwt-assertion'] ||
          req.headers['x-vpsc-owner-id'] || req.headers['x-vpsc-owner-digest'])) {
        return reply(res, 403, { error: 'Unsupported Owner identity header' });
      }
      return mcpHandler(req, res);
    }
    if (!AGENT_PATHS.has(req.url)) return reply(res, 404, { error: 'Not found' });
    if (req.method !== 'POST' || req.headers.origin || req.headers.cookie ||
        req.headers.authorization || req.headers['cf-access-jwt-assertion'] ||
        !/^application\/json(?:;|$)/i.test(req.headers['content-type'] ?? '')) {
      return reply(res, 403, { error: 'Machine authentication required' });
    }
    const machineClient = machine.clients.find(client =>
      client.clientId === req.headers['cf-access-client-id']);
    if (!machineClient || !secretMatches(machineClient.serviceSecret,
      req.headers['cf-access-client-secret'])) return reply(res, 403, { error: 'Machine credential denied' });
    let body;
    try { body = await readBody(req); }
    catch (error) { return reply(res, error?.code === 'TOO_LARGE' ? 413 : 400, { error: 'Invalid request body' }); }
    const headers = { 'content-type': 'application/json',
      'cf-access-jwt-assertion': mintMachineJwt(machine, machineSigner, machineClient.clientId) };
    for (const name of ['x-vpsc-device-id', 'x-vpsc-session-id', 'x-vpsc-sequence', 'x-vpsc-signature']) {
      if (typeof req.headers[name] === 'string') headers[name] = req.headers[name];
    }
    const machineRequest = Readable.from([body]);
    machineRequest.url = req.url;
    machineRequest.method = req.method;
    machineRequest.headers = headers;
    return machineIngress.handle(machineRequest, res);
  };

  const server = createHttpsServer({ key: config.tls.key, cert: config.tls.certificate }, handle);
  server.requestTimeout = 15_000;
  server.headersTimeout = 10_000;
  server.maxHeadersCount = 64;
  try {
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(config.listen.port, '127.0.0.1', resolve);
    });
  } catch (error) {
    router.close();
    await machineIngress.close().catch(() => {});
    throw error;
  }
  return Object.freeze({ realmId: realm.realmId, hostname: config.hostname,
    host: '127.0.0.1', port: server.address().port, tools: Object.freeze(['read_file']),
    close: async () => {
      server.closeAllConnections?.();
      if (server.listening) await new Promise(resolve => server.close(resolve));
      router.close();
      await machineIngress.close();
    } });
}
