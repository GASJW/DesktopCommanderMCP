import { createHash, createPublicKey } from 'node:crypto';
import { lstatSync, realpathSync } from 'node:fs';
import path from 'node:path';

const ROOT_KEYS = 'controlIdentity,listen,paths,protectedKeyFingerprints,protectedPaths,realmId,version';
const PATH_KEYS = 'auditDirectory,bindingDirectory,configFile,grantDirectory,ledgerDirectory,ownerAuthorityDirectory,policyDirectory,provisioningDirectory,runtimeDirectory,storageRoot,trustDirectory';
const DIRECTORY_KEYS = ['auditDirectory','bindingDirectory','grantDirectory','ledgerDirectory',
  'ownerAuthorityDirectory','policyDirectory','provisioningDirectory','runtimeDirectory','trustDirectory'];
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-4[0-9a-f]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const HEX64 = /^[a-f0-9]{64}$/;
const KEY_ID = /^[A-Za-z0-9_.-]{1,128}$/;

function exact(value, keys) {
  return value && typeof value === 'object' && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype &&
    Object.keys(value).sort().join(',') === keys;
}

function normalizedAbsolute(value) {
  return typeof value === 'string' && path.isAbsolute(value) && path.normalize(value) === value;
}

function canonicalPath(value, { mustExist = false, expectedType } = {}) {
  if (!normalizedAbsolute(value)) throw new TypeError('Realm paths must be normalized absolute paths');
  const root = path.parse(value).root;
  const parts = value.slice(root.length).split(path.sep).filter(Boolean);
  let current = root;
  let missing = false;
  let lastExisting = root;
  const missingParts = [];
  let stat = null;
  for (let index = 0; index < parts.length; index += 1) {
    current = path.join(current, parts[index]);
    if (missing) {
      missingParts.push(parts[index]);
      continue;
    }
    try {
      const linkStat = lstatSync(current);
      if (linkStat.isSymbolicLink()) throw new Error('Realm paths cannot use symlinks or reparse points');
      if (index < parts.length - 1 && !linkStat.isDirectory()) {
        throw new Error('Realm path ancestor is not a directory');
      }
      lastExisting = current;
      if (index === parts.length - 1) stat = linkStat;
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
      missing = true;
      missingParts.push(parts[index]);
    }
  }
  if (missing && mustExist) throw new Error('Realm path is missing');
  const realExisting = realpathSync.native(lastExisting);
  const canonical = path.normalize(missing
    ? path.join(realExisting, ...missingParts) : realExisting);
  if (!missing && expectedType === 'directory' && !stat?.isDirectory()) {
    throw new Error('Realm directory path is not a directory');
  }
  if (!missing && expectedType === 'file' && !stat?.isFile()) {
    throw new Error('Realm configuration path is not a regular file');
  }
  const identity = !missing && stat
    ? `${stat.dev}:${stat.ino}` : null;
  return Object.freeze({ input: value, canonical, exists: !missing, identity, stat });
}

function windowsNormalized(value) {
  const normalized = path.normalize(value);
  return process.platform === 'win32' ? normalized.toLowerCase() : normalized;
}

function overlaps(left, right) {
  const a = windowsNormalized(left.canonical);
  const b = windowsNormalized(right.canonical);
  const contains = (parent, child) => {
    const relative = path.relative(parent, child);
    return relative === '' || relative !== '..' && !relative.startsWith(`..${path.sep}`) &&
      !path.isAbsolute(relative);
  };
  return contains(a, b) || contains(b, a) ||
    !!left.identity && left.identity === right.identity;
}

function underRoot(root, candidate) {
  const relative = path.relative(windowsNormalized(root.canonical),
    windowsNormalized(candidate.canonical));
  return relative !== '' && relative !== '..' && !relative.startsWith(`..${path.sep}`) &&
    !path.isAbsolute(relative);
}

async function closeListener(listener) {
  if (typeof listener?.close !== 'function') throw new Error('Loopback listener must be closeable');
  if (listener.close.length === 0) return listener.close();
  return new Promise((resolve, reject) => listener.close(error => error ? reject(error) : resolve()));
}

function controlKeyFingerprint(pem) {
  if (typeof pem !== 'string' || pem.length > 8192 || /PRIVATE KEY/.test(pem)) {
    throw new TypeError('Isolated realm requires an Ed25519 public control key');
  }
  let key;
  try { key = createPublicKey(pem); } catch { throw new TypeError('Invalid isolated realm control key'); }
  if (key.asymmetricKeyType !== 'ed25519') throw new TypeError('Isolated realm control key must be Ed25519');
  return createHash('sha256').update(key.export({ type: 'spki', format: 'der' })).digest('hex');
}

export function validateIsolatedG7RealmConfig(config, { requireExisting = false } = {}) {
  if (!exact(config, ROOT_KEYS) || config.version !== 1 || !UUID.test(config.realmId ?? '') ||
      !exact(config.listen, 'host,port') || config.listen.host !== '127.0.0.1' ||
      !Number.isSafeInteger(config.listen.port) || config.listen.port < 1 || config.listen.port > 65535 ||
      !exact(config.paths, PATH_KEYS) || !Array.isArray(config.protectedPaths) ||
      config.protectedPaths.length < 1 || config.protectedPaths.length > 32 ||
      !Array.isArray(config.protectedKeyFingerprints) || config.protectedKeyFingerprints.length > 32 ||
      config.protectedKeyFingerprints.some(value => !HEX64.test(value)) ||
      new Set(config.protectedKeyFingerprints).size !== config.protectedKeyFingerprints.length ||
      !exact(config.controlIdentity, 'algorithm,fingerprint,keyId,publicKeyPem') ||
      config.controlIdentity.algorithm !== 'Ed25519' || !KEY_ID.test(config.controlIdentity.keyId ?? '')) {
    throw new TypeError('Invalid isolated G7 realm configuration');
  }
  const root = canonicalPath(config.paths.storageRoot, { mustExist: requireExisting,
    expectedType: requireExisting ? 'directory' : undefined });
  const newPaths = new Map();
  for (const key of DIRECTORY_KEYS) {
    const item = canonicalPath(config.paths[key], { mustExist: requireExisting,
      expectedType: requireExisting ? 'directory' : undefined });
    if (!underRoot(root, item)) throw new Error('Isolated realm stores must remain under their storage root');
    newPaths.set(key, item);
  }
  const configPath = canonicalPath(config.paths.configFile, { mustExist: requireExisting,
    expectedType: requireExisting ? 'file' : undefined });
  if (!underRoot(root, configPath)) throw new Error('Isolated realm configuration must remain under its storage root');
  newPaths.set('configFile', configPath);

  const pathEntries = Array.from(newPaths.entries());
  for (let i = 0; i < pathEntries.length; i += 1) {
    for (let j = i + 1; j < pathEntries.length; j += 1) {
      if (overlaps(pathEntries[i][1], pathEntries[j][1])) {
        throw new Error('Isolated realm store paths overlap or share an underlying directory');
      }
    }
  }

  const protectedPaths = config.protectedPaths.map(value =>
    canonicalPath(value, { mustExist: true, expectedType: 'directory' }));
  for (const protectedPath of protectedPaths) {
    if (overlaps(root, protectedPath)) throw new Error('Isolated realm overlaps an existing G7 realm');
    for (const [, newPath] of pathEntries) {
      if (overlaps(newPath, protectedPath)) throw new Error('Isolated realm store aliases an existing G7 path');
    }
  }

  const fingerprint = controlKeyFingerprint(config.controlIdentity.publicKeyPem);
  if (fingerprint !== config.controlIdentity.fingerprint ||
      config.protectedKeyFingerprints.includes(fingerprint)) {
    throw new Error('Isolated realm control identity is invalid or reused');
  }
  return Object.freeze({ realmId: config.realmId.toLowerCase(),
    listen: Object.freeze({ host: '127.0.0.1', port: config.listen.port }),
    root: root.canonical,
    paths: Object.freeze(Object.fromEntries([...pathEntries]
      .map(([key, value]) => [key, value.canonical]))),
    controlKeyFingerprint: fingerprint,
    protectedPaths: Object.freeze(protectedPaths.map(value => value.canonical)) });
}

export function createIsolatedG7Realm({ config, ownerAuthority, storeInspectors,
  startLoopback } = {}) {
  const prepared = validateIsolatedG7RealmConfig(config);
  if (ownerAuthority?.realmId !== prepared.realmId ||
      typeof ownerAuthority?.inspect !== 'function' ||
      typeof ownerAuthority?.verifyReadPrincipal !== 'function' ||
      typeof ownerAuthority?.verifyAdminPrincipal !== 'function' ||
      !storeInspectors || typeof storeInspectors !== 'object' ||
      typeof startLoopback !== 'function') {
    throw new TypeError('Isolated realm authority, store inspectors and loopback starter are required');
  }
  if (path.resolve(ownerAuthority.directory) !== path.resolve(config.paths.ownerAuthorityDirectory)) {
    throw new Error('Owner authority is outside the isolated realm state root');
  }
  const requiredStores = ['audit', 'binding', 'grant', 'ledger', 'policy', 'provisioning', 'trust'];
  if (requiredStores.some(name => typeof storeInspectors[name] !== 'function')) {
    throw new TypeError('Every isolated realm store must have a read-only health inspector');
  }
  let started = null;

  function inspectActivation() {
    const blockers = [];
    let paths;
    try { paths = validateIsolatedG7RealmConfig(config, { requireExisting: true }); }
    catch { blockers.push('REALM_PATHS_UNSAFE'); }
    let owner;
    try { owner = ownerAuthority.inspect(); }
    catch { blockers.push('OWNER_AUTHORITY_UNAVAILABLE'); }
    if (owner && (owner.status !== 'active' || owner.pendingCount !== 0 ||
        owner.lockPresent || owner.healthy !== true)) blockers.push('OWNER_NOT_ACTIVE_OR_RECOVERED');
    const stores = {};
    for (const name of requiredStores) {
      try {
        const state = storeInspectors[name]();
        if (!state || state.healthy !== true || state.pending !== 0 ||
            !Number.isSafeInteger(state.revision) || state.revision < 0) {
          blockers.push(`${name.toUpperCase()}_STORE_NOT_READY`);
        }
        stores[name] = state;
      } catch { blockers.push(`${name.toUpperCase()}_STORE_UNAVAILABLE`); }
    }
    if (!Number.isSafeInteger(stores.provisioning?.readyDeviceCount) ||
        stores.provisioning.readyDeviceCount < 1) blockers.push('NO_APPROVED_READ_ONLY_DEVICE');
    return Object.freeze({ ready: blockers.length === 0,
      blockers: Object.freeze(blockers), realmId: prepared.realmId,
      ownerId: owner?.owner?.ownerId ?? null,
      revisions: Object.freeze(Object.fromEntries(Object.entries(stores)
        .filter(([, value]) => Number.isSafeInteger(value?.revision))
        .map(([name, value]) => [name, value.revision]))),
      listener: prepared.listen, paths: paths?.paths ?? null });
  }

  return Object.freeze({
    inspectActivation,
    async activate() {
      if (started) return started;
      const readiness = inspectActivation();
      if (!readiness.ready) {
        throw Object.assign(new Error('Isolated realm activation barrier is closed'), {
          code: 'REALM_ACTIVATION_BLOCKED', blockers: readiness.blockers,
        });
      }
      const server = await startLoopback(Object.freeze({
        realmId: prepared.realmId,
        host: '127.0.0.1',
        port: prepared.listen.port,
        tools: Object.freeze(['read_file']),
        ownerAuthority,
        paths: prepared.paths,
      }));
      if (typeof server?.close !== 'function') {
        throw Object.assign(new Error('Loopback listener must expose close()'), {
          code: 'REALM_LISTENER_CONTROL_REQUIRED',
        });
      }
      const afterStart = inspectActivation();
      if (!afterStart.ready) {
        await closeListener(server);
        throw Object.assign(new Error('Isolated G7 realm changed during listener activation'), {
          code: 'REALM_ACTIVATION_BLOCKED', blockers: afterStart.blockers,
        });
      }
      started = server;
      return server;
    },
  });
}
