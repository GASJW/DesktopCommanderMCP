import { createHash, createPublicKey, verify as verifySignature } from 'node:crypto';
import path from 'node:path';
import { lstatSync } from 'node:fs';
import {
  appendRecoveredOwnerOutcome, createDurableOwnerAudit,
  inspectDurableOwnerAudit, releaseOwnerAuditLockForReconciliation,
} from '../dashboard/durable-owner-audit.mjs';
import { createDurableProcessLock, inspectDurableProcessLock,
  removeDeadDurableProcessLock, removeOwnedDurableProcessLock }
  from '../common/durable-process-lock.mjs';
import { createAuth0OwnerIdentityReference, isAuth0OwnerPrincipal } from './auth0-owner-auth.mjs';

const WRITER_LOCK = '.owner-decisions-writer.lock';
const RECOVERY_LOCK = '.owner-pairing-reconciliation.lock';
const DOMAIN = 'VPSC-I8F-OWNER-AUTHORITY-v1\n';
const HEX24 = /^[a-f0-9]{24}$/;
const HEX64 = /^[a-f0-9]{64}$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const KEY_ID = /^[A-Za-z0-9_.-]{1,128}$/;
const CLIENT_ID = /^[A-Za-z0-9_.-]{8,256}$/;
const APPROVAL_KEYS = 'eventId,expectedRevision,expiresAt,issuedAt,keyId,operation,ownerDigest,realmId,signature,targetDigest,version';
const MAX_APPROVAL_AGE_SECONDS = 300;
const ZERO_DIGEST = '0'.repeat(64);

function exact(value, keys) {
  return value && typeof value === 'object' && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype &&
    Object.keys(value).sort().join(',') === keys;
}

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort()
    .map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function validIssuer(value) {
  if (typeof value !== 'string' || value.length > 2048) return false;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && !url.username && !url.password &&
      !url.search && !url.hash && url.href === value && value.endsWith('/');
  } catch { return false; }
}

function validResource(value) {
  if (typeof value !== 'string' || value.length > 2048) return false;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && !url.username && !url.password &&
      !url.search && !url.hash && url.href === value;
  } catch { return false; }
}

function privateDirectory(directory) {
  if (process.platform !== 'linux' || typeof process.getuid !== 'function' ||
      process.getuid() === 0 || typeof directory !== 'string' ||
      !path.isAbsolute(directory) || path.normalize(directory) !== directory || directory === '/') {
    throw new Error('Owner authority storage requires a private nonroot Linux directory');
  }
  let current = path.parse(directory).root;
  for (const part of directory.slice(current.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    const st = lstatSync(current);
    if (st.isSymbolicLink() || !st.isDirectory()) throw new Error('Unsafe Owner authority path');
  }
  const st = lstatSync(directory);
  if (st.uid !== process.getuid() || (st.mode & 0o7777) !== 0o700) {
    throw new Error('Owner authority directory must be owned by its nonroot service user with mode 0700');
  }
}

function publicApprovalKeys(jwks) {
  if (!Array.isArray(jwks) || jwks.length < 1 || jwks.length > 8) {
    throw new TypeError('Owner approval keys are required');
  }
  const keys = new Map();
  for (const jwk of jwks) {
    if (!jwk || jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' ||
        typeof jwk.kid !== 'string' || !KEY_ID.test(jwk.kid) ||
        typeof jwk.x !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(jwk.x) ||
        ['d', 'y'].some(key => Object.hasOwn(jwk, key)) || keys.has(jwk.kid)) {
      throw new TypeError('Owner approval keys must be unique public Ed25519 JWKs');
    }
    let key;
    try { key = createPublicKey({ key: jwk, format: 'jwk' }); }
    catch { throw new TypeError('Invalid Owner approval key'); }
    if (key.asymmetricKeyType !== 'ed25519') throw new TypeError('Owner approval key must be Ed25519');
    keys.set(jwk.kid, key);
  }
  return keys;
}

function approvalFields(approval) {
  if (!exact(approval, APPROVAL_KEYS) || approval.version !== 1 ||
      !UUID.test(approval.eventId ?? '') || !Number.isSafeInteger(approval.expectedRevision) ||
      approval.expectedRevision < 0 || !Number.isSafeInteger(approval.issuedAt) ||
      !Number.isSafeInteger(approval.expiresAt) || approval.expiresAt <= approval.issuedAt ||
      approval.expiresAt - approval.issuedAt > MAX_APPROVAL_AGE_SECONDS ||
      !KEY_ID.test(approval.keyId ?? '') ||
      !['bootstrap', 'revoke', 'owner.recover'].includes(approval.operation) ||
      !HEX64.test(approval.ownerDigest ?? '') || !UUID.test(approval.realmId ?? '') ||
      typeof approval.signature !== 'string' || !/^[A-Za-z0-9_-]{86}$/.test(approval.signature) ||
      !HEX64.test(approval.targetDigest ?? '')) {
    throw new TypeError('Invalid Owner approval envelope');
  }
  return { version: 1, realmId: approval.realmId.toLowerCase(),
    eventId: approval.eventId.toLowerCase(), operation: approval.operation,
    expectedRevision: approval.expectedRevision, ownerDigest: approval.ownerDigest,
    targetDigest: approval.targetDigest, issuedAt: approval.issuedAt,
    expiresAt: approval.expiresAt, keyId: approval.keyId };
}

function approvalRecord(approval) {
  return { ...approvalFields(approval), signature: approval.signature };
}

export function ownerAuthorityApprovalSigningBytes(approval) {
  const fields = approvalFields(approval);
  return Buffer.from(DOMAIN + canonical(fields), 'utf8');
}

export function ownerAuthorityTargetDigest(operation, target) {
  if (typeof operation !== 'string' || !/^[a-z][a-z0-9_.-]{0,63}$/.test(operation)) {
    throw new TypeError('Invalid Owner approval operation');
  }
  return sha256(DOMAIN + canonical({ operation, target }));
}

export function ownerAuthorityRecoveryTargetDigest(evidence) {
  if (!evidence || !Number.isSafeInteger(evidence.sequence) ||
      !HEX64.test(evidence.hash ?? '') || !HEX64.test(evidence.lockDigest ?? ZERO_DIGEST) ||
      !HEX64.test(evidence.recoveryLockDigest ?? ZERO_DIGEST) ||
      !(evidence.pendingEventId === null || UUID.test(evidence.pendingEventId))) {
    throw new TypeError('Invalid Owner recovery evidence');
  }
  return ownerAuthorityTargetDigest('owner.recover', {
    sequence: evidence.sequence,
    hash: evidence.hash,
    pendingEventId: evidence.pendingEventId,
    lockDigest: evidence.lockDigest ?? ZERO_DIGEST,
    recoveryLockDigest: evidence.recoveryLockDigest ?? ZERO_DIGEST,
  });
}

function auth0ReferenceFromState(state) {
  if (state.status !== 'active' || !state.ownerIssuer || !state.ownerId || !state.ownerDigest) return null;
  return createAuth0OwnerIdentityReference({ issuer: state.ownerIssuer,
    ownerId: state.ownerId, ownerDigest: state.ownerDigest });
}

export function createDurableOwnerAuthority({
  directory, realmId, issuer, verifier, approvalJwks, now = Date.now, testHooks,
} = {}) {
  if (!UUID.test(realmId ?? '') || !validIssuer(issuer) ||
      typeof verifier?.verifyPrincipal !== 'function' ||
      typeof verifier?.verifyAdminPrincipal !== 'function' || typeof now !== 'function') {
    throw new TypeError('Invalid isolated Owner authority configuration');
  }
  if (verifier.issuer !== issuer || !validIssuer(verifier.issuer) ||
      !validResource(verifier.resource) ||
      verifier.readScope !== 'g7.read' || verifier.ownerScope !== 'g7.owner' ||
      !Array.isArray(verifier.authorizedClientIds) || verifier.authorizedClientIds.length === 0) {
    throw new TypeError('Owner authority requires the strict Auth0 access-token verifier');
  }
  if (testHooks !== undefined && (!process.env.NODE_TEST_CONTEXT ||
      typeof testHooks?.afterDurableWrite !== 'function')) {
    throw new TypeError('Owner authority failure hooks are test-only');
  }
  const keys = publicApprovalKeys(approvalJwks);
  const approvalKeyIds = new Set(keys.keys());

  function inspect() {
    privateDirectory(directory);
    const evidence = inspectDurableOwnerAudit({ directory, includeOwnerAuthority: true });
    const authorityEvents = evidence.events.filter(event => event.event === 'g7_owner_authority');
    const otherEvents = evidence.events.some(event => event.event !== 'g7_owner_authority');
    const ownerAuthority = evidence.ownerAuthority ?? {
      revision: 0, status: 'empty', ownerIssuer: null, ownerId: null, ownerDigest: null,
    };
    return Object.freeze({
      realmId,
      sequence: evidence.sequence,
      hash: evidence.hash,
      revision: ownerAuthority.revision,
      status: ownerAuthority.status,
      owner: auth0ReferenceFromState(ownerAuthority),
      pending: Object.freeze(evidence.pending.filter(event => event.event === 'g7_owner_authority')),
      pendingCount: evidence.pending.length,
      lockPresent: evidence.lockPresent,
      lockStatus: evidence.lockStatus,
      lockDigest: evidence.lockDigest ?? null,
      healthy: !otherEvents && evidence.pending.length === 0 && !evidence.lockPresent,
      events: Object.freeze(authorityEvents),
    });
  }

  function verifyApproval(approval, { operation, eventId, expectedRevision,
    ownerDigest, targetDigest, at = Math.floor(now() / 1000) } = {}) {
    let fields;
    try { fields = approvalFields(approval); } catch { return false; }
    if (fields.realmId !== realmId || fields.operation !== operation ||
        fields.eventId !== eventId.toLowerCase() || fields.expectedRevision !== expectedRevision ||
        fields.ownerDigest !== ownerDigest || fields.targetDigest !== targetDigest ||
        !approvalKeyIds.has(fields.keyId) || !Number.isSafeInteger(at) ||
        fields.issuedAt > at + 30 || fields.expiresAt < at) return false;
    const key = keys.get(fields.keyId);
    const signature = Buffer.from(approval.signature, 'base64url');
    return signature.length === 64 && signature.toString('base64url') === approval.signature &&
      verifySignature(null, ownerAuthorityApprovalSigningBytes(approval), key, signature);
  }

  function requireState() {
    const state = inspect();
    if (!state.healthy) throw Object.assign(new Error('Owner authority requires recovery'), {
      code: 'OWNER_AUTHORITY_RECOVERY_REQUIRED',
    });
    return state;
  }

  function commit(operation, principal, approval) {
    const before = requireState();
    if (!isAuth0OwnerPrincipal(principal) || principal.issuer !== issuer || !HEX64.test(principal.ownerDigest ?? '') ||
        principal.ownerId !== principal.ownerDigest.slice(0, 24)) {
      throw Object.assign(new Error('Auth0 Owner identity is invalid'), { code: 'OWNER_AUTH_REQUIRED' });
    }
    const eventId = approval?.eventId;
    const targetDigest = ownerAuthorityTargetDigest(operation, {
      issuer: principal.issuer,
      ownerDigest: principal.ownerDigest,
    });
    const duplicate = typeof eventId === 'string'
      ? before.events.find(event => event.eventId === eventId.toLowerCase()) : undefined;
    if (duplicate) {
      const outcome = before.events.find(event => event.eventId === duplicate.eventId && event.phase === 'outcome');
      if (outcome && duplicate.operation === operation && duplicate.ownerDigest === principal.ownerDigest &&
          duplicate.ownerIssuer === principal.issuer &&
          verifyApproval(approval, { operation, eventId,
            expectedRevision: duplicate.expectedRevision,
            ownerDigest: principal.ownerDigest, targetDigest }) &&
          canonical(duplicate.approval) === canonical(approvalRecord(approval))) {
        return Object.freeze({ ...requireState(), alreadyApplied: true });
      }
      throw Object.assign(new Error('Owner transition eventId conflict'), { code: 'EVENT_ID_CONFLICT' });
    }
    if (!verifyApproval(approval, { operation, eventId,
      expectedRevision: before.revision, ownerDigest: principal.ownerDigest, targetDigest })) {
      throw Object.assign(new Error('Independent Owner approval is required'), {
        code: 'OWNER_APPROVAL_REQUIRED',
      });
    }

    if (operation === 'bootstrap' && (before.status !== 'empty' || before.revision !== 0)) {
      throw Object.assign(new Error('Isolated Owner is already initialized'), { code: 'REVISION_CONFLICT' });
    }
    if (operation === 'revoke' && (before.status !== 'active' ||
        before.owner?.ownerDigest !== principal.ownerDigest)) {
      throw Object.assign(new Error('Only the active Owner can revoke this realm'), { code: 'OWNER_AUTH_REQUIRED' });
    }

    const at = new Date(now()).toISOString();
    const actorScope = operation === 'bootstrap' ? 'g7.read' : 'g7.owner';
    const intent = {
      event: 'g7_owner_authority', version: 1, at, eventId: eventId.toLowerCase(),
      operation, ownerId: principal.ownerId, ownerDigest: principal.ownerDigest,
      ownerIssuer: principal.issuer, actorClientId: principal.clientId,
      actorKeyId: principal.keyId, actorScope, expectedRevision: before.revision,
      approval: approvalRecord(approval), phase: 'intent',
    };
    const audit = createDurableOwnerAudit({ directory });
    let closed = false;
    try {
      if (testHooks) testHooks.afterDurableWrite('after-lock');
      if (inspectDurableOwnerAudit({ directory, includeOwnerAuthority: true })
          .ownerAuthority.revision !== before.revision) {
        throw Object.assign(new Error('Owner authority changed during transition'), { code: 'REVISION_CONFLICT' });
      }
      audit.auditWrite(intent);
      if (testHooks) testHooks.afterDurableWrite('after-intent');
      audit.auditWrite({ ...intent, at: new Date(now()).toISOString(), phase: 'outcome',
        outcome: 'accepted', revisionAfter: before.revision + 1, recoveryApproval: null });
      if (testHooks) testHooks.afterDurableWrite('after-outcome');
      audit.close();
      closed = true;
      return Object.freeze(requireState());
    } finally {
      if (!closed) {
        try { audit.close(); } catch { /* preserve uncertain writer evidence */ }
      }
    }
  }

  function bootstrap({ accessToken, approval } = {}) {
    const principal = verifier.verifyPrincipal(accessToken);
    if (!principal) throw Object.assign(new Error('A verified Auth0 g7.read token is required'), {
      code: 'OWNER_AUTH_REQUIRED',
    });
    return commit('bootstrap', principal, approval);
  }

  function revoke({ accessToken, approval } = {}) {
    const principal = verifier.verifyAdminPrincipal(accessToken);
    if (!principal) throw Object.assign(new Error('A verified Auth0 g7.owner token is required'), {
      code: 'OWNER_ADMIN_AUTH_REQUIRED',
    });
    return commit('revoke', principal, approval);
  }

  function recover({ approval, operatorConfirmedNoActiveWriters } = {}) {
    if (operatorConfirmedNoActiveWriters !== true) {
      throw Object.assign(new Error('Explicit operator quiescence confirmation is required'), {
        code: 'OPERATOR_REQUIRED',
      });
    }
    privateDirectory(directory);
    const before = inspectDurableOwnerAudit({ directory, includeOwnerAuthority: true });
    const recoveryLock = inspectDurableProcessLock(directory, RECOVERY_LOCK);
    const writerLock = inspectDurableProcessLock(directory, WRITER_LOCK);
    const pending = before.pending[0] ?? null;
    const ownerDigest = pending?.ownerDigest ?? before.ownerAuthority.ownerDigest ?? ZERO_DIGEST;
    const targetDigest = ownerAuthorityRecoveryTargetDigest({
      sequence: before.sequence,
      hash: before.hash,
      pendingEventId: pending?.eventId ?? null,
      lockDigest: writerLock.digest ?? ZERO_DIGEST,
      recoveryLockDigest: recoveryLock.digest ?? ZERO_DIGEST,
    });
    if (!approval || !verifyApproval(approval, { operation: 'owner.recover',
        eventId: approval.eventId, expectedRevision: before.ownerAuthority.revision,
        ownerDigest, targetDigest })) {
      throw Object.assign(new Error('Signed Owner recovery approval is required'), {
        code: 'OWNER_RECOVERY_APPROVAL_REQUIRED',
      });
    }
    if (writerLock.present && writerLock.status !== 'dead' ||
        recoveryLock.present && recoveryLock.status !== 'dead') {
      throw Object.assign(new Error('Owner authority writer is active or cannot be verified'), {
        code: 'OWNER_AUTHORITY_BUSY',
      });
    }
    if (recoveryLock.present) {
      removeDeadDurableProcessLock({ directory, name: RECOVERY_LOCK,
        expectedDigest: recoveryLock.digest });
    }
    const owner = createDurableProcessLock(directory, RECOVERY_LOCK, 'reconciliation');
    try {
      const current = inspectDurableOwnerAudit({ directory, includeOwnerAuthority: true });
      const currentWriter = inspectDurableProcessLock(directory, WRITER_LOCK);
      if (current.sequence !== before.sequence || current.hash !== before.hash ||
          currentWriter.digest !== writerLock.digest ||
          current.pending.length !== before.pending.length) {
        throw Object.assign(new Error('Owner authority evidence changed during recovery'), {
          code: 'OWNER_AUTHORITY_CONFLICT',
        });
      }
      if (pending) {
        if (pending.event !== 'g7_owner_authority' || current.pending.length !== 1) {
          throw Object.assign(new Error('Unrecognized pending Owner audit event'), {
            code: 'OWNER_AUTHORITY_CORRUPT',
          });
        }
        const approvedAt = Date.parse(pending.at);
        const signedApproval = pending.approval;
        if (!verifyApproval(signedApproval, { operation: pending.operation,
            eventId: pending.eventId, expectedRevision: pending.expectedRevision,
            ownerDigest: pending.ownerDigest,
            targetDigest: ownerAuthorityTargetDigest(pending.operation, {
              issuer: pending.ownerIssuer, ownerDigest: pending.ownerDigest,
            }), at: Math.floor(approvedAt / 1000) })) {
          throw Object.assign(new Error('Pending Owner transition approval is invalid'), {
            code: 'OWNER_AUTHORITY_CORRUPT',
          });
        }
        appendRecoveredOwnerOutcome({ directory, intent: pending,
          outcome: { ...pending, at: new Date(approvedAt).toISOString(), phase: 'outcome',
            outcome: 'accepted', revisionAfter: pending.expectedRevision + 1,
            recoveryApproval: approvalRecord(approval) },
          operatorConfirmedNoActiveWriters: true });
      }
      const currentEvidence = inspectDurableOwnerAudit({ directory, includeOwnerAuthority: true });
      if (currentEvidence.pending.length) {
        throw Object.assign(new Error('Owner authority transition remains unresolved'), {
          code: 'OWNER_AUTHORITY_RECOVERY_REQUIRED',
        });
      }
      releaseOwnerAuditLockForReconciliation({ directory,
        expectedSequence: currentEvidence.sequence, expectedHash: currentEvidence.hash,
        operatorConfirmedNoActiveWriters: true });
    } finally {
      removeOwnedDurableProcessLock({ directory, name: RECOVERY_LOCK, owner });
    }
    const result = requireState();
    return Object.freeze({ ...result, recovered: true });
  }

  return Object.freeze({ directory, realmId, issuer, resource: verifier.resource,
    authorizedClientIds: verifier.authorizedClientIds, inspect, bootstrap, revoke,
    recover,
    isCurrentReadPrincipal(principal) {
      if (!isAuth0OwnerPrincipal(principal) || principal.issuer !== issuer ||
          !principal.scopes.includes('g7.read') || principal.expiresAt <= Math.floor(now() / 1000)) return false;
      try {
        const state = requireState();
        return state.status === 'active' && state.owner?.ownerDigest === principal.ownerDigest;
      } catch { return false; }
    },
    verifyReadPrincipal(accessToken) {
      const principal = verifier.verifyPrincipal(accessToken);
      if (!isAuth0OwnerPrincipal(principal)) return null;
      const state = requireState();
      return state.status === 'active' && state.owner?.ownerDigest === principal.ownerDigest
        ? principal : null;
    },
    verifyAdminPrincipal(accessToken) {
      const principal = verifier.verifyAdminPrincipal(accessToken);
      if (!isAuth0OwnerPrincipal(principal)) return null;
      const state = requireState();
      return state.status === 'active' && state.owner?.ownerDigest === principal.ownerDigest
        ? principal : null;
    },
    get accessVerifier() {
      return Object.freeze({ verifyPrincipal: accessToken => {
        const principal = verifier.verifyAdminPrincipal(accessToken);
        if (!isAuth0OwnerPrincipal(principal)) return null;
        const state = requireState();
        return state.status === 'active' && state.owner?.ownerDigest === principal.ownerDigest
          ? principal : null;
      } });
    },
  });
}
