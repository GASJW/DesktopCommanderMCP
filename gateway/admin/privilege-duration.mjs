// G7.3 future administrator duration contract.
// Pure policy data only: this module creates no grants, capabilities, API routes,
// privileged processes, persistent secrets or dashboard controls.
export const ADMIN_DURATION_OPTIONS = Object.freeze([
  Object.freeze({ id: '10m', label: '10 minutos', milliseconds: 10 * 60_000 }),
  Object.freeze({ id: '30m', label: '30 minutos', milliseconds: 30 * 60_000 }),
  Object.freeze({ id: '60m', label: '1 hora', milliseconds: 60 * 60_000 }),
  Object.freeze({ id: 'indefinite', label: 'Indefinida (até revogação manual)', milliseconds: null }),
]);

const byId = new Map(ADMIN_DURATION_OPTIONS.map(option => [option.id, option]));
const MAX_TIME = 8_640_000_000_000_000;
const isTimestamp = value => Number.isSafeInteger(value) && value >= 0 && value <= MAX_TIME;

export function planAdminAccessWindow(durationId, approvedAt) {
  const option = byId.get(durationId);
  if (!option || !isTimestamp(approvedAt)) throw new TypeError('Invalid administrative duration selection');
  const expiresAt = option.milliseconds === null ? null : approvedAt + option.milliseconds;
  if (expiresAt !== null && !isTimestamp(expiresAt)) throw new RangeError('Administrative expiry overflow');
  // This is ONLY a validated plan, not a signed authorization/permission.
  return Object.freeze({ durationId, approvedAt, expiresAt });
}

export function adminWindowStatus(window, { now, revokedAt = null } = {}) {
  if (!window || typeof window !== 'object' || Array.isArray(window) ||
      !isTimestamp(now) || !isTimestamp(window.approvedAt) ||
      !byId.has(window.durationId) ||
      (revokedAt !== null && !isTimestamp(revokedAt))) return 'invalid';
  const expected = planAdminAccessWindow(window.durationId, window.approvedAt);
  // Exact shape keeps callers from claiming a non-expiring finite window.
  if (window.expiresAt !== expected.expiresAt) return 'invalid';
  if (revokedAt !== null) return 'revoked'; // Explicit revocation is final.
  if (now < window.approvedAt) return 'not_started';
  if (expected.expiresAt !== null && now >= expected.expiresAt) return 'expired';
  return 'within_window'; // STILL requires owner auth, device binding and operation policy.
}
