import { randomUUID } from 'node:crypto';

// Isolated G7.2 prototype: no network listeners, no process execution, no owner auth.
// Transport must authenticate agents and owner/tool policy before invoking this.
const TOOL = /^[A-Za-z][A-Za-z0-9_-]{0,79}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export class DeviceRouteError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'DeviceRouteError';
    this.code = code;
  }
}
const fail = (code, message) => new DeviceRouteError(code, message);
const copy = (value, maxBytes) => {
  let serialized;
  try { serialized = JSON.stringify(value); } catch {
    throw fail('BAD_PAYLOAD', 'Unserializable payload');
  }
  if (typeof serialized !== 'string' || Buffer.byteLength(serialized, 'utf8') > maxBytes) {
    throw fail('BAD_PAYLOAD', 'Payload is missing or too large');
  }
  return JSON.parse(serialized);
};

export function createDeviceRouter({
  registry, timeoutMs = 30_000, maxPendingPerDevice = 4,
  maxRequestBytes = 128 * 1024, maxResponseBytes = 1024 * 1024,
} = {}) {
  if (!registry || typeof registry.isLiveSession !== 'function' ||
      !Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 120_000 ||
      !Number.isInteger(maxPendingPerDevice) || maxPendingPerDevice < 1 || maxPendingPerDevice > 16 ||
      !Number.isInteger(maxRequestBytes) || maxRequestBytes < 1024 || maxRequestBytes > 1024 * 1024 ||
      !Number.isInteger(maxResponseBytes) || maxResponseBytes < 1024 || maxResponseBytes > 8 * 1024 * 1024) {
    throw new TypeError('Invalid router configuration');
  }
  const active = new Map();
  let stopped = false;
  const endPending = (channel, error) => {
    for (const [id, item] of channel.pending) {
      channel.pending.delete(id);
      clearTimeout(item.timer);
      item.reject(error);
    }
  };
  function attachTransport({deviceId, sessionId, send} = {}) {
    if (stopped) throw fail('CLOSED', 'Router closed');
    if (typeof send !== 'function' || !registry.isLiveSession(deviceId, sessionId)) {
      throw fail('UNAUTHORIZED_DEVICE', 'Device session is not authenticated and live');
    }
    const previous = active.get(deviceId);
    if (previous && previous.sessionId === sessionId) {
      throw fail('SESSION_IN_USE', 'Session already attached');
    }
    if (previous) endPending(previous, fail('AMBIGUOUS_DISCONNECT', 'Session superseded; no replay'));
    active.set(deviceId, {sessionId, send, pending:new Map()});
    return Object.freeze({deviceId,sessionId});
  }
  async function callDevice({deviceId, name, arguments:args = {}} = {}) {
    if (stopped) throw fail('CLOSED', 'Router closed');
    if (typeof deviceId !== 'string' || !UUID.test(deviceId)) {
      throw fail('BAD_DEVICE', 'Explicit deviceId required');
    }
    if (typeof name !== 'string' || !TOOL.test(name)) {
      throw fail('BAD_TOOL', 'Invalid tool name');
    }
    if (!args || typeof args !== 'object' || Array.isArray(args) ||
        (Object.getPrototypeOf(args) !== Object.prototype && Object.getPrototypeOf(args) !== null)) {
      throw fail('BAD_PAYLOAD', 'Tool arguments must be a plain object');
    }
    const params = copy({name,arguments:args}, maxRequestBytes);
    const channel = active.get(deviceId);
    if (!channel || !registry.isLiveSession(deviceId, channel.sessionId)) {
      if (channel) {
        active.delete(deviceId);
        endPending(channel, fail('AMBIGUOUS_DISCONNECT','Session expired; no replay'));
      }
      throw fail('OFFLINE', 'Device offline');
    }
    if (channel.pending.size >= maxPendingPerDevice) throw fail('BUSY', 'Device busy');
    const requestId = randomUUID();
    const frame = Object.freeze({version:1,deviceId,sessionId:channel.sessionId,requestId,
      method:'tools/call',params});
    return new Promise((resolve,reject) => {
      const timer = setTimeout(() => {
        if (channel.pending.delete(requestId)) {
          reject(fail('AMBIGUOUS_TIMEOUT', 'Outcome unknown; do not replay'));
        }
      }, timeoutMs);
      channel.pending.set(requestId,{timer,resolve,reject});
      Promise.resolve().then(() => {
        if (stopped || active.get(deviceId) !== channel || !channel.pending.has(requestId) ||
            !registry.isLiveSession(deviceId, channel.sessionId)) {
          throw fail('AMBIGUOUS_DISCONNECT','Device unavailable; no replay');
        }
        return channel.send(frame);
      }).catch(() => {
        const item = channel.pending.get(requestId);
        if (item) {
          clearTimeout(item.timer);
          channel.pending.delete(requestId);
          item.reject(fail('AMBIGUOUS_DISPATCH','Transport failed; outcome unknown'));
        }
      });
    });
  }
  // acceptResponse must be called ONLY from a verified agent transport.
  function acceptResponse({deviceId, sessionId, requestId, result} = {}) {
    const channel = active.get(deviceId);
    if (stopped || !channel || channel.sessionId !== sessionId ||
        !registry.isLiveSession(deviceId, sessionId) || typeof requestId !== 'string' ||
        !UUID.test(requestId) || !channel.pending.has(requestId)) return false;
    let payload;
    try { payload = copy(result,maxResponseBytes); } catch {
      const item=channel.pending.get(requestId);
      channel.pending.delete(requestId);
      clearTimeout(item.timer);
      item.reject(fail('BAD_RESPONSE','Remote response invalid or too large'));
      return false;
    }
    const item=channel.pending.get(requestId);
    channel.pending.delete(requestId);
    clearTimeout(item.timer);
    item.resolve(payload);
    return true;
  }
  function detachTransport({deviceId,sessionId} = {}) {
    const channel=active.get(deviceId);
    if (!channel || channel.sessionId !== sessionId) return false;
    active.delete(deviceId);
    endPending(channel,fail('AMBIGUOUS_DISCONNECT','Device disconnected; no replay'));
    return true;
  }
  function close() {
    if (stopped) return;
    stopped=true;
    for (const channel of active.values()) endPending(channel,fail('CLOSED','Router closed'));
    active.clear();
  }
  return Object.freeze({attachTransport,callDevice,acceptResponse,detachTransport,close});
}
