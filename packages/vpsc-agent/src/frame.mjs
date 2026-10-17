import { createHash } from 'node:crypto';

const PATHS = new Set(['/agent/heartbeat', '/agent/poll', '/agent/result',
  '/agent/cancel-ack','/agent/disconnect']);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

// Single source included in the prototype npm package and imported by its
// server-side loopback pilot. Path and raw UTF-8 request body are signed.
export function signedAgentRequest({method='POST',pathname,deviceId,sessionId,sequence,bodyText}) {
  if (method !== 'POST' || !PATHS.has(pathname) ||
      typeof deviceId !== 'string' || !UUID.test(deviceId) ||
      typeof sessionId !== 'string' || !UUID.test(sessionId) ||
      !Number.isSafeInteger(sequence) || sequence < 1 ||
      typeof bodyText !== 'string' || Buffer.byteLength(bodyText,'utf8') > 256 * 1024) {
    throw new TypeError('Invalid agent request envelope');
  }
  const digest=createHash('sha256').update(bodyText,'utf8').digest('hex');
  return Buffer.from(['VPSC-AGENT-HTTP-v1',method,pathname,deviceId,sessionId,String(sequence),digest].join('\n'),'utf8');
}
