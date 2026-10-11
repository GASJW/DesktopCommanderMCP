import { createHash, randomUUID } from 'node:crypto';

const allowedMethods = new Set(['initialize', 'tools/list', 'tools/call', 'ping', 'resources/list', 'prompts/list']);
function operationName(value) {
  if (typeof value !== 'string') return 'unknown';
  if (allowedMethods.has(value)) return value;
  return value.startsWith('notifications/') ? 'notification' : 'other';
}
function toolName(value) {
  return typeof value === 'string' && /^[a-zA-Z][a-zA-Z0-9_-]{0,79}$/.test(value) ? value : 'unknown';
}
function httpMethod(value) {
  return ['GET', 'POST', 'OPTIONS', 'HEAD', 'DELETE'].includes(value) ? value : 'other';
}
function routeName(value) {
  return value === '/mcp' ? 'mcp' : value === '/healthz' ? 'healthz' :
    (value === '/dashboard' || value === '/dashboard/' || value === '/dashboard/metrics' ||
      value === '/dashboard/app.js' || value === '/dashboard/style.css') ? 'dashboard' : 'other';
}
function outcomeName(value) {
  return ['ok', 'denied', 'invalid_request', 'tool_error', 'rpc_error', 'unavailable', 'disconnected', 'busy', 'limit_exceeded'].includes(value) ? value : 'other';
}

export function verifiedPrincipalId(principal) {
  if (!principal || typeof principal.issuer !== 'string' || typeof principal.subject !== 'string') return 'anonymous';
  return 'cf_' + createHash('sha256').update(principal.issuer).update('\0').update(principal.subject).digest('hex').slice(0, 24);
}

export function createAuditRecorder({ sink = line => process.stdout.write(line), onEntry = () => {}, now = () => new Date(), monotonic = () => process.hrtime.bigint() } = {}) {
  return function beginRequest(request, response) {
    const requestId = randomUUID();
    const startedAt = now().toISOString();
    const begun = monotonic();
    const state = { principal: 'anonymous', operation: 'unknown', tool: null, outcome: null };
    let finished = false;
    function record() {
      if (finished) return;
      finished = true;
      const ms = Number(monotonic() - begun) / 1e6;
      const httpStatus = Number.isInteger(response.statusCode) ? response.statusCode : 0;
      const result = state.outcome ?? (response.writableEnded ? (
        httpStatus === 401 || httpStatus === 403 ? 'denied' :
        httpStatus >= 500 ? 'unavailable' :
        httpStatus >= 400 ? 'invalid_request' : 'ok'
      ) : 'disconnected');
      const entry = {
        event: 'vps_commander_audit',
        version: 1,
        request_id: requestId,
        started_at: startedAt,
        duration_ms: Math.max(0, Math.round(ms)),
        identity: state.principal,
        route: routeName(request.url),
        http_method: httpMethod(request.method),
        operation: state.operation,
        tool: state.tool,
        http_status: httpStatus,
        outcome: outcomeName(result),
      };
      try { onEntry(entry); } catch { /* metrics never affect serving or raw audit */ }
      try { sink(JSON.stringify(entry) + '\n'); } catch { /* logging failure must not leak untrusted content */ }
    }
    response.once('finish', record);
    response.once('close', record);
    return {
      principal(value) { state.principal = verifiedPrincipalId(value); },
      local() { state.principal = 'local-authenticated'; },
      operation(method, tool) {
        state.operation = operationName(method);
        state.tool = state.operation === 'tools/call' ? toolName(tool) : null;
      },
      outcome(value) { state.outcome = outcomeName(value); },
      requestId,
    };
  };
}
