import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { createConnection } from 'node:net';
import { randomUUID, timingSafeEqual } from 'node:crypto';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createAccessVerifier } from './access-auth.mjs';
import { createAuditRecorder } from './audit.mjs';

// Development-only bridge: stdio MCP -> stateless Streamable HTTP JSON.
// No public hostname or Cloudflare route is authorized by this module.
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DEFAULT_EXECUTOR = path.join(ROOT, 'dist/index.js');
const TIMEOUT_MS = 120_000;
const MAX_PENDING = 16;
const MAX_BODY = 1024 * 1024;
const DEFAULT_MAX_RESPONSE = 2 * 1024 * 1024;
const DEFAULT_MAX_RPC_LINE = 4 * 1024 * 1024;

export function matchesBearer(header, token) {
  if (typeof header !== 'string' || !header.startsWith('Bearer ')) return false;
  const actual = Buffer.from(header.slice(7));
  const expected = Buffer.from(token);
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}
function reply(res, status, data) {
  res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
  res.end(JSON.stringify(data));
}
function fault(id, code, message) {
  return { jsonrpc: '2.0', id: id ?? null, error: { code, message } };
}
class Peer {
  constructor(file, socketPath, maxLine = DEFAULT_MAX_RPC_LINE) { this.file = file; this.socketPath = socketPath; this.maxLine = maxLine; this.pending = new Map(); this.sequence = 0; this.dead = false; }
  async start() {
    if (this.socketPath) {
      const socket = createConnection(this.socketPath);
      try {
        await new Promise((resolve, reject) => { socket.once('connect', resolve); socket.once('error', reject); });
      } catch (error) { socket.destroy(); throw error; }
      this.socket = socket;
      this.input = socket;
      this.output = socket;
      socket.once('close', () => this.fail());
      socket.on('error', () => this.fail());
    } else {
    // Legacy single-user mode: only for isolated development/testing.
    const childEnv = { ...process.env, DC_REMOTE_DEVICE: 'true', VPS_COMMANDER_DISABLE_BROWSER_INIT: '1' };
    delete childEnv.VPS_COMMANDER_TOKEN;
    this.child = spawn(process.execPath, [this.file, '--no-onboarding'], {
      shell: false, cwd: path.dirname(this.file), stdio: ['pipe', 'pipe', 'inherit'],
      env: childEnv,
    });
    this.input = this.child.stdin;
    this.output = this.child.stdout;
    this.child.on('exit', () => this.fail());
    this.child.on('error', () => this.fail());
    }
    // Bound every upstream JSONL frame while receiving, including lines with no newline.
    // Oversized output closes this transport; in-flight operations are never automatically replayed.
    let parts = [];
    let frameBytes = 0;
    this.output.on('data', chunk => {
      if (this.dead) return;
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      let start = 0;
      while (start < buffer.length && !this.dead) {
        const endOfLine = buffer.indexOf(10, start);
        const end = endOfLine < 0 ? buffer.length : endOfLine;
        const length = end - start;
        if (frameBytes + length > this.maxLine) {
          parts = [];
          frameBytes = 0;
          this.fail();
          this.socket?.destroy();
          this.child?.kill('SIGTERM');
          return;
        }
        if (length) parts.push(buffer.subarray(start, end));
        frameBytes += length;
        if (endOfLine < 0) return;
        const line = Buffer.concat(parts, frameBytes).toString('utf8');
        parts = [];
        frameBytes = 0;
        let message;
        try { message = JSON.parse(line); } catch { start = endOfLine + 1; continue; }
        if (message && Object.hasOwn(message, 'id')) {
          const key = String(message.id);
          const item = this.pending.get(key);
          if (item) {
            clearTimeout(item.timer);
            this.pending.delete(key);
            item.resolve(message);
          }
        }
        start = endOfLine + 1;
      }
    });
    try {
      const init = await this.call('initialize', {
        protocolVersion: '2025-03-26', capabilities: {},
        clientInfo: { name: 'vps-commander-gateway', version: '0.1.0' },
      }, 8_000);
      if (init.error || !init.result?.capabilities) throw Error('Upstream MCP initialization failed');
      this.initialization = init.result;
      this.notify('notifications/initialized', {});
    } catch (error) { this.close(); throw error; }
  }
  fail() {
    if (this.dead) return;
    this.dead = true;
    for (const item of this.pending.values()) {
      clearTimeout(item.timer);
      item.reject(new Error('Executor unavailable'));
    }
    this.pending.clear();
    this.onDisconnect?.();
  }
  call(method, params = {}, timeoutMs = TIMEOUT_MS) {
    if (this.dead || !this.input?.writable) return Promise.reject(Error('Executor disconnected'));
    if (this.pending.size >= MAX_PENDING) return Promise.reject(Error('Executor busy'));
    const id = 'vpsc-' + ++this.sequence + '-' + randomUUID();
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id); reject(Error('Executor timeout'));
      }, timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      this.input.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n', error => {
        if (error) { clearTimeout(timer); this.pending.delete(id); reject(error); }
      });
    });
  }
  notify(method, params = {}) {
    if (this.input?.writable && !this.dead) {
      this.input.write(JSON.stringify({ jsonrpc: '2.0', method, params }) + '\n');
    }
  }
  close() { this.fail(); this.socket?.destroy(); this.child?.kill('SIGTERM'); }
}


class RecoveringPeer {
  constructor(file, socketPath, options = {}) {
    this.file = file;
    this.socketPath = socketPath;
    this.current = null;
    this.connecting = null;
    this.stopping = false;
    this.retry = null;
    this.retries = 0;
    this.initialDelay = options.initialDelay ?? 250;
    this.maxDelay = options.maxDelay ?? 8000;
    this.recoverySink = options.recoverySink ?? (line => process.stderr.write(line));
    this.maxLine = options.maxLine ?? DEFAULT_MAX_RPC_LINE;
  }
  logRecovery(phase, attempt = 0, retryDelayMs = 0) {
    const record = {
      event: 'vps_commander_recovery', version: 1, phase, attempt, retry_delay_ms: retryDelayMs,
    };
    try { this.recoverySink(JSON.stringify(record) + '\n'); } catch { /* best effort */ }
  }
  get dead() { return !this.current || this.current.dead; }
  get initialization() { return this.current?.initialization; }
  call(method, params) {
    if (this.dead) return Promise.reject(new Error('Executor unavailable'));
    return this.current.call(method, params);
  }
  async start() { await this.connect(); }
  async connect() {
    if (this.stopping) return;
    const candidate = new Peer(this.file, this.socketPath, this.maxLine);
    this.connecting = candidate;
    try {
      await candidate.start();
    } catch (error) {
      candidate.close();
      throw error;
    } finally {
      if (this.connecting === candidate) this.connecting = null;
    }
    if (this.stopping) { candidate.close(); return; }
    this.current = candidate;
    if (this.retries > 0) this.logRecovery('reconnected', this.retries);
    this.retries = 0;
    candidate.onDisconnect = () => this.disconnected(candidate);
    if (candidate.dead) this.disconnected(candidate);
  }
  disconnected(candidate) {
    if (this.stopping || this.current !== candidate) return;
    this.current = null;
    candidate.close();
    this.logRecovery('disconnected');
    this.schedule();
  }
  schedule() {
    if (this.stopping || this.retry || this.connecting) return;
    const delay = Math.min(this.maxDelay, this.initialDelay * 2 ** Math.min(this.retries++, 8));
    this.logRecovery('retry_scheduled', this.retries, delay);
    this.retry = setTimeout(async () => {
      this.retry = null;
      if (this.stopping) return;
      try {
        await this.connect();
      } catch {
        this.schedule();
      }
    }, delay);
    this.retry.unref?.();
  }
  close() {
    this.stopping = true;
    if (this.retry) clearTimeout(this.retry);
    this.retry = null;
    this.connecting?.close();
    this.current?.close();
    this.current = null;
  }
}

export async function startGateway(options = {}) {
  const authMode = options.authMode ?? process.env.VPS_COMMANDER_AUTH_MODE ?? 'local';
  const token = options.token ?? process.env.VPS_COMMANDER_TOKEN;
  if (authMode !== 'local' && authMode !== 'access') throw Error('Unknown authorization mode');
  const verifyAccess = authMode === 'access' ? createAccessVerifier({
    issuer: options.accessIssuer ?? process.env.VPS_COMMANDER_ACCESS_ISSUER,
    audience: options.accessAudience ?? process.env.VPS_COMMANDER_ACCESS_AUD,
    allowedEmails: options.allowedEmails ?? process.env.VPS_COMMANDER_ALLOWED_EMAILS,
    keyProvider: options.accessKeyProvider,
  }) : null;
  const host = options.host ?? process.env.VPS_COMMANDER_HOST ?? '127.0.0.1';
  const port = Number(options.port ?? process.env.VPS_COMMANDER_PORT ?? 8787);
  const executable = path.resolve(options.executorFile ?? process.env.VPS_COMMANDER_EXECUTOR_FILE ?? DEFAULT_EXECUTOR);
  // Explicit test executor takes precedence over a production socket inherited from the environment.
  const executorSocket = options.executorSocket !== undefined
    ? options.executorSocket : (options.executorFile ? null : process.env.VPS_COMMANDER_EXECUTOR_SOCKET ?? null);
  if (executorSocket && (!path.isAbsolute(executorSocket) || executorSocket.length > 105)) throw Error('Invalid executor socket path');
  if (authMode === 'local' &&
      (typeof token !== 'string' || Buffer.byteLength(token) < 32 || Buffer.byteLength(token) > 4096))
    throw Error('VPS_COMMANDER_TOKEN must contain 32-4096 bytes');
  if (host !== '127.0.0.1' && host !== '::1') throw Error('Loopback bind required');
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw Error('Invalid port');
  const maxResponseBytes = options.maxResponseBytes ?? Number(process.env.VPS_COMMANDER_MAX_RESPONSE_BYTES ?? DEFAULT_MAX_RESPONSE);
  const maxUpstreamLineBytes = options.maxUpstreamLineBytes ?? Number(process.env.VPS_COMMANDER_MAX_RPC_LINE_BYTES ?? DEFAULT_MAX_RPC_LINE);
  const maxInFlight = options.maxInFlight ?? Number(process.env.VPS_COMMANDER_MAX_INFLIGHT ?? MAX_PENDING);
  if (!Number.isSafeInteger(maxResponseBytes) || maxResponseBytes < 1024 || maxResponseBytes > 8 * 1024 * 1024) throw Error('Invalid response byte limit');
  if (!Number.isSafeInteger(maxUpstreamLineBytes) || maxUpstreamLineBytes < 1024 || maxUpstreamLineBytes > 16 * 1024 * 1024 || maxUpstreamLineBytes < maxResponseBytes) throw Error('Invalid upstream line byte limit');
  if (!Number.isSafeInteger(maxInFlight) || maxInFlight < 1 || maxInFlight > MAX_PENDING) throw Error('Invalid in-flight limit');
  if (!executorSocket && !existsSync(executable)) throw Error('Build missing: expected Desktop Commander dist/index.js');
  const peer = executorSocket
    ? new RecoveringPeer(executable, executorSocket, { initialDelay: options.recoveryInitialDelay, maxDelay: options.recoveryMaxDelay, recoverySink: options.recoverySink, maxLine: maxUpstreamLineBytes })
    : new Peer(executable, executorSocket, maxUpstreamLineBytes);
  await peer.start();
  const auditEnabled = options.auditEnabled ?? process.env.VPS_COMMANDER_AUDIT_ENABLED === '1';
  const beginAudit = auditEnabled ? createAuditRecorder({ sink: options.auditSink }) : null;
  let inFlight = 0;
  const server = createServer(async (req, res) => {
    const audit = beginAudit?.(req, res);
    // No browser cross-origin requests. Also do not leak MCP methods without auth.
    if (req.headers.origin) return reply(res, 403, { error: 'Origin forbidden' });
    if (req.url !== '/mcp' && req.url !== '/healthz') return reply(res, 404, { error: 'Not found' });
    const principal = authMode === 'access'
      ? await verifyAccess.verifyPrincipal(req.headers['cf-access-jwt-assertion']) : null;
    const authorized = authMode === 'access'
      ? Boolean(principal) : matchesBearer(req.headers.authorization, token);
    if (!authorized) {
      audit?.outcome('denied');
      if (authMode === 'local') res.setHeader('www-authenticate', 'Bearer');
      return reply(res, 401, { error: 'Unauthorized' });
    }
    if (authMode === 'access') audit?.principal(principal);
    else audit?.local();
    if (req.url === '/healthz') return reply(res, peer.dead ? 503 : 200, { status: peer.dead ? 'down' : 'ready' });
    if (req.method !== 'POST') {
      res.setHeader('allow', 'POST');
      return reply(res, 405, { error: 'Only POST is implemented' });
    }
    if (!req.headers['content-type']?.toLowerCase().startsWith('application/json'))
      return reply(res, 415, { error: 'JSON required' });
    if (req.headers['mcp-session-id']) return reply(res, 400, { error: 'Stateless MCP only' });
    if (peer.dead) return reply(res, 503, { error: 'Executor disconnected' });
    let body = '';
    try {
      for await (const part of req) {
        body += part;
        if (Buffer.byteLength(body) > MAX_BODY) return reply(res, 413, { error: 'Payload too large' });
      }
    } catch { return reply(res, 400, { error: 'Invalid body' }); }
    let message;
    try { message = JSON.parse(body); } catch { return reply(res, 400, fault(null, -32700, 'Invalid JSON')); }
    if (!message || Array.isArray(message) || message.jsonrpc !== '2.0' || typeof message.method !== 'string')
      return reply(res, 400, fault(message?.id, -32600, 'Invalid request'));
    audit?.operation(message.method, message.params?.name);
    if (message.method === 'initialize' && Object.hasOwn(message, 'id')) {
      const init = peer.initialization;
      return reply(res, 200, {
        jsonrpc: '2.0', id: message.id,
        result: { protocolVersion: init.protocolVersion, capabilities: init.capabilities,
          serverInfo: { name: 'vps-commander-gateway', version: '0.1.0' } },
      });
    }
    if (!Object.hasOwn(message, 'id')) {
      res.writeHead(202, { 'cache-control': 'no-store' }); return res.end();
    }
    if (inFlight >= maxInFlight) {
      audit?.outcome('busy');
      res.setHeader('retry-after', '1');
      return reply(res, 429, fault(message.id, -32001, 'Gateway at concurrency limit'));
    }
    inFlight++;
    try {
      const result = await peer.call(message.method, message.params ?? {});
      const envelope = { ...result, id: message.id };
      const encoded = JSON.stringify(envelope);
      if (Buffer.byteLength(encoded, 'utf8') > maxResponseBytes) {
        audit?.outcome('limit_exceeded');
        return reply(res, 502, fault(message.id, -32005, 'Executor response exceeds limit; use smaller chunks'));
      }
      audit?.outcome(result?.error ? 'rpc_error' : result?.result?.isError ? 'tool_error' : 'ok');
      res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
      return res.end(encoded);
    } catch {
      audit?.outcome('unavailable');
      return reply(res, peer.dead ? 503 : 502, fault(message.id, -32000, 'Executor unavailable or timed out'));
    } finally {
      inFlight--;
    }
  });
  server.requestTimeout = TIMEOUT_MS + 5000;
  await new Promise((resolve, reject) => {
    server.once('error', reject); server.listen(port, host, resolve);
  });
  return {
    address: 'http://' + (host === '::1' ? '[::1]' : host) + ':' + server.address().port,
    close: async () => {
      peer.close(); server.closeAllConnections();
      await new Promise(resolve => server.close(resolve));
    },
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  startGateway().then(g => process.stderr.write('MCP gateway: ' + g.address + ' (LOCAL ONLY)\n'))
    .catch(error => { process.stderr.write('Gateway startup refused: ' + error.message + '\n'); process.exitCode = 1; });
}
