import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { randomUUID, timingSafeEqual } from 'node:crypto';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Development-only bridge: stdio MCP -> stateless Streamable HTTP JSON.
// No public hostname or Cloudflare route is authorized by this module.
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DEFAULT_EXECUTOR = path.join(ROOT, 'dist/index.js');
const TIMEOUT_MS = 120_000;
const MAX_PENDING = 16;
const MAX_BODY = 1024 * 1024;

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
  constructor(file) { this.file = file; this.pending = new Map(); this.sequence = 0; this.dead = false; }
  async start() {
    // Do not hand the gateway's authentication secret to the executor shell.
    const childEnv = { ...process.env, DC_REMOTE_DEVICE: 'true', VPS_COMMANDER_DISABLE_BROWSER_INIT: '1' };
    delete childEnv.VPS_COMMANDER_TOKEN;
    this.child = spawn(process.execPath, [this.file, '--no-onboarding'], {
      shell: false, cwd: path.dirname(this.file), stdio: ['pipe', 'pipe', 'inherit'],
      env: childEnv,
    });
    this.child.on('exit', () => this.fail());
    this.child.on('error', () => this.fail());
    createInterface({ input: this.child.stdout }).on('line', line => {
      if (line.length > 16_000_000) return;
      let message;
      try { message = JSON.parse(line); } catch { return; }
      if (!message || !Object.hasOwn(message, 'id')) return;
      const key = String(message.id);
      const item = this.pending.get(key);
      if (!item) return;
      clearTimeout(item.timer);
      this.pending.delete(key);
      item.resolve(message);
    });
    try {
      const init = await this.call('initialize', {
        protocolVersion: '2025-03-26', capabilities: {},
        clientInfo: { name: 'vps-commander-gateway', version: '0.1.0' },
      });
      if (init.error || !init.result?.capabilities) throw Error('Upstream MCP initialization failed');
      this.initialization = init.result;
      this.notify('notifications/initialized', {});
    } catch (error) { this.close(); throw error; }
  }
  fail() {
    this.dead = true;
    for (const item of this.pending.values()) {
      clearTimeout(item.timer);
      item.reject(new Error('Executor unavailable'));
    }
    this.pending.clear();
  }
  call(method, params = {}) {
    if (this.dead || !this.child?.stdin.writable) return Promise.reject(Error('Executor disconnected'));
    if (this.pending.size >= MAX_PENDING) return Promise.reject(Error('Executor busy'));
    const id = 'vpsc-' + ++this.sequence + '-' + randomUUID();
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id); reject(Error('Executor timeout'));
      }, TIMEOUT_MS);
      this.pending.set(id, { resolve, reject, timer });
      this.child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n', error => {
        if (error) { clearTimeout(timer); this.pending.delete(id); reject(error); }
      });
    });
  }
  notify(method, params = {}) {
    if (this.child?.stdin.writable && !this.dead) {
      this.child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method, params }) + '\n');
    }
  }
  close() { this.fail(); this.child?.kill('SIGTERM'); }
}

export async function startGateway(options = {}) {
  const token = options.token ?? process.env.VPS_COMMANDER_TOKEN;
  const host = options.host ?? process.env.VPS_COMMANDER_HOST ?? '127.0.0.1';
  const port = Number(options.port ?? process.env.VPS_COMMANDER_PORT ?? 8787);
  const executable = path.resolve(options.executorFile ?? process.env.VPS_COMMANDER_EXECUTOR_FILE ?? DEFAULT_EXECUTOR);
  if (typeof token !== 'string' || Buffer.byteLength(token) < 32 || Buffer.byteLength(token) > 4096)
    throw Error('VPS_COMMANDER_TOKEN must contain 32-4096 bytes');
  if (host !== '127.0.0.1' && host !== '::1') throw Error('Loopback bind required');
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw Error('Invalid port');
  if (!existsSync(executable)) throw Error('Build missing: expected Desktop Commander dist/index.js');
  const peer = new Peer(executable);
  await peer.start();
  const server = createServer(async (req, res) => {
    // No browser cross-origin requests. Also do not leak MCP methods without auth.
    if (req.headers.origin) return reply(res, 403, { error: 'Origin forbidden' });
    if (req.url !== '/mcp' && req.url !== '/healthz') return reply(res, 404, { error: 'Not found' });
    if (!matchesBearer(req.headers.authorization, token)) {
      res.setHeader('www-authenticate', 'Bearer');
      return reply(res, 401, { error: 'Unauthorized' });
    }
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
    try {
      const result = await peer.call(message.method, message.params ?? {});
      return reply(res, 200, { ...result, id: message.id });
    } catch {
      return reply(res, peer.dead ? 503 : 502, fault(message.id, -32000, 'Executor unavailable, busy or timed out'));
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
