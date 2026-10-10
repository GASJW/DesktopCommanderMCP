import { createServer } from 'node:net';
import { spawn } from 'node:child_process';
import { existsSync, lstatSync, unlinkSync, chmodSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DEFAULT_EXECUTOR = path.join(ROOT, 'dist/index.js');
const DEFAULT_SOCKET = '/run/vps-commander-ipc/mcp.sock';

export async function startExecutor(options = {}) {
  const socketPath = options.socketPath ?? process.env.VPS_COMMANDER_EXECUTOR_SOCKET ?? DEFAULT_SOCKET;
  const executorFile = path.resolve(options.executorFile ?? DEFAULT_EXECUTOR);
  if (!path.isAbsolute(socketPath) || socketPath.length > 105) throw Error('Invalid absolute Unix socket path');
  if (!existsSync(executorFile)) throw Error('Desktop Commander build missing');
  if (existsSync(socketPath)) {
    if (!lstatSync(socketPath).isSocket()) throw Error('Refusing to remove non-socket filesystem entry');
    unlinkSync(socketPath);
  }
  const env = { ...process.env, DC_REMOTE_DEVICE: 'true', VPS_COMMANDER_DISABLE_BROWSER_INIT: '1' };
  for (const k of Object.keys(env)) if (k.startsWith('VPS_COMMANDER_ACCESS_') ||
      k === 'VPS_COMMANDER_TOKEN' || k === 'VPS_COMMANDER_ALLOWED_EMAILS') delete env[k];
  const child = spawn(process.execPath, [executorFile, '--no-onboarding'], {
    cwd: path.dirname(executorFile), shell: false, stdio: ['pipe', 'pipe', 'inherit'], env,
  });
  let closing = false;
  child.on('error', () => { if (!closing) { process.exitCode = 1; server.close(); } });
  child.on('exit', () => { if (!closing) { process.exitCode = 1; server.close(); } });
  let current = null;
  const server = createServer(socket => {
    if (current) { socket.destroy(); return; }
    current = socket;
    socket.setNoDelay(true);
    socket.pipe(child.stdin, { end: false });
    child.stdout.pipe(socket, { end: false });
    const cleanup = () => {
      socket.unpipe(child.stdin); child.stdout.unpipe(socket);
      if (current === socket) current = null;
    };
    socket.once('close', cleanup);
    socket.once('error', cleanup);
  });
  try {
    await new Promise((resolve, reject) => {
      server.once('error', reject); server.listen(socketPath, resolve);
    });
    chmodSync(socketPath, 0o660);
  } catch (error) { child.kill('SIGTERM'); throw error; }
  return { socketPath, close: async () => {
    closing = true; current?.destroy(); child.kill('SIGTERM');
    await new Promise(resolve => server.close(resolve));
    if (existsSync(socketPath) && lstatSync(socketPath).isSocket()) unlinkSync(socketPath);
  } };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  startExecutor().then(x => process.stderr.write('MCP executor socket ready: ' + x.socketPath + '\n'))
    .catch(error => { process.stderr.write('MCP executor startup denied: ' + error.message + '\n'); process.exitCode = 1; });
}
