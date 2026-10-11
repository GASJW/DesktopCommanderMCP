import { readFile } from 'node:fs/promises';
import { statfsSync } from 'node:fs';
import { hostname, freemem, totalmem, loadavg } from 'node:os';
import { execFile } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const DIR = path.dirname(fileURLToPath(import.meta.url));
const RESOURCES = new Map([
  ['/dashboard', ['index.html', 'text/html; charset=utf-8']],
  ['/dashboard/', ['index.html', 'text/html; charset=utf-8']],
  ['/dashboard/app.js', ['app.js', 'text/javascript; charset=utf-8']],
  ['/dashboard/style.css', ['style.css', 'text/css; charset=utf-8']],
]);
const UNITS = [
  ['gateway','vps-commander.service'],
  ['executor','vps-commander-executor.service'],
  ['tunnel_commander','cloudflared-vps-commander.service'],
  ['tunnel_cofre','cloudflared.service'],
];
const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'none'";
export const DASHBOARD_PATHS = new Set([...RESOURCES.keys(), '/dashboard/metrics']);

export function dashboardHeaders(type) {
  return {
    'content-type': type,
    'cache-control': 'private, no-store, max-age=0',
    'content-security-policy': CSP,
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
    'x-frame-options': 'DENY',
  };
}

function serviceActive(name) {
  return new Promise(resolve => {
    execFile('/usr/bin/systemctl', ['is-active', name],
      { timeout: 1500, maxBuffer: 128, encoding: 'utf8', env: {PATH:'/usr/bin:/bin'} },
      (error, stdout) => resolve(error ? (stdout?.trim()==='inactive'?'inactive':'unknown')
        : stdout.trim()==='active'?'active':'unknown'));
  });
}
let cache = null;
let cacheExpires = 0;
async function serviceStatuses(now = Date.now()) {
  if (cache && cacheExpires > now) return cache;
  const states = await Promise.all(UNITS.map(async ([key,unit]) => [key,await serviceActive(unit)]));
  cache = Object.fromEntries(states);
  cacheExpires = now + 5000;
  return cache;
}
function hostInfo() {
  let disk = null;
  try {
    const s = statfsSync('/');
    const total = s.blocks * s.bsize;
    disk = { used_percent: total ? Math.round((1-s.bavail*s.bsize/total)*100) : null };
  } catch { /* optional; never fake a disk reading */ }
  return {
    device: { id:'vps-gui', name:hostname(), type:'VPS', inventory_count:1,
      caveat:'Este MCP opera em um host. Nao descobre outros PCs ou dispositivos remotos.' },
    ram: { total_bytes:totalmem(), available_bytes:freemem() },
    load_1m: loadavg()[0],
    disk,
  };
}
export async function serveDashboard(req,res,{metrics,peerUp,inFlight}) {
  res.setHeader('vary','Cf-Access-Jwt-Assertion');
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.writeHead(405, {...dashboardHeaders('application/json'), allow:'GET, HEAD'});
    return res.end(JSON.stringify({error:'Method not allowed'}));
  }
  let data, type;
  if (req.url === '/dashboard/metrics') {
    type = 'application/json; charset=utf-8';
    data = JSON.stringify({
      ...metrics.snapshot(),
      health:{ services: await serviceStatuses(), executor_connected:peerUp(), in_flight:inFlight() },
      system:hostInfo(),
    });
  } else {
    const asset = RESOURCES.get(req.url);
    if (!asset) { res.writeHead(404,dashboardHeaders('application/json')); return res.end(); }
    [data,type] = [await readFile(path.join(DIR,asset[0])),asset[1]];
  }
  res.writeHead(200, dashboardHeaders(type));
  res.end(req.method === 'HEAD'?undefined:data);
}
