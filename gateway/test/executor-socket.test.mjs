import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync, statSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { startExecutor } from '../executor-socket.mjs';
import { startGateway } from '../server.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const fixture = path.join(here, 'fixtures', 'mock-executor.mjs');

test('isolated executor over Unix socket preserves MCP and strips gateway secret', async () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'vpsc-g3-'));
  const sock = path.join(dir, 'mcp.sock');
  const token = randomBytes(32).toString('hex');
  const oldToken = process.env.VPS_COMMANDER_TOKEN;
  process.env.VPS_COMMANDER_TOKEN = token;
  let worker, gateway;
  try {
    worker = await startExecutor({ socketPath: sock, executorFile: fixture });
    assert.equal(statSync(sock).mode & 0o777, 0o660);
    gateway = await startGateway({executorSocket:sock, authMode:'local', token, port:0});
    const post = async (id, method, params={}) => {
      const res=await fetch(gateway.address+'/mcp',{method:'POST',
        headers:{authorization:'Bearer '+token,'content-type':'application/json'},
        body:JSON.stringify({jsonrpc:'2.0',id,method,params})});
      assert.equal(res.status,200); return res.json();
    };
    const list = await post(1, 'tools/list');
    assert.equal(list.result.tools[0].name,'echo');
    const secret = await post(2,'tools/call',{name:'inspect-env',arguments:{}});
    assert.equal(secret.result.content[0].text,'NO_TOKEN');
    const echo = await post(3,'tools/call',{name:'echo',arguments:{text:'G3_IPC_GREEN'}});
    assert.equal(echo.result.content[0].text,'G3_IPC_GREEN');
  } finally {
    await gateway?.close(); await worker?.close();
    if (oldToken===undefined) delete process.env.VPS_COMMANDER_TOKEN;
    else process.env.VPS_COMMANDER_TOKEN=oldToken;
    rmSync(dir,{recursive:true,force:true});
  }
});

test('socket bootstrap refuses replacing regular files', async () => {
  const dir=mkdtempSync(path.join(os.tmpdir(), 'vpsc-g3-file-'));
  const dest=path.join(dir,'mcp.sock');
  try {
    const {writeFileSync}=await import('node:fs');
    writeFileSync(dest,'DO_NOT_REMOVE');
    await assert.rejects(startExecutor({socketPath:dest,executorFile:fixture}),/non-socket/);
    assert.equal((await import('node:fs')).readFileSync(dest,'utf8'),'DO_NOT_REMOVE');
  } finally {rmSync(dir,{recursive:true,force:true});}
});
