import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { startGateway, matchesBearer } from '../server.mjs';

const dir = path.dirname(fileURLToPath(import.meta.url));
const mock = path.join(dir, 'fixtures', 'mock-executor.mjs');
const token = randomBytes(32).toString('hex');
const request = (id, method, params={}) => ({ jsonrpc:'2.0', id, method, params });
const post = (base, body, key=token, headers={}) => fetch(base + '/mcp', {
  method:'POST', headers: { authorization: 'Bearer ' + key, 'content-type': 'application/json', ...headers },
  body:JSON.stringify(body),
});
test('fail-closed secret and listen host', async () => {
  assert.equal(matchesBearer('Bearer '+token, token), true);
  assert.equal(matchesBearer('Bearer invalid', token), false);
  assert.equal(matchesBearer(undefined, token), false);
  await assert.rejects(startGateway({token:'short',executorFile:mock,port:0}), /32-4096/);
  await assert.rejects(startGateway({token,executorFile:mock,host:'0.0.0.0',port:0}), /Loopback/);
});
test('MCP init, tools and auth through HTTP-to-stdio', async () => {
  const app = await startGateway({token,executorFile:mock,port:0});
  try {
    const bad = await fetch(app.address + '/mcp', {method:'POST',headers:{'content-type':'application/json'},body:'{}'});
    assert.equal(bad.status,401);
    const hello = await post(app.address,request(1,'initialize',{ protocolVersion:'2025-03-26',capabilities:{},clientInfo:{name:'test',version:'0.1'}}));
    assert.equal(hello.status,200);
    assert.equal((await hello.json()).result.serverInfo.name,'vps-commander-gateway');
    const list = await post(app.address,request(2,'tools/list'));
    assert.equal((await list.json()).result.tools[0].name,'echo');
    const call = await post(app.address,request(3,'tools/call',{name:'echo',arguments:{text:'test passed'}}));
    assert.equal((await call.json()).result.content[0].text,'test passed');
    const secretCheck = await post(app.address,request(4,'tools/call',{name:'inspect-env',arguments:{}}));
    assert.equal((await secretCheck.json()).result.content[0].text,'NO_TOKEN');
    const concurrent = await Promise.all(Array.from({length:5},(_,i)=>post(app.address,request(i+10,'tools/call',{name:'echo',arguments:{text:'t'+i}}))));
    for (let i=0;i<5;i++) {
      const response = await concurrent[i].json();
      assert.equal(response.id,i+10);
      assert.equal(response.result.content[0].text,'t'+i);
    }
    assert.equal((await post(app.address,request(25,'tools/list'),'wrong')).status,401);
    assert.equal((await post(app.address,request(26,'tools/list'),token,{origin:'https://evil.example'})).status,403);
    const noGet = await fetch(app.address+'/mcp',{headers:{authorization:'Bearer '+token}});
    assert.equal(noGet.status,405);
    const health = await fetch(app.address+'/healthz',{headers:{authorization:'Bearer '+token}});
    assert.equal(health.status,200);
  } finally { await app.close(); }
});
