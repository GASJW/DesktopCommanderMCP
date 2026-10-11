import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync, sign} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import vm from 'node:vm';
import {createDashboardMetrics} from '../dashboard/metrics.mjs';
import {startGateway} from '../server.mjs';

const fixture=path.join(path.dirname(fileURLToPath(import.meta.url)),'fixtures/mock-executor.mjs');
const issuer='https://dashboard.cloudflareaccess.com',audience='b'.repeat(64),email='owner@example.test';
const pair=generateKeyPairSync('rsa',{modulusLength:2048});
const jwk={...pair.publicKey.export({format:'jwk'}),kid:'dashboard-key',use:'sig',alg:'RS256'};
function token(claims={}) {
  const t=Math.floor(Date.now()/1000);
  const h=Buffer.from(JSON.stringify({alg:'RS256',kid:jwk.kid})).toString('base64url');
  const p=Buffer.from(JSON.stringify({iss:issuer,aud:audience,sub:'owner-sub',email,iat:t,exp:t+1000,...claims})).toString('base64url');
  return h+'.'+p+'.'+sign('RSA-SHA256',Buffer.from(h+'.'+p),pair.privateKey).toString('base64url');
}
const events=[];
const opts={authMode:'access',accessIssuer:issuer,accessAudience:audience,
  allowedEmails:email,accessKeyProvider:async()=>({keys:[jwk]}),
  executorFile:fixture,port:0,auditEnabled:true,auditSink:line=>events.push(JSON.parse(line))};

function makeElement(id='') {
  const classes=new Set();
  const attributes=new Map();
  const element={id,className:'',textContent:'',hidden:false,disabled:false,title:'',style:{},dataset:{},children:[],parentElement:null,
    classList:{toggle(name,force){if(force)classes.add(name);else classes.delete(name);},add(name){classes.add(name);},contains(name){return classes.has(name);}},
    append(...items){for(const item of items){item.parentElement=this;this.children.push(item);}},
    replaceChildren(...items){this.children=[];this.append(...items);},
    setAttribute(key,value){attributes.set(key,String(value));},getAttribute(key){return attributes.get(key)??null;},removeAttribute(key){attributes.delete(key);},
    addEventListener(type,handler){this['on'+type]=handler;},click(){this.onclick?.({target:this});},
    querySelector(selector){if(selector==='span')return this.children.find(child=>child.tagName==='SPAN')??null;return null;},
    getBoundingClientRect(){return {width:760,height:250};},
    getContext(){return {scale(){},clearRect(){},beginPath(){},moveTo(){},lineTo(){},stroke(){},fillText(){},fillRect(){}};},
    set innerHTML(_value){this.children=[];},
  };
  element.tagName=id==='activity-chart'?'CANVAS':'';
  return element;
}

const emptyMetrics=()=>({since:'2026-10-11T08:00:00.000Z',updated_at:'2026-10-11T11:00:00.000Z',uptime_seconds:4,
  totals:{requests:0,mcp:0,tools:0,ok:0,errors:0,denied:0,busy:0},latency:{p50_ms:null,p95_ms:null},
  minutes:Array.from({length:60},(_,minute)=>({minute,calls:0,errors:0,denied:0})),top_tools:[],
  clients:{active_15m:0,recent:[]},health:{services:{gateway:'active',executor:'active',tunnel_commander:'active',tunnel_cofre:'active'},executor_connected:true,in_flight:0},
  system:{device:{id:'vps-gui',name:'gui',type:'VPS',inventory_count:1,caveat:'Este MCP opera em um host.'},
    ram:{total_bytes:17179869184,available_bytes:8589934592},load_1m:0,disk:{used_percent:30}}});

const dashboardSource=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../dashboard');
const dashboardHtml=await readFile(path.join(dashboardSource,'index.html'),'utf8');
const dashboardScript=await readFile(path.join(dashboardSource,'app.js'),'utf8');
async function renderDashboard(payload,{fail=false,failAfter=false}={}) {
  const elements=new Map([...dashboardHtml.matchAll(/\bid="([^"]+)"/g)].map(([,id])=>{
    const match=dashboardHtml.match(new RegExp(`<[^>]+\\bid="${id}"[^>]*>([^<]*)`));
    const element=makeElement(id);
    if(match)element.textContent=match[1];
    return [id,element];
  }));
  for(const id of ['memory-meter','disk-meter'])elements.get(id).append(Object.assign(makeElement(),{tagName:'SPAN'}));
  const document={hidden:false,
    getElementById:id=>elements.get(id)??null,
    createElement:tag=>Object.assign(makeElement(),{tagName:tag.toUpperCase()}),
    addEventListener(){},
  };
  document.querySelector=selector=>{
    if(selector.startsWith('#'))return elements.get(selector.slice(1))??null;
    if(selector==='.tool-row .tool-name')return [...elements.values()].flatMap(node=>node.children??[]).flatMap(node=>node.children??[]).find(node=>node.className==='tool-name')??null;
    return null;
  };
  document.querySelectorAll=selector=>{
    if(selector==='.tool-row')return [...elements.values()].flatMap(node=>node.children??[]).filter(node=>node.className==='tool-row');
    if(selector.includes('[data-service="tunnel_commander"]'))return elements.get('services-commander')?.children.find(row=>row.dataset.service==='tunnel_commander')?.children.filter(child=>child.className==='service-state')??[];
    return [];
  };
  let fetchCount=0;
  const context={document,window:{devicePixelRatio:1,addEventListener(){}},Intl,Date,Math,Number,String,Array,Map,Set,AbortController,
    setTimeout,clearTimeout,setInterval(){},fetch:async()=>{fetchCount++;return fail||(failAfter&&fetchCount>1)?{ok:false,status:503}:{ok:true,json:async()=>payload};}};
  vm.runInNewContext(dashboardScript,context,{filename:'gateway/dashboard/app.js'});
  await new Promise(resolve=>setImmediate(resolve));
  return {document,elements};
}
test('Dashboard metrics only store safe aggregates and exclude dashboard polling',()=>{
  let tick=Date.UTC(2026,9,11,10,0,0);
  const store=createDashboardMetrics({now:()=>tick});
  store.record({event:'vps_commander_audit',route:'mcp',operation:'tools/call',tool:'start_process',
    identity:'cf_'+'a'.repeat(24),duration_ms:25,outcome:'ok'});
  store.record({event:'vps_commander_audit',route:'mcp',operation:'tools/call',tool:'start_process',
    identity:'cf_'+'a'.repeat(24),duration_ms:70,outcome:'tool_error'});
  store.record({event:'vps_commander_audit',route:'mcp',operation:'tools/call',tool:'../bad',
    identity:'anonymous',duration_ms:0,outcome:'denied'});
  store.record({event:'vps_commander_audit',route:'dashboard',operation:'unknown',outcome:'ok'});
  const data=store.snapshot();
  assert.equal(data.totals.mcp,3);
  assert.equal(data.totals.requests,4);
  assert.equal(data.totals.tools,3);
  assert.equal(data.totals.errors,1);
  assert.equal(data.totals.denied,1);
  assert.equal(data.clients.active_15m,1);
  assert.equal(data.top_tools[0].name,'start_process');
  assert.equal(data.top_tools[0].calls,2);
  assert.equal(data.minutes.at(-1).calls,3);
  assert.equal(data.latency.p95_ms,70);
  assert.doesNotMatch(JSON.stringify(data),/cf_aaaaaaaa|Bearer |email|token|secret|command/);
  tick+=16*60*1000;
  assert.equal(store.snapshot().clients.active_15m,0);
});
test('Dashboard requires real signed owner Access JWT; serves only known routes',async()=>{
  const gw=await startGateway(opts);
  const go=async(route='/dashboard',headers={},method='GET')=>fetch(gw.address+route,{method,
    headers:{'cf-access-jwt-assertion':token(),...headers}});
  try {
    assert.equal((await fetch(gw.address+'/dashboard')).status,401);
    assert.equal((await go('/dashboard',{'cf-access-jwt-assertion':token({email:'intruder@example.test'})})).status,401);
    const home=await go();
    assert.equal(home.status,200);
    assert.match(await home.text(),/Commander/);
    assert.match(home.headers.get('content-security-policy'),/default-src 'none'/);
    assert.match(home.headers.get('cache-control'),/no-store/);
    for(const item of ['/dashboard/app.js','/dashboard/style.css']) {
      const res=await go(item);assert.equal(res.status,200);assert.ok((await res.text()).length>100);
    }
    const metrics=await go('/dashboard/metrics');
    assert.equal(metrics.status,200);
    const data=await metrics.json();
    assert.equal(data.system.device.type,'VPS');
    assert.equal(data.system.device.inventory_count,1);
    assert.equal(typeof data.health.executor_connected,'boolean');
    assert.equal(typeof data.clients.active_15m,'number');
    assert.equal(data.totals.mcp,0);
    assert.equal((await go('/dashboard/metrics',{},'POST')).status,405);
    assert.equal((await go('/dashboard/metrics',{origin:'https://evil.test'})).status,403);
    assert.equal((await go('/dashboard/../../etc/passwd')).status,404);
    assert.equal((await go('/dashboard/metrics?verbose=true')).status,404);
    assert.ok(events.every(e=>!JSON.stringify(e).includes('owner@example.test')));
    const rpc=await fetch(gw.address+'/mcp',{method:'POST',headers:{
      'cf-access-jwt-assertion':token(),'content-type':'application/json'},
      body:JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/list'})});
    assert.equal(rpc.status,200);
    await new Promise(r=>setTimeout(r,15));
    const last=(await (await go('/dashboard/metrics')).json());
    assert.equal(last.totals.mcp,1);
    assert.equal(last.clients.active_15m,1);
    assert.ok(last.top_tools.length===0);
    assert.ok(events.some(e=>e.route==='dashboard'));
  } finally { await gw.close(); }
});
test('Dashboard unavailable in legacy local bearer mode, including valid local bearer',async()=>{
  const gw=await startGateway({authMode:'local',token:'x'.repeat(48),executorFile:fixture,port:0});
  try {
    const res=await fetch(gw.address+'/dashboard',{headers:{authorization:'Bearer '+'x'.repeat(48)}});
    assert.equal(res.status,404);
  } finally { await gw.close(); }
});

test('Dashboard renders an empty restart state without invented volume or identities',async()=>{
  const {document}=await renderDashboard(emptyMetrics());
  assert.equal(document.getElementById('metric-calls').textContent,'0');
  assert.match(document.getElementById('activity-empty').textContent,/nenhuma chamada/i);
  assert.match(document.getElementById('tools-empty').textContent,/nenhuma chamada/i);
  assert.match(document.getElementById('uptime-context').textContent,/Uptime do Gateway/i);
  assert.equal(document.getElementById('identities-list').children[0].textContent,'Nenhuma identidade recente.');
  assert.equal(document.getElementById('activity-table').children.length,60);
});

test('Dashboard renders a small number of calls with the same chart scale and context',async()=>{
  const data=emptyMetrics();
  data.totals.mcp=2;
  data.totals.ok=2;
  data.latency.p95_ms=11;
  data.minutes[59]={minute:59,calls:2,errors:0,denied:0};
  data.top_tools=[{name:'tools_list',calls:2}];
  const {document}=await renderDashboard(data);
  assert.equal(document.getElementById('requests-60').textContent,'2 chamadas');
  assert.equal(document.getElementById('activity-empty').hidden,true);
  assert.equal(document.getElementById('activity-table').children.at(-1).children[1].textContent,'2');
  assert.equal(document.getElementById('tools-empty').hidden,true);
});

test('Dashboard renders high volume, long tool names, skewed latency and uncertain health without equating identities to devices',async()=>{
  const data=emptyMetrics();
  data.totals={requests:1400,mcp:1376,tools:1200,ok:1328,errors:36,denied:12,busy:4};
  data.latency={p50_ms:42,p95_ms:178000};
  data.top_tools=[{name:'start_process',calls:980},{name:'read_file_with_a_deliberately_long_tool_name_for_small_screens',calls:140}];
  data.minutes[57]={minute:57,calls:600,errors:0,denied:0};
  data.minutes[59]={minute:59,calls:720,errors:18,denied:4};
  data.health.services.tunnel_commander='unknown';
  data.health.services.tunnel_cofre='inactive';
  data.health.in_flight=2;
  data.clients={active_15m:1,recent:[{id:'client-a1b2c3d4',calls:120,last_seen:'2026-10-11T10:59:59.000Z'}]};
  data.system.ram.available_bytes=2147483648;
  data.system.load_1m=3.25;
  data.system.disk.used_percent=91;
  const {document}=await renderDashboard(data);
  assert.equal(document.getElementById('metric-calls').textContent,'1.376');
  assert.equal(document.getElementById('metric-p95').textContent,'178.000 ms');
  assert.equal(document.getElementById('tools-list').children.length,2);
  assert.equal(document.querySelector('.tool-row .tool-name').textContent,data.top_tools[0].name);
  assert.equal(document.querySelectorAll('[data-service="tunnel_commander"] .service-state')[0].textContent,'Não verificado');
  assert.match(document.getElementById('external-health').textContent,/não observada/i);
  assert.match(document.getElementById('managed-device-copy').textContent,/Host do Gateway e dispositivo do Executor local/i);
  assert.match(dashboardHtml,/Identidades MCP recentes/i);
  assert.match(document.getElementById('attention-summary').textContent,/18 falhas/);
  assert.match(document.getElementById('attention-summary').textContent,/4 recusas/);
  assert.doesNotMatch(document.getElementById('attention-summary').textContent,/inativa/);
  assert.match(document.getElementById('attention-detail').textContent,/90%/);
  assert.match(document.getElementById('attention-summary').textContent,/Disco raiz acima da referência de 90%/);
  assert.match(document.getElementById('memory-text').textContent,/13% livre/);
  assert.match(document.getElementById('chart-summary').textContent,/Pico de 720\/min/);
  assert.equal(document.getElementById('identities-list').children[0].children[0].textContent,'client-a1b2c3d4');
  assert.match(dashboardHtml,/não representa dispositivos físicos online/i);
});

test('Dashboard shows a clear first-load error and marks a failed refresh as stale',async()=>{
  const failed=await renderDashboard(emptyMetrics(),{fail:true});
  assert.match(failed.document.getElementById('load-error').textContent,/não foi possível atualizar/i);
  assert.equal(failed.document.getElementById('metric-calls').textContent,'—');
  const stale=await renderDashboard(emptyMetrics(),{failAfter:true});
  stale.document.getElementById('refresh').click();
  await new Promise(resolve=>setImmediate(resolve));
  assert.match(stale.document.getElementById('load-error').textContent,/atualização indisponível/i);
  assert.match(stale.document.getElementById('load-error').textContent,/última leitura/i);
  assert.equal(stale.document.getElementById('metric-calls').textContent,'0');
});

test('Dashboard labels unavailable resource readings instead of inventing values',async()=>{
  const data=emptyMetrics();
  data.system.ram=null;
  data.system.disk=null;
  data.system.load_1m=null;
  const {document}=await renderDashboard(data);
  assert.equal(document.getElementById('memory-text').textContent,'Sem leitura disponível');
  assert.equal(document.getElementById('disk-text').textContent,'Sem leitura disponível');
  assert.equal(document.getElementById('load-text').textContent,'Sem leitura disponível');
  assert.doesNotMatch(document.getElementById('attention-summary').textContent,/90%/);
});
