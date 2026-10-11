'use strict';
const $ = id => document.getElementById(id);
const nf = new Intl.NumberFormat('pt-BR');
const compact = n => typeof n === 'number' && Number.isFinite(n) ? nf.format(n) : '—';
const time = value => {try{return new Date(value).toLocaleTimeString('pt-BR',{hour:'2-digit',minute:'2-digit',second:'2-digit'});}catch{return '—';}};
const duration = secs => {
  if (!Number.isFinite(secs)) return '—';
  if (secs < 60) return Math.floor(secs)+'s';
  if (secs < 3600) return Math.floor(secs/60)+'min';
  const h=Math.floor(secs/3600);return h < 24 ? h+'h '+Math.floor((secs%3600)/60)+'min' : Math.floor(h/24)+'d '+(h%24)+'h';
};
const set = (id,v) => {const e=$(id);if(e)e.textContent=String(v);};
let lastPayload=null, fetching=false;
let redraw=()=>{};
const serviceLabels = {
  gateway:['Gateway MCP','HTTP · autenticação Access','⬡'],
  executor:['Executor isolado','Socket Unix · usuário restrito','◈'],
  tunnel_commander:['Cloudflare Commander','Unidade systemd · túnel MCP','↗'],
  tunnel_cofre:['Cloudflare Cofre','Túnel independente (somente leitura)','⌁'],
};
function statusBadge(status) {
  const e=document.createElement('span');
  e.className='svc-badge'+(status==='active'?'':status==='inactive'?' bad':' unknown');
  e.textContent=status==='active'?'● Unidade ativa':status==='inactive'?'● Parado':'● Não verificado';
  return e;
}
function paintServices(data) {
  const host=$('services');host.replaceChildren();
  for(const [key,[title,desc,icon]] of Object.entries(serviceLabels)) {
    const row=document.createElement('div');row.className='service-row';
    const ico=document.createElement('span');ico.className='svc-icon';ico.textContent=icon;
    const middle=document.createElement('div');
    const a=document.createElement('div');a.className='service-name';a.textContent=title;
    const b=document.createElement('div');b.className='service-desc';b.textContent=desc;
    middle.append(a,b);row.append(ico,middle,statusBadge(data?.[key]??'unknown'));host.append(row);
  }
}
function paintTools(tools) {
  const parent=$('tools-list');parent.replaceChildren();
  if(!tools.length){const e=document.createElement('p');e.className='empty-state';e.textContent='Aguardando chamadas de ferramentas. O histórico inicia com o gateway.';parent.append(e);return;}
  const max=Math.max(1,...tools.map(x=>x.calls));
  for(const tool of tools) {
    const row=document.createElement('div');row.className='tool-row';
    const name=document.createElement('span');name.className='name';name.textContent=tool.name;
    const track=document.createElement('div');track.className='bar-track';
    const fill=document.createElement('div');fill.className='bar-fill';fill.style.width=Math.max(3,tool.calls/max*100)+'%';track.append(fill);
    const value=document.createElement('strong');value.className='tool-count';value.textContent=compact(tool.calls);
    row.append(name,track,value);parent.append(row);
  }
}
function meter(id,pct) {
  const bar=$(id), track=bar?.parentElement;
  if(!bar)return;
  const valid=Number.isFinite(pct) && pct>=0 && pct<=100;
  bar.style.width=(valid?pct:0)+'%';
  track.classList.toggle('warn',valid&&pct>=85);
}
function paintClients(data) {
  set('device-name',data.system?.device?.name||'gui');
  set('device-state',data.health?.executor_connected?'● Executor conectado':'● Executor sem confirmação');
  set('active-identities',compact(data.clients?.active_15m));
  const list=$('identity-list');list.replaceChildren();
  if(!data.clients?.recent?.length){const e=document.createElement('span');e.textContent='Nenhum acesso autenticado recente registrado.';list.append(e);return;}
  for(const item of data.clients.recent) {
    const line=document.createElement('span');
    line.textContent=item.id+' · '+compact(item.calls)+' chamadas · '+time(item.last_seen);
    list.append(line);
  }
}
function drawActivity(minutes) {
  const canvas=$('activity-chart');if(!canvas)return;
  const rect=canvas.getBoundingClientRect();if(!rect.width||!rect.height)return;
  const ratio=Math.min(2,window.devicePixelRatio||1);
  canvas.width=Math.round(rect.width*ratio);canvas.height=Math.round(rect.height*ratio);
  const ctx=canvas.getContext('2d');ctx.scale(ratio,ratio);
  const W=rect.width,H=rect.height,left=35,right=6,top=9,bottom=25,plotW=W-left-right,plotH=H-top-bottom;
  ctx.clearRect(0,0,W,H);
  const peak=Math.max(1,...minutes.map(p=>p.calls));
  ctx.font='10px ui-sans-serif, system-ui';ctx.textAlign='right';
  for(let i=0;i<=4;i++){
    const y=top+plotH*i/4;
    ctx.strokeStyle='#253744';ctx.lineWidth=1;ctx.beginPath();ctx.moveTo(left,y);ctx.lineTo(W-right,y);ctx.stroke();
    ctx.fillStyle='#718697';ctx.fillText(String(Math.round(peak*(4-i)/4)),left-9,y+3);
  }
  const gap=plotW/60,width=Math.max(1.5,gap*.61);
  for(let i=0;i<minutes.length;i++){
    const m=minutes[i],x=left+i*gap+gap*.2;
    const barH=Math.max(m.calls?2:0,(m.calls/peak)*plotH);
    ctx.fillStyle='#4fdcc7';ctx.fillRect(x,top+plotH-barH,width,barH);
    if(m.errors){const errH=Math.min(barH,m.errors/peak*plotH);ctx.fillStyle='#fa7783';ctx.fillRect(x,top+plotH-barH,width,Math.max(2,errH));}
  }
  ctx.textAlign='left';ctx.fillStyle='#7893a4';ctx.fillText('−60 min',left,H-4);
  ctx.textAlign='center';ctx.fillText('−30 min',left+plotW/2,H-4);
  ctx.textAlign='right';ctx.fillText('agora',W-right,H-4);
  $('chart-empty').classList.toggle('hidden',minutes.some(m=>m.calls>0));
}
function paint(d) {
  const totals=d.totals??{}, services=d.health?.services??{};
  const servicesUp=Object.values(services).every(x=>x==='active');
  const reachable=d.health?.executor_connected===true;
  $('connection-pill').classList.toggle('offline',!reachable);
  set('connection-label',reachable?'CONECTADO':'EXECUTOR INDISPONÍVEL');
  set('hero-status',reachable&&servicesUp?'Todos os serviços operacionais':reachable?'Serviços exigem atenção':'Executor indisponível');
  set('hero-sub',reachable?'Gateway conectado ao executor. Estados dos túneis verificados via systemd.':'A conexão com o executor não está disponível.');
  set('hero-host',d.system?.device?.name||'gui');
  set('hero-uptime',duration(d.uptime_seconds));
  set('kpi-calls',compact(totals.mcp));
  set('kpi-ok',compact(totals.ok));
  const success=totals.mcp?100*(totals.ok/totals.mcp):null;
  set('kpi-success',success===null?'—':success.toLocaleString('pt-BR',{maximumFractionDigits:1})+'%');
  set('kpi-latency',d.latency?.p95_ms==null?'—':compact(d.latency.p95_ms)+' ms');
  set('kpi-clients',compact(d.clients?.active_15m));
  const recentCalls=(d.minutes??[]).reduce((sum,x)=>sum+x.calls,0);
  set('requests-60',compact(recentCalls)+' chamadas na última hora');
  paintServices(services);
  paintTools(d.top_tools??[]);
  const ram=d.system?.ram;
  const memUsed=ram?.total_bytes>0?100*(1-ram.available_bytes/ram.total_bytes):null;
  set('memory-text',memUsed===null?'—':Math.round(memUsed)+'%');meter('memory-fill',memUsed);
  const disk=d.system?.disk?.used_percent;
  set('disk-text',disk==null?'—':disk+'%');meter('disk-fill',disk);
  set('load-text',Number.isFinite(d.system?.load_1m)?d.system.load_1m.toFixed(2):'—');
  set('inflight-text',compact(d.health?.in_flight)+' chamadas');
  paintClients(d);
  set('footer-updated','Atualizado às '+time(d.updated_at));
  redraw=()=>drawActivity(d.minutes??[]);
  redraw();
}
async function refresh() {
  if(fetching)return;
  fetching=true;$('refresh').disabled=true;
  const aborter=new AbortController(),timer=setTimeout(()=>aborter.abort(),6500);
  try {
    const response=await fetch('/dashboard/metrics',{cache:'no-store',credentials:'same-origin',signal:aborter.signal,headers:{accept:'application/json'}});
    if(!response.ok)throw new Error(response.status===401?'Autenticação expirada':'HTTP '+response.status);
    const data=await response.json();
    lastPayload=data;paint(data);
  } catch(error) {
    $('connection-pill').classList.add('offline');
    set('connection-label','SEM ATUALIZAÇÃO');
    set('footer-updated','Falha na atualização: '+(error?.message??'rede'));
    if(!lastPayload)set('hero-status','Não foi possível carregar métricas');
  } finally {clearTimeout(timer);fetching=false;$('refresh').disabled=false;}
}
$('refresh').addEventListener('click',refresh);
window.addEventListener('resize',()=>redraw(),{passive:true});
document.addEventListener('visibilitychange',()=>{if(!document.hidden)refresh();});
refresh();
setInterval(()=>{if(!document.hidden)refresh();},15000);
