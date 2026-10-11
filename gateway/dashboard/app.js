'use strict';
const $ = id => document.getElementById(id);
const number = new Intl.NumberFormat('pt-BR');
const decimal = new Intl.NumberFormat('pt-BR', {maximumFractionDigits: 1});
const formatCount = value => Number.isFinite(value) ? number.format(value) : '—';
const formatTime = value => {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleTimeString('pt-BR', {hour:'2-digit', minute:'2-digit'});
};
const formatDuration = seconds => {
  if (!Number.isFinite(seconds) || seconds < 0) return '—';
  if (seconds < 60) return Math.floor(seconds) + ' s';
  if (seconds < 3600) return Math.floor(seconds / 60) + ' min';
  const hours = Math.floor(seconds / 3600);
  return hours < 24 ? hours + ' h ' + Math.floor(seconds % 3600 / 60) + ' min'
    : Math.floor(hours / 24) + ' d ' + hours % 24 + ' h';
};
const setText = (id, value) => { const element = $(id); if (element) element.textContent = String(value); };

let latest = null;
let fetching = false;
let redrawChart = () => {};

const serviceNames = {
  gateway: 'Gateway MCP',
  executor: 'Executor local',
  tunnel_commander: 'Túnel Commander',
  tunnel_cofre: 'Túnel Cofre',
};

function serviceState(value) {
  if (value === 'active') return ['active', 'Ativa'];
  if (value === 'inactive') return ['inactive', 'Inativa'];
  return ['unknown', 'Não verificado'];
}

function renderServices(services = {}) {
  const commander = $('services-commander');
  const cofre = $('services-cofre');
  commander.replaceChildren();
  cofre.replaceChildren();
  for (const key of ['gateway', 'executor', 'tunnel_commander', 'tunnel_cofre']) {
    const [state, label] = serviceState(services[key]);
    const row = document.createElement('div');
    row.className = 'service-row';
    row.dataset.service = key;
    const name = document.createElement('span');
    name.className = 'service-name';
    name.textContent = serviceNames[key];
    const status = document.createElement('span');
    status.className = 'service-state';
    status.dataset.state = state;
    status.textContent = label;
    row.append(name, status);
    (key === 'tunnel_cofre' ? cofre : commander).append(row);
  }
}

function renderTools(tools = []) {
  const list = $('tools-list');
  const empty = $('tools-empty');
  list.replaceChildren();
  empty.hidden = tools.length > 0;
  for (const tool of tools) {
    const row = document.createElement('div');
    row.className = 'tool-row';
    const name = document.createElement('span');
    name.className = 'tool-name';
    name.textContent = tool.name;
    name.title = tool.name;
    const count = document.createElement('strong');
    count.className = 'tool-count';
    count.textContent = formatCount(tool.calls);
    const track = document.createElement('div');
    track.className = 'bar-track';
    const fill = document.createElement('div');
    fill.className = 'bar-fill';
    const max = Math.max(1, ...tools.map(item => Number.isFinite(item.calls) ? item.calls : 0));
    fill.style.width = Math.max(1, (tool.calls / max) * 100) + '%';
    track.append(fill);
    row.append(name, count, track);
    list.append(row);
  }
}

function setMeter(id, percent) {
  const meter = $(id);
  const fill = meter.querySelector('span');
  const valid = Number.isFinite(percent) && percent >= 0;
  if (!valid) {
    fill.style.width = '0%';
    meter.removeAttribute('aria-valuenow');
    return;
  }
  const bounded = Math.min(100, percent);
  fill.style.width = bounded + '%';
  meter.setAttribute('aria-valuenow', String(Math.round(bounded)));
}

function renderMemory(ram) {
  const total = ram?.total_bytes;
  const available = ram?.available_bytes;
  if (!Number.isFinite(total) || total <= 0 || !Number.isFinite(available) || available < 0) {
    setText('memory-text', 'Sem leitura disponível');
    $('memory-resource').removeAttribute('data-level');
    setMeter('memory-meter', null);
    return;
  }
  const free = Math.min(total, available);
  const percent = Math.min(100, (free / total) * 100);
  const gib = bytes => decimal.format(bytes / 1024 ** 3) + ' GiB';
  setText('memory-text', Math.round(percent) + '% livre · ' + gib(free) + ' de ' + gib(total));
  $('memory-resource').removeAttribute('data-level');
  setMeter('memory-meter', percent);
}

function renderDisk(disk) {
  const percent = disk?.used_percent;
  if (!Number.isFinite(percent) || percent < 0) {
    setText('disk-text', 'Sem leitura disponível');
    $('disk-resource').removeAttribute('data-level');
    setMeter('disk-meter', null);
    return;
  }
  setText('disk-text', Math.round(percent) + '% usado');
  $('disk-resource').dataset.level = percent >= 90 ? 'high' : 'normal';
  setMeter('disk-meter', percent);
}

function renderIdentities(clients = {}) {
  const rows = Array.isArray(clients.recent) ? clients.recent : [];
  const list = $('identities-list');
  list.replaceChildren();
  setText('active-identities', formatCount(clients.active_15m) + ' ativas');
  setText('metric-identities', formatCount(clients.active_15m));
  if (!rows.length) {
    const empty = document.createElement('p');
    empty.className = 'empty-copy';
    empty.textContent = 'Nenhuma identidade recente.';
    list.append(empty);
    return;
  }
  for (const item of rows) {
    const row = document.createElement('div');
    row.className = 'identity-row';
    const id = document.createElement('strong');
    id.textContent = item.id;
    const detail = document.createElement('span');
    detail.textContent = formatCount(item.calls) + ' chamadas · ' + formatTime(item.last_seen);
    row.append(id, detail);
    list.append(row);
  }
}

function renderAttention(data) {
  const minutes = Array.isArray(data.minutes) ? data.minutes : [];
  const errors = minutes.reduce((sum, item) => sum + (Number.isFinite(item.errors) ? item.errors : 0), 0);
  const denied = minutes.reduce((sum, item) => sum + (Number.isFinite(item.denied) ? item.denied : 0), 0);
  const states = data.health?.services ?? {};
  const commanderStates = ['gateway', 'executor', 'tunnel_commander'].map(key => states[key]);
  const inactive = commanderStates.filter(value => value === 'inactive').length;
  const unknown = commanderStates.filter(value => value !== 'active' && value !== 'inactive').length;
  const details = [];
  if (errors + denied) details.push(formatCount(errors) + ' falhas · ' + formatCount(denied) + ' recusas na última hora');
  if (inactive) details.push(formatCount(inactive) + ' unidade(s) inativa(s)');
  if (unknown) details.push(formatCount(unknown) + ' unidade(s) não verificadas');
  if (data.health?.executor_connected === false) details.push('Executor sem conexão local');
  const diskHigh = $('disk-resource').dataset.level === 'high';
  const context = ['A janela considera chamadas MCP dos últimos 60 minutos e estados locais observáveis.'];
  if (diskHigh) context.push('Disco raiz acima da referência visual de 90%.');
  if (diskHigh) details.push('Disco raiz acima da referência de 90%');
  if (!details.length) details.push('Nenhuma falha ou indisponibilidade observada na janela.');
  setText('attention-summary', details.join(' · '));
  setText('attention-detail', context.join(' '));
}

function drawActivity(minutes) {
  const canvas = $('activity-chart');
  const rect = canvas.getBoundingClientRect();
  if (!rect.width || !rect.height) return;
  const points = Array.isArray(minutes) ? minutes.slice(-60) : [];
  while (points.length < 60) points.unshift({calls: 0, errors: 0});
  const calls = points.reduce((sum, point) => sum + (Number.isFinite(point.calls) ? point.calls : 0), 0);
  const failures = points.reduce((sum, point) => sum + (Number.isFinite(point.errors) ? point.errors : 0), 0);
  const peak = Math.max(0, ...points.map(point => Number.isFinite(point.calls) ? point.calls : 0));
  const ratio = Math.min(2, window.devicePixelRatio || 1);
  canvas.width = Math.round(rect.width * ratio);
  canvas.height = Math.round(rect.height * ratio);
  const context = canvas.getContext('2d');
  if (!context) return;
  context.scale(ratio, ratio);
  const width = rect.width;
  const height = rect.height;
  const left = 34, right = 5, top = 8, bottom = 23;
  const plotWidth = width - left - right;
  const plotHeight = height - top - bottom;
  const scalePeak = Math.max(1, peak);
  context.clearRect(0, 0, width, height);
  context.font = '10px -apple-system, BlinkMacSystemFont, sans-serif';
  context.textAlign = 'right';
  for (let step = 0; step <= 4; step++) {
    const y = top + plotHeight * step / 4;
    context.strokeStyle = '#2a333b';
    context.lineWidth = 1;
    context.beginPath();
    context.moveTo(left, y);
    context.lineTo(width - right, y);
    context.stroke();
    context.fillStyle = '#78858e';
    context.fillText(formatCount(Math.round(scalePeak * (4 - step) / 4)), left - 7, y + 3);
  }
  const slot = plotWidth / points.length;
  const barWidth = Math.max(1, slot * .62);
  for (let index = 0; index < points.length; index++) {
    const point = points[index];
    const value = Number.isFinite(point.calls) ? Math.max(0, point.calls) : 0;
    const barHeight = value ? Math.max(1.5, value / scalePeak * plotHeight) : 0;
    const x = left + index * slot + (slot - barWidth) / 2;
    if (barHeight) {
      context.fillStyle = '#91bed2';
      context.fillRect(x, top + plotHeight - barHeight, barWidth, barHeight);
      const failed = Number.isFinite(point.errors) ? Math.min(value, Math.max(0, point.errors)) : 0;
      if (failed) {
        const errorHeight = Math.max(1.5, failed / scalePeak * plotHeight);
        context.fillStyle = '#dd8b83';
        context.fillRect(x, top + plotHeight - barHeight, barWidth, Math.min(barHeight, errorHeight));
      }
    }
  }
  context.fillStyle = '#78858e';
  context.textAlign = 'left';
  context.fillText('−60 min', left, height - 3);
  context.textAlign = 'center';
  context.fillText('−30 min', left + plotWidth / 2, height - 3);
  context.textAlign = 'right';
  context.fillText('agora', width - right, height - 3);
  $('activity-empty').hidden = calls > 0;
  setText('chart-summary', calls
    ? 'Pico de ' + formatCount(peak) + '/min · ' + formatCount(failures) + ' falhas · totais reiniciam com o Gateway.'
    : 'Sem atividade · totais reiniciam com o Gateway.');
  canvas.setAttribute('aria-label', calls
    ? formatCount(calls) + ' chamadas MCP nos últimos 60 minutos, pico de ' + formatCount(peak) + ' por minuto e ' + formatCount(failures) + ' falhas.'
    : 'Nenhuma chamada MCP nos últimos 60 minutos.');
  const table = $('activity-table');
  table.replaceChildren();
  for (let index = 0; index < points.length; index++) {
    const point = points[index];
    const row = document.createElement('tr');
    const values = [index === points.length - 1 ? 'Agora' : '−' + (points.length - 1 - index) + ' min',
      formatCount(point.calls), formatCount(point.errors), formatCount(point.denied)];
    for (const value of values) {
      const cell = document.createElement('td');
      cell.textContent = value;
      row.append(cell);
    }
    table.append(row);
  }
  setText('requests-60', formatCount(calls) + ' chamadas');
}

function paint(data) {
  const totals = data.totals ?? {};
  const services = data.health?.services ?? {};
  const [gatewayState] = serviceState(services.gateway);
  const connection = $('connection-state');
  const connected = data.health?.executor_connected === true;
  connection.dataset.state = !connected ? 'offline' : gatewayState === 'active' ? 'ok' : 'attention';
  setText('connection-label', connected ? 'Executor conectado' : 'Executor sem conexão');
  setText('metric-calls', formatCount(totals.mcp));
  const success = Number.isFinite(totals.mcp) && totals.mcp > 0 && Number.isFinite(totals.ok)
    ? totals.ok / totals.mcp * 100 : null;
  setText('metric-success', success === null ? '—' : decimal.format(success) + '%');
  setText('metric-success-context', totals.mcp > 0
    ? formatCount(totals.ok) + ' de ' + formatCount(totals.mcp) + ' chamadas concluídas'
    : 'Sem chamadas desde a inicialização');
  setText('metric-p95', Number.isFinite(data.latency?.p95_ms) ? formatCount(data.latency.p95_ms) + ' ms' : '—');
  setText('footer-updated', 'Última leitura às ' + formatTime(data.updated_at));
  setText('uptime-context', 'Uptime do Gateway: ' + formatDuration(data.uptime_seconds));
  setText('gateway-role-state', gatewayState === 'active' ? 'Unidade local: ativa'
    : gatewayState === 'inactive' ? 'Unidade local: inativa' : 'Unidade local: não verificada');
  const executorRole = $('executor-role-state');
  executorRole.textContent = connected ? 'Conexão local: confirmada' : 'Conexão local: indisponível';
  executorRole.dataset.state = connected ? 'active' : 'offline';
  renderServices(services);
  renderTools(Array.isArray(data.top_tools) ? data.top_tools : []);
  renderMemory(data.system?.ram);
  renderDisk(data.system?.disk);
  setText('load-text', Number.isFinite(data.system?.load_1m) ? decimal.format(data.system.load_1m) : 'Sem leitura disponível');
  setText('inflight-text', Number.isFinite(data.health?.in_flight) ? formatCount(data.health.in_flight) : '—');
  const device = data.system?.device ?? {};
  setText('device-name', device.name || 'Host não identificado');
  setText('device-type', device.type || 'Tipo não informado');
  if (device.caveat) setText('device-caveat', device.caveat + ' Nenhum outro computador aparece sem evidência de inventário ou conexão.');
  renderIdentities(data.clients);
  renderAttention(data);
  redrawChart = () => drawActivity(data.minutes);
  redrawChart();
  $('load-error').hidden = true;
}

async function refresh() {
  if (fetching) return;
  fetching = true;
  $('refresh').disabled = true;
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 6500);
    let response;
    try {
      response = await fetch('/dashboard/metrics', {
        cache: 'no-store', credentials: 'same-origin', signal: controller.signal,
        headers: {accept: 'application/json'},
      });
    } finally { clearTimeout(timeout); }
    if (!response.ok) throw new Error('metrics unavailable');
    const data = await response.json();
    paint(data);
    latest = data;
  } catch {
    const alert = $('load-error');
    alert.classList.toggle('is-error', !latest);
    alert.textContent = latest
      ? 'Atualização indisponível. A última leitura, de ' + formatTime(latest.updated_at) + ', permanece exibida.'
      : 'Não foi possível atualizar as métricas. Verifique a conexão e tente novamente.';
    alert.hidden = false;
  } finally {
    fetching = false;
    $('refresh').disabled = false;
  }
}

$('refresh').addEventListener('click', refresh);
window.addEventListener('resize', () => redrawChart(), {passive: true});
document.addEventListener('visibilitychange', () => { if (!document.hidden) refresh(); });
refresh();
setInterval(() => { if (!document.hidden) refresh(); }, 15000);
