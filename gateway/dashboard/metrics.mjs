// In-process metrics, derived only from G3.2 sanitized audit entries.
// No raw JWT, email, commands, tool arguments or response bodies are stored.
const RETAIN_MINUTES = 120;
const MAX_LATENCIES = 512;
const CLIENT_TTL_MS = 15 * 60_000;
export function createDashboardMetrics({ now = () => Date.now() } = {}) {
  const start = now();
  const totals = { requests: 0, mcp: 0, tools: 0, ok: 0, errors: 0, denied: 0, busy: 0 };
  const buckets = new Map();
  const toolCounts = new Map();
  const clients = new Map();
  const latencies = [];
  const errorOutcomes = new Set(['tool_error', 'rpc_error', 'unavailable', 'disconnected', 'limit_exceeded']);
  function record(entry) {
    if (!entry || entry.event !== 'vps_commander_audit') return;
    totals.requests++;
    if (entry.route !== 'mcp') return; // Dashboard polling must not inflate MCP use.
    totals.mcp++;
    const minute = Math.floor(now() / 60_000) * 60_000;
    let bucket = buckets.get(minute);
    if (!bucket) { bucket = { minute, calls: 0, errors: 0, denied: 0 }; buckets.set(minute, bucket); }
    bucket.calls++;
    if (entry.outcome === 'ok') totals.ok++;
    if (errorOutcomes.has(entry.outcome)) { totals.errors++; bucket.errors++; }
    if (entry.outcome === 'denied') { totals.denied++; bucket.denied++; }
    if (entry.outcome === 'busy') totals.busy++;
    if (entry.operation === 'tools/call') {
      totals.tools++;
      if (/^[a-zA-Z][a-zA-Z0-9_-]{0,79}$/.test(entry.tool ?? '')) {
        const key = toolCounts.has(entry.tool) || toolCounts.size < 64 ? entry.tool : 'other';
        toolCounts.set(key, (toolCounts.get(key) ?? 0) + 1);
      }
    }
    if (typeof entry.identity === 'string' && /^cf_[a-f0-9]{24}$/.test(entry.identity)) {
      if (clients.has(entry.identity) || clients.size < 128)
        clients.set(entry.identity, { lastSeen: now(), calls: (clients.get(entry.identity)?.calls ?? 0) + 1 });
    }
    if (Number.isSafeInteger(entry.duration_ms) && entry.duration_ms >= 0 && entry.duration_ms <= 300_000) {
      latencies.push(entry.duration_ms);
      if (latencies.length > MAX_LATENCIES) latencies.shift();
    }
    prune();
  }
  function prune() {
    const cutoff = now() - RETAIN_MINUTES * 60_000;
    for (const key of buckets.keys()) if (key < cutoff) buckets.delete(key);
    // Do not retain client identifiers beyond the activity window.
    for (const [key, client] of clients) if (client.lastSeen < now() - CLIENT_TTL_MS) clients.delete(key);
  }
  function snapshot() {
    prune();
    const recent = [...latencies].sort((a,b) => a-b);
    const percentile = q => recent.length ? recent[Math.ceil(recent.length * q) - 1] : null;
    const currentMinute = Math.floor(now() / 60_000) * 60_000;
    const minutes = Array.from({length:60}, (_, index) => {
      const minute = currentMinute - (59-index) * 60_000;
      return buckets.get(minute) ?? {minute, calls:0, errors:0, denied:0};
    });
    const topTools = [...toolCounts.entries()].sort((a,b) => b[1]-a[1]).slice(0,8)
      .map(([name, calls]) => ({name, calls}));
    const activeClients = [...clients.entries()].map(([id, c]) => ({
      id: 'client-' + id.slice(-8), last_seen: new Date(c.lastSeen).toISOString(), calls: c.calls
    })).sort((a,b) => b.calls - a.calls);
    return {
      since: new Date(start).toISOString(),
      updated_at: new Date(now()).toISOString(),
      uptime_seconds: Math.round((now()-start)/1000),
      totals: {...totals},
      latency: { p50_ms: percentile(.50), p95_ms: percentile(.95) },
      minutes,
      top_tools: topTools,
      clients: { active_15m: activeClients.length, recent:activeClients.slice(0,8),
        caveat: 'Clientes MCP recentes; nao representam dispositivos fisicos.' },
      retention: { timeline_minutes: 60, ephemeral: true, source: 'Gateway audit G3.2' },
    };
  }
  return {record, snapshot};
}
