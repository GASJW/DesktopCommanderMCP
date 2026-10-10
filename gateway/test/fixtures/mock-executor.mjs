import { createInterface } from 'node:readline';
for await (const line of createInterface({ input: process.stdin })) {
  let request;
  try { request = JSON.parse(line); } catch { continue; }
  if (!Object.hasOwn(request, 'id')) continue;
  let result = {};
  if (request.method === 'initialize')
    result = { protocolVersion: '2025-03-26', capabilities: { tools: {} }, serverInfo: { name: 'mock', version: '0.1' } };
  else if (request.method === 'tools/list')
    result = { tools: [{ name: 'echo', description: 'Deterministic mock', inputSchema: { type: 'object', properties: { text: { type: 'string' } } } }] };
  else if (request.method === 'tools/call')
    result = { content: [{ type: 'text', text: String(request.params?.arguments?.text ?? '') }] };
  process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: request.id, result }) + '\n');
}
