import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
const text=file=>readFileSync(fileURLToPath(new URL('../dashboard/'+file,import.meta.url)),'utf8');
test('G7 owner pairing page clearly declares unavailable until authenticated API exists',()=>{
  const html=text('pairing.html');
  assert.match(html,/Parear novo dispositivo/);
  assert.match(html,/vpsc-agent pair/);
  assert.match(html,/ainda oferece apenas/);
  assert.match(html,/disabled>Aprovar em modo padrão/);
  assert.match(html,/disabled>Rejeitar solicitação/);
  assert.doesNotMatch(html,/javascript:|<script(?! src)/i);
});
test('pairing frontend fails closed without explicit enabled, token and pending array',()=>{
  const js=text('pairing.js');
  assert.match(js,/result\.enabled!==true/);
  assert.match(js,/result\.csrf\.length<24/);
  assert.match(js,/!Array\.isArray\(result\.pending\)/);
  assert.match(js,/codeOf\(field\.value\)/);
  assert.match(js,/textContent/);
  assert.doesNotMatch(js,/innerHTML|eval\(|localStorage|sessionStorage|new Function\(/);
});
test('G6 active router never references pairing page or owner review module',()=>{
  const router=readFileSync(fileURLToPath(new URL('../server.mjs',import.meta.url)),'utf8');
  const http=readFileSync(fileURLToPath(new URL('../dashboard/http.mjs',import.meta.url)),'utf8');
  assert.doesNotMatch(router,/owner-pairing-review|pairing\.html|dashboard\/api\/g7\/pairing/);
  assert.doesNotMatch(http,/pairing\.html|dashboard\/api\/g7\/pairing/);
});
