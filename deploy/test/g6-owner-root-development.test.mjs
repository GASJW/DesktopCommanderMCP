import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
const source = name => readFileSync(fileURLToPath(
  new URL('../' + name, import.meta.url)), 'utf8');
test('root development activation has an explicit owner-console approval and no gateway unit rewrite', () => {
  const s=source('g6-owner-root-activate.sh');
  assert.match(s,/VPSC_OWNER_ROOT_CONSENT/);
  assert.match(s,/I_ACCEPT_FULL_ROOT_MCP/);
  assert.match(s,/EUID -eq 0/);
  assert.match(s,/User=root/);
  assert.match(s,/Group=vpsc-ipc/);
  assert.match(s,/NoNewPrivileges=false/);
  assert.match(s,/systemctl restart "\$UNIT"/);
  assert.doesNotMatch(s,/systemctl restart "\$GW"/);
  assert.match(s,/show -P User "\$GW"\) == vpsc-gateway/);
  assert.match(s,/http:\/\/127\.0\.0\.1:8787\/mcp/);
  assert.match(s,/== 401/);
});
test('activation arms automatic revert and protects prior configuration',()=>{
  const s=source('g6-owner-root-activate.sh');
  assert.match(s,/systemd-run --unit=vpsc-g6-root-dev-watchdog --on-active=7m/);
  assert.match(s,/trap rollback_on_failure ERR/);
  assert.match(s,/\/root\/vpsc-g6-root-dev/);
  assert.match(s,/install -o root -g root -m 0700/);
  assert.match(s,/test|cmp|DROPIN/);
});
test('rollback cannot discard unrelated override configuration',()=>{
  const s=source('g6-owner-root-revert.sh');
  assert.match(s,/cmp -s "\$DROPIN" "\$BASE\/expected-override\.conf"/);
  assert.match(s,/manual reconciliation required/);
  assert.match(s,/systemctl restart vps-commander-executor.service/);
  assert.match(s,/== vpscommander/);
  assert.match(s,/== vpsc-gateway/);
});
test('indefinite confirmation only cancels watchdog after owner confirms',()=>{
  const s=source('g6-owner-root-confirm.sh');
  assert.match(s,/VPSC_OWNER_ROOT_CONSENT/);
  assert.match(s,/I_ACCEPT_FULL_ROOT_MCP/);
  assert.match(s,/is-active --quiet vpsc-g6-root-dev-watchdog.timer/);
  assert.match(s,/systemctl stop vpsc-g6-root-dev-watchdog.timer/);
  assert.match(s,/until_manual_reversion/i);
});
