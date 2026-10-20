import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { parseStagingCommandLine } from '../staging/runtime-mode.mjs';
import { isValidStagingIssuer } from '../staging/runtime.mjs';
import { fileURLToPath } from 'node:url';

const ROOT=fileURLToPath(new URL('../../',import.meta.url));
const read=relative=>readFileSync(path.join(ROOT,relative),'utf8');

test('persistent staging service templates are isolated and exclude fixture selectors',()=>{
  const gateway=read('deploy/g7-staging/systemd/vpsc-g7-staging-gateway.service');
  const agent=read('deploy/g7-staging/systemd/vpsc-g7-staging-agent.service');
  for(const unit of [gateway,agent]){
    assert.match(unit,/^User=vpsc-g7-staging-(?:gateway|agent)$/m);
    assert.match(unit,/^NoNewPrivileges=yes$/m);
    assert.match(unit,/^ProtectSystem=strict$/m);
    assert.match(unit,/^ProtectHome=yes$/m);
    assert.match(unit,/^PrivateTmp=yes$/m);
    assert.match(unit,/^CapabilityBoundingSet=$/m);
    assert.match(unit,/^AmbientCapabilities=$/m);
    assert.match(unit,/^Restart=no$/m);
    assert.match(unit,/^UnsetEnvironment=.*NODE_TEST_CONTEXT.*NODE_OPTIONS.*NODE_V8_COVERAGE.*VPSC_STAGING_TEST_ACTIVE_JOB.*VPSC_STAGING_TEST_SCENARIO.*VPSC_STAGING_NODE.*VPSC_STAGING_MCP_ENTRYPOINT.*VPSC_STAGING_TRACE$/m);
    assert.match(unit,/^ReadOnlyPaths=.*\/opt\/vps-commander\/g7-staging$/m);
    assert.doesNotMatch(unit,/VPSC_STAGING_TEST_(?:ACTIVE_JOB|SCENARIO)=/);
    assert.doesNotMatch(unit,/\/opt\/vps-commander\/code|8787|20242/);
    assert.match(unit,/^ExecStart=.*--persistent-staging --config/m);
  }
  assert.match(gateway,/^ExecStart=.*--persistent-staging --config/m);
  assert.match(agent,/^ExecStart=.*--persistent-staging --config/m);
  assert.match(agent,/^BindsTo=vpsc-g7-staging-gateway\.service$/m);
  assert.match(agent,/^After=vpsc-g7-staging-gateway\.service$/m);
  assert.match(gateway,/^User=vpsc-g7-staging-gateway$/m);
  assert.match(agent,/^User=vpsc-g7-staging-agent$/m);
  assert.match(gateway,/^StateDirectory=vpsc-g7-staging-gateway$/m);
  assert.match(agent,/^StateDirectory=vpsc-g7-staging-agent$/m);
});

test('inert config examples are loopback-only and contain no usable credentials',()=>{
  const gateway=JSON.parse(read('deploy/g7-staging/config/gateway.json.example'));
  const agent=JSON.parse(read('deploy/g7-staging/config/agent.json.example'));
  assert.equal(gateway.listen.host,'127.0.0.1');
  assert.equal(gateway.listen.port,18443);
  assert.equal(Object.hasOwn(gateway,'chatgptBridge'),false);
  assert.equal(agent.port,18443);
  assert.equal(gateway.machine.clientId,agent.clientId);
  assert.equal(gateway.owner.issuer,'https://g7-owner-staging.cloudflareaccess.com');
  assert.equal(gateway.machine.issuer,'https://g7-machine-staging.cloudflareaccess.com');
  assert.equal(isValidStagingIssuer(gateway.owner.issuer,'owner'),true);
  assert.equal(isValidStagingIssuer(gateway.machine.issuer,'machine'),true);
  assert.equal(isValidStagingIssuer(gateway.owner.issuer,'machine'),false);
  assert.equal(isValidStagingIssuer('https://unrelated.cloudflareaccess.com','owner'),false);
  assert.equal(isValidStagingIssuer('https://unrelated.cloudflareaccess.com','machine'),false);
  assert.match(gateway.owner.controlToken,/^REPLACE_/);
  assert.match(gateway.machine.serviceSecret,/^REPLACE_/);
  assert.match(agent.deviceId,/^REPLACE_/);
  assert.match(gateway.policy.privateKeyPem,/^REPLACE_/);
  assert.match(gateway.owner.jwks[0].n,/^REPLACE_/);
  assert.match(gateway.machine.jwks[0].n,/^REPLACE_/);
});

test('persistent Gateway uses direct authenticated ingress, never the harness listener',()=>{
  const runtime=read('gateway/staging/runtime.mjs');
  assert.match(runtime,/createAuthenticatedMachineIngress/);
  assert.doesNotMatch(runtime,/startMachineIngressLoopback|enableTestIngress|fetch\(ingress\.url/);
  assert.match(runtime,/req\.headers\['cf-access-jwt-assertion'\]\s*\|\|/);
  assert.match(runtime,/cf-access-jwt-assertion':\s*mintMachineJwt\(/);
  assert.match(runtime,/one-use challenge plus signed monotonic frame sequence/);
});

test('persistent mode rejects future fixture selectors by namespace',()=>{
  assert.throws(()=>parseStagingCommandLine(['--persistent-staging','--config','/unused'],{
    env:{VPSC_STAGING_TEST_FUTURE_SELECTOR:'',VPSC_STAGING_FIXTURE_SELECTOR:'x'},
  }),/test fixture environment/);
  assert.deepEqual(parseStagingCommandLine(['--persistent-staging','--config','/private/gateway.json'],{
    env:{PATH:'/usr/bin:/bin'},
  }),{persistent:true,configPath:'/private/gateway.json'});
});

for(const [label,script,env] of [
  ['Gateway','gateway/staging/server.mjs',{VPSC_STAGING_TEST_ACTIVE_JOB:'1'}],
  ['agent','packages/vpsc-agent/bin/g7-staging-worker.mjs',{VPSC_STAGING_FIXTURE_SCENARIO:'unknown'}],
]){
  test(`persistent ${label} entrypoint rejects test fixture environment before config access`,()=>{
    const result=spawnSync(process.execPath,[path.join(ROOT,script),'--persistent-staging','--config',
      '/missing/g7-staging-config.json'],{encoding:'utf8',env:{PATH:process.env.PATH??'/usr/bin:/bin',...env}});
    assert.notEqual(result.status,0);
    assert.match(result.stderr,/TEST_FIXTURE_ENVIRONMENT/);
    assert.doesNotMatch(result.stderr,/Unsafe staging configuration/);
  });
}
