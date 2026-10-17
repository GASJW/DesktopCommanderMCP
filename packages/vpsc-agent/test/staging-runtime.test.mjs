import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { once } from 'node:events';
import { mkdtempSync, mkdirSync, chmodSync, writeFileSync, symlinkSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import * as stagingRuntime from '../../../gateway/staging/runtime.mjs';

const ROOT=fileURLToPath(new URL('../../../',import.meta.url));
const PILOT=path.join(ROOT,'scripts/g7-staging-pilot.mjs');
const NODE=process.env.VPSC_STAGING_NODE??
  (typeof process.getuid==='function'&&process.getuid()===0?'/usr/bin/node':process.execPath);
const MCP_ENTRYPOINT=process.env.VPSC_STAGING_MCP_ENTRYPOINT??path.join(ROOT,'dist/index.js');

test('staging configuration reader rejects symlinks and writable parent directories',async t=>{
  const readStagingConfig=stagingRuntime.readStagingConfig;
  assert.equal(typeof readStagingConfig,'function','runtime must expose the same config reader used by its entrypoint');
  const parent=mkdtempSync(path.join(tmpdir(),'g7-staging-config-'));
  chmodSync(parent,0o700);
  const protectedDir=path.join(parent,'protected');
  mkdirSync(protectedDir,{mode:0o700});
  const regular=path.join(protectedDir,'gateway.json');
  writeFileSync(regular,'{}',{mode:0o600});
  const link=path.join(protectedDir,'gateway-link.json');
  symlinkSync(regular,link);
  const writableDir=path.join(parent,'writable');
  mkdirSync(writableDir,{mode:0o700});
  chmodSync(writableDir,0o777);
  const writableFile=path.join(writableDir,'gateway.json');
  writeFileSync(writableFile,'{}',{mode:0o600});
  try{
    assert.throws(()=>readStagingConfig(link),/Unsafe staging configuration/);
    assert.throws(()=>readStagingConfig(writableFile),/Unsafe staging configuration/);
  }finally{rmSync(parent,{recursive:true,force:true});}
});

test('standalone staging pilot runs Gateway and agent as separate processes',async()=>{
  const child=spawn(NODE,[PILOT,'--json'],{cwd:ROOT,stdio:['ignore','pipe','pipe'],
    ...(typeof process.getuid==='function'&&process.getuid()===0?{uid:65534,gid:65534}:{}),
    env:{PATH:process.env.PATH??'/usr/bin:/bin',TMPDIR:process.env.TMPDIR??'',
      VPSC_STAGING_MCP_ENTRYPOINT:MCP_ENTRYPOINT}});
  let stdout='',stderr='';
  child.stdout.setEncoding('utf8').on('data',chunk=>{stdout+=chunk;});
  child.stderr.setEncoding('utf8').on('data',chunk=>{stderr+=chunk;});
  const [code]=await once(child,'exit');
  assert.equal(code,0,stderr||stdout);
  const report=JSON.parse(stdout.trim().split('\n').at(-1));
  assert.equal(report.status,'pass_with_limitations',JSON.stringify(report));
  assert.equal(report.gateway.processIndependent,true);
  assert.equal(report.agent.processIndependent,true);
  assert.equal(report.https.tlsValidated,true);
  assert.equal(report.ownerAuthentication.separateFromMachine,true);
  assert.equal(report.operations.realMcpRead,true);
  assert.equal(report.operations.governedWrite,true);
  assert.equal(report.restart.gateway,true);
  assert.equal(report.restart.gatewayAfterSigkill,true);
  assert.equal(report.restart.gatewayAfterSigkillRecovery,'RECONCILED_CONSISTENT');
  assert.equal(report.restart.agent,true);
  assert.equal(report.revocation.grantBlocksDispatch,true);
  assert.equal(report.security.invalidOwnerRejected,true);
  assert.equal(report.security.ownerTokenRejectedByMachineIngress,true);
  assert.equal(report.security.invalidMachineSecretRejected,true);
  assert.equal(report.security.crossDeviceChallengeRejected,true);
  assert.equal(report.security.mismatchedMachineClientIdRejected,true);
  assert.equal(report.cancellation.cooperativeDuringExecution,'not_certified_by_standalone_pilot');
  assert.equal(report.cleanup.processGroupsGone,true);
  assert.equal(report.cleanup.temporaryStateRemoved,true);
});
