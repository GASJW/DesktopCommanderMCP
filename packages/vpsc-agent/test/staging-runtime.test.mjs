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

async function runPilot(scenario){
  const env={PATH:process.env.PATH??'/usr/bin:/bin',TMPDIR:process.env.TMPDIR??'',
    VPSC_STAGING_MCP_ENTRYPOINT:MCP_ENTRYPOINT};
  if(scenario!==undefined){
    env.NODE_TEST_CONTEXT=process.env.NODE_TEST_CONTEXT;
    env.VPSC_STAGING_TEST_ACTIVE_JOB='1';
    env.VPSC_STAGING_TEST_SCENARIO=scenario;
  }
  const child=spawn(NODE,[PILOT,'--json'],{cwd:ROOT,stdio:['ignore','pipe','pipe'],
    ...(typeof process.getuid==='function'&&process.getuid()===0?{uid:65534,gid:65534}:{}),
    env});
  let stdout='',stderr='';
  child.stdout.setEncoding('utf8').on('data',chunk=>{stdout+=chunk;});
  child.stderr.setEncoding('utf8').on('data',chunk=>{stderr+=chunk;});
  const [code]=await once(child,'exit');
  assert.equal(code,0,stderr||stdout);
  return JSON.parse(stdout.trim().split('\n').at(-1));
}

function assertBasePilot(report){
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
  assert.equal(report.cleanup.processGroupsGone,true);
  assert.equal(report.cleanup.temporaryStateRemoved,true);
}

test('ordinary standalone staging pilot remains available without a test fixture',async t=>{
  const report=await runPilot();
  t.diagnostic(JSON.stringify(report.cancellation));
  assertBasePilot(report);
  assert.equal(report.cancellation.scenario,'not_tested_outside_node_test');
  assert.equal(report.cancellation.activeExecution.startProven,false);
});

test('standalone Owner cancellation is acknowledged before execution and during a live job',async t=>{
  const report=await runPilot('owner-cancel');
  t.diagnostic(JSON.stringify(report.cancellation));
  assertBasePilot(report);
  assert.equal(report.cancellation.afterReceiptBeforeExecution.receivedByAgent,true);
  assert.equal(report.cancellation.afterReceiptBeforeExecution.acknowledged,true);
  assert.equal(report.cancellation.afterReceiptBeforeExecution.agentExecutionStatus,'cancelled');
  assert.equal(report.cancellation.afterReceiptBeforeExecution.gatewayAcknowledgementStatus,'ambiguous');
  assert.equal(report.cancellation.afterReceiptBeforeExecution.ownerResult,'ambiguous_after_disconnect');
  assert.equal(report.cancellation.afterReceiptBeforeExecution.noExecutionIntent,true);
  assert.equal(report.cancellation.followUpReadSucceeded,true);
  assert.equal(report.cancellation.activeExecution.startProven,true);
  assert.equal(report.cancellation.activeExecution.processWasLiveAtCancel,true);
  assert.equal(report.cancellation.activeExecution.cancelAcknowledged,true);
  assert.equal(report.cancellation.activeExecution.acknowledgedStatus,'ambiguous');
  assert.equal(report.cancellation.activeExecution.gatewayAcknowledgementStatus,'ambiguous');
  assert.equal(report.cancellation.activeExecution.processStopped,true);
  assert.equal(report.cancellation.activeExecution.automaticReplay,false);
});

test('standalone Gateway grant revocation fences a live job and its result',async t=>{
  const report=await runPilot('grant-revoke');
  t.diagnostic(JSON.stringify(report.cancellation));
  assertBasePilot(report);
  assert.equal(report.cancellation.activeExecution.startProven,true);
  assert.equal(report.cancellation.activeExecution.processWasLiveAtCancel,true);
  assert.equal(report.cancellation.activeExecution.cancelAcknowledged,true);
  assert.equal(report.cancellation.activeExecution.acknowledgedStatus,'ambiguous');
  assert.equal(report.cancellation.activeExecution.gatewayAcknowledgementStatus,'ambiguous');
  assert.equal(report.cancellation.activeExecution.processStopped,true);
  assert.equal(report.cancellation.activeExecution.automaticReplay,false);
  assert.equal(report.cancellation.grantRevocationDuringJob.revoked,true);
  assert.equal(report.cancellation.grantRevocationDuringJob.commitBeforeCommandTimeout,true);
  assert.equal(report.cancellation.grantRevocationDuringJob.acknowledgementAfterRevocationRequest,true);
  assert.equal(report.cancellation.grantRevocationDuringJob.acknowledgementBeforeCommandTimeout,true);
  assert.ok(report.cancellation.grantRevocationDuringJob.commitElapsedMs<
    report.cancellation.grantRevocationDuringJob.commandTimeoutMs-500);
  assert.ok(report.cancellation.grantRevocationDuringJob.acknowledgementElapsedMs<
    report.cancellation.grantRevocationDuringJob.commandTimeoutMs-500);
  assert.equal(report.cancellation.activeExecution.responseFenced,true);
  assert.ok(report.cancellation.activeExecution.ownerResponseStatus>=400);
});

test('standalone device trust revocation fences a live job and its result',async t=>{
  const report=await runPilot('device-revoke');
  t.diagnostic(JSON.stringify(report.cancellation));
  assertBasePilot(report);
  assert.equal(report.cancellation.activeExecution.startProven,true);
  assert.equal(report.cancellation.activeExecution.processWasLiveAtCancel,true);
  assert.equal(report.cancellation.activeExecution.processStopped,true);
  assert.equal(report.cancellation.activeExecution.automaticReplay,false);
  assert.equal(report.cancellation.deviceRevocationDuringJob.revoked,true);
  assert.equal(report.cancellation.deviceRevocationDuringJob.sessionRejectionObserved,true);
  assert.equal(report.cancellation.deviceRevocationDuringJob.commitBeforeCommandTimeout,true);
  assert.ok(report.cancellation.deviceRevocationDuringJob.commitElapsedMs<
    report.cancellation.deviceRevocationDuringJob.commandTimeoutMs);
  assert.equal(report.cancellation.activeExecution.responseFenced,true);
  assert.equal(report.cancellation.activeExecution.ownerResponseStatus,503);
  assert.equal(report.cancellation.activeExecution.ownerResponseCode,'AMBIGUOUS_TIMEOUT');
  assert.ok(['ambiguous','unavailable_after_device_revocation'].includes(
    report.cancellation.activeExecution.acknowledgedStatus));
});
