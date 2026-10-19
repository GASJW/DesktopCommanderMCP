import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { createServer } from 'node:https';
import { randomUUID } from 'node:crypto';
import { chmodSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createDeviceRegistry } from '../devices/registry.mjs';
import { createPairingCoordinator } from '../devices/pairing.mjs';
import { loadOrCreateDeviceIdentity } from '../../packages/vpsc-agent/src/identity-store.mjs';
import { securePrivateWindowsDirectory, securePrivateWindowsFile } from '../../packages/vpsc-agent/src/windows-security.mjs';

const ROOT=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const CLI=path.join(ROOT,'scripts/g7-staging-device-pair.mjs');
const windows=process.platform==='win32';
const OPENSSL=windows?path.join(process.env.ProgramFiles??'C:\\Program Files','Git','usr','bin','openssl.exe'):'openssl';
async function sandbox(fn){
  const dir=mkdtempSync(path.join(os.tmpdir(),'g7-device-pair-'));
  if(windows)securePrivateWindowsDirectory(dir);else chmodSync(dir,0o700);
  try{return await fn(dir);}finally{rmSync(dir,{recursive:true,force:true});}
}
function privateFile(filename,value){
  writeFileSync(filename,value,{mode:0o600,flag:'wx'});
  if(windows)securePrivateWindowsFile(filename);else chmodSync(filename,0o600);
}
function runCli(args){
  return new Promise(resolve=>{
    const child=spawn(process.execPath,[CLI,...args],{cwd:ROOT,windowsHide:true,
      stdio:['ignore','pipe','pipe']});
    let stdout='',stderr='',settled=false;
    const timer=setTimeout(()=>child.kill(),120_000);
    child.stdout.setEncoding('utf8').on('data',chunk=>stdout+=chunk);
    child.stderr.setEncoding('utf8').on('data',chunk=>stderr+=chunk);
    child.once('error',error=>{if(settled)return;settled=true;clearTimeout(timer);
      resolve({status:null,signal:null,error,stdout,stderr});});
    child.once('close',(status,signal)=>{if(settled)return;settled=true;clearTimeout(timer);
      resolve({status,signal,stdout,stderr});});
  });
}

test('device CLI proves a DPAPI/POSIX identity and persists an Owner-approved machine binding',async()=>{
  await sandbox(async dir=>{
    const tls=path.join(dir,'tls');mkdirSync(tls);
    if(windows)securePrivateWindowsDirectory(tls);else chmodSync(tls,0o700);
    const key=path.join(tls,'key.pem'),cert=path.join(tls,'cert.pem');
    execFileSync(OPENSSL,['req','-x509','-newkey','rsa:2048','-nodes','-days','1',
      '-subj','/CN=g7-staging.test','-addext','subjectAltName=DNS:g7-staging.test',
      '-keyout',key,'-out',cert],{stdio:'ignore'});
    if(windows)securePrivateWindowsFile(cert);
    else{chmodSync(key,0o600);chmodSync(cert,0o644);}
    const registry=createDeviceRegistry(),pairing=createPairingCoordinator({registry});
    const requests=[],tlsEvents=[];
    const server=createServer({key:readFileSync(key),cert:readFileSync(cert)},async(req,res)=>{
      const chunks=[];for await(const chunk of req)chunks.push(chunk);
      const body=JSON.parse(Buffer.concat(chunks).toString('utf8'));requests.push(req.url);
      let result,status=200;
      if(req.url==='/pairing/start'){
        status=201;result=pairing.startPairing(body);
      }else if(req.url==='/pairing/prove'){
        result={proved:pairing.provePossession(body.requestId,body.proof)};
      }else{status=404;result={error:'not found'};}
      res.writeHead(status,{'content-type':'application/json'});res.end(JSON.stringify(result));
    });
    server.on('connection',()=>tlsEvents.push('tcp'));
    server.on('secureConnection',()=>tlsEvents.push('tls'));
    server.on('tlsClientError',error=>tlsEvents.push(error.code??error.name));
    server.listen(0,'127.0.0.1');
    await new Promise(resolve=>server.once('listening',resolve));
    const identityDirectory=path.join(dir,'identity');mkdirSync(identityDirectory,{mode:0o700});
    const configPath=path.join(dir,'pairing.json');
    privateFile(configPath,JSON.stringify({version:1,hostname:'g7-staging.test',port:server.address().port,
      caPath:cert,identityDirectory,deviceName:'Gui-PC Windows pilot'}));
    try{
      const result=await runCli(['--config',configPath]);
      assert.equal(result.status,0,JSON.stringify({signal:result.signal,error:result.error?.message,
        stderr:result.stderr,requests,tlsEvents}));
      const proof=JSON.parse(result.stdout.trim());
      assert.equal(proof.status,'proof_verified');
      assert.match(proof.requestId,/^[0-9a-f-]{36}$/i);
      assert.match(proof.displayCode,/^[A-F0-9]{10}$/);
      assert.equal(proof.platform,process.platform);
      const identity=loadOrCreateDeviceIdentity({directory:identityDirectory,platform:process.platform});
      assert.equal(proof.fingerprint,identity.fingerprint);
      assert.doesNotMatch(result.stdout,/nonce|PRIVATE KEY/i);
      assert.deepEqual(requests,['/pairing/start','/pairing/prove']);

      const deviceId=randomUUID(),binding={deviceId,clientId:'g7-staging-windows.synthetic',
        fingerprint:identity.fingerprint,approvalEventId:randomUUID(),bindingEventId:randomUUID(),
        bindingRevision:1,ownerId:'a'.repeat(24),ownerDigest:'b'.repeat(64),
        trustRevisionBefore:0,trustRevisionAfter:1,trustRevision:1};
      const receipt=path.join(dir,'owner-receipt.json');
      privateFile(receipt,JSON.stringify({status:'provisioned',deviceId,clientId:binding.clientId,
        fingerprint:identity.fingerprint,binding}));
      const bound=await runCli(['--config',configPath,'--binding-receipt',receipt]);
      assert.equal(bound.status,0,JSON.stringify({signal:bound.signal,error:bound.error?.message,stderr:bound.stderr}));
      assert.equal(JSON.parse(bound.stdout.trim()).status,'bound');
      assert.equal(loadOrCreateDeviceIdentity({directory:identityDirectory,platform:process.platform})
        .deviceBinding.bindingEventId,binding.bindingEventId);
      assert.deepEqual(requests,['/pairing/start','/pairing/prove']);
    }finally{await new Promise(resolve=>server.close(resolve));}
  });
});
