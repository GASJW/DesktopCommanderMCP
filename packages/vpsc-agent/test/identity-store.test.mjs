import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { mkdtempSync, chmodSync, mkdirSync, readFileSync, lstatSync,
  writeFileSync, symlinkSync, rmSync } from 'node:fs';
import os from 'node:os';
import { execFileSync } from 'node:child_process';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createDeviceRegistry } from '../../../gateway/devices/registry.mjs';
import { createPairingCoordinator } from '../../../gateway/devices/pairing.mjs';
import { ownerIdentityDigest,ownerPrincipalId } from '../../../gateway/dashboard/owner-identity.mjs';
import { analyzeDeviceIdentityBindingRecovery, bindApprovedDeviceIdentity,
  clearStaleDeviceIdentityBindingLock, loadOrCreateDeviceIdentity } from '../src/identity-store.mjs';

const DEVICE_ID='f1a2b3c4-d5e6-4a9f-8abc-1bb9b99c0001';
const APPROVAL_EVENT='a1a2b3c4-d5e6-4a9f-8abc-1bb9b99c0001';
const APPROVAL=(fingerprint,deviceId=DEVICE_ID)=>({deviceId,eventId:APPROVAL_EVENT,
  fingerprint,trustRevisionBefore:0,trustRevisionAfter:1,trustRevision:1});
const OWNER={issuer:'https://identity-test.cloudflareaccess.com',subject:'identity-test-owner'};
function approvedBinding(fingerprint,deviceId=DEVICE_ID,overrides={}){
  return {deviceId,clientId:'vpsc-test-machine.access',fingerprint,
    approvalEventId:APPROVAL_EVENT,bindingEventId:'b1a2b3c4-d5e6-4a9f-8abc-1bb9b99c0001',
    bindingRevision:1,ownerId:ownerPrincipalId(OWNER),ownerDigest:ownerIdentityDigest(OWNER),
    trustRevisionBefore:0,trustRevisionAfter:1,trustRevision:1,...overrides};
}
const IDENTITY_FIXTURE=fileURLToPath(new URL('./fixtures-device-identity-process.mjs',import.meta.url));

function withTemp(fn) {
  const base=mkdtempSync(path.join(os.tmpdir(),'vpsc-agent-identity-test-'));
  const directory=path.join(base,'keys');
  try{
    const result=fn(directory,base);
    return result&&typeof result.then==='function'
      ?result.finally(()=>rmSync(base,{recursive:true,force:true}))
      :(rmSync(base,{recursive:true,force:true}),result);
  }catch(error){rmSync(base,{recursive:true,force:true});throw error;}
}
test('create then load identity retains exact fingerprint across simulated process restart',()=>{
  withTemp(dir=>{
    const a=loadOrCreateDeviceIdentity({directory:dir});
    const b=loadOrCreateDeviceIdentity({directory:dir});
    assert.equal(a.fingerprint,b.fingerprint);
    assert.equal(a.publicKeyPem,b.publicKeyPem);
    const rec=createDeviceRegistry();
    const pairing=createPairingCoordinator({registry:rec});
    const request=pairing.startPairing({name:'Gui-PC',platform:'win32',publicKeyPem:b.publicKeyPem});
    assert.equal(pairing.provePossession(request.requestId,b.prove(request)),true);
    pairing.approvePairing(request.requestId,b.fingerprint);
    assert.equal(rec.listDevices()[0].online,false);
  });
});
test('identity store exposes only signing helpers and public material',()=>{
  withTemp(dir=>{
    const identity=loadOrCreateDeviceIdentity({directory:dir});
    assert.deepEqual(Object.keys(identity).sort(),
      ['deviceBinding','fingerprint','prove','proveDeviceChallenge','publicKeyPem','signFrame']);
    assert.equal(identity.deviceBinding,null);
    assert.equal(JSON.stringify(identity).includes('PRIVATE KEY'),false);
  });
});
test('approved device binding persists across reload and is immutable',()=>{
  withTemp(dir=>{
    const identity=loadOrCreateDeviceIdentity({directory:dir});
    const binding=approvedBinding(identity.fingerprint);
    const bound=bindApprovedDeviceIdentity({directory:dir,machineBinding:binding});
    assert.deepEqual(bound.deviceBinding,binding);
    const loaded=loadOrCreateDeviceIdentity({directory:dir});
    assert.equal(loaded.fingerprint,identity.fingerprint);
    assert.deepEqual(loaded.deviceBinding,bound.deviceBinding);
    const child=JSON.parse(execFileSync(process.execPath,[IDENTITY_FIXTURE],{
      env:{...process.env,VPSC_TEST_IDENTITY_DIR:dir},encoding:'utf8',
    }));
    assert.equal(child.fingerprint,identity.fingerprint);
    assert.deepEqual(child.deviceBinding,bound.deviceBinding,
      'a different process reloads the exact approved device/Client-ID binding');
    assert.equal(bindApprovedDeviceIdentity({directory:dir,machineBinding:binding})
      .deviceBinding.clientId,'vpsc-test-machine.access');
    assert.throws(()=>bindApprovedDeviceIdentity({directory:dir,machineBinding:
      {...binding,clientId:'other-machine.access'}}),/already bound/);
    assert.throws(()=>bindApprovedDeviceIdentity({directory:dir,machineBinding:
      {...binding,deviceId:'b1a2b3c4-d5e6-4a9f-8abc-1bb9b99c0001'}}),/already bound/);
  });
});
test('approved identity binding rejects a receipt for another key or invalid revision',()=>{
  withTemp(dir=>{
    const identity=loadOrCreateDeviceIdentity({directory:dir});
    assert.throws(()=>bindApprovedDeviceIdentity({directory:dir,machineBinding:
      approvedBinding('f'.repeat(64))}),/does not bind/);
    assert.throws(()=>bindApprovedDeviceIdentity({directory:dir,machineBinding:
      approvedBinding(identity.fingerprint,DEVICE_ID,{trustRevisionAfter:3})}),/Verified durable machine binding/);
    assert.equal(loadOrCreateDeviceIdentity({directory:dir}).deviceBinding,null);
  });
});
test('directory fsync failure after identity rename preserves a recovery lock',()=>{
  withTemp(dir=>{
    const identity=loadOrCreateDeviceIdentity({directory:dir});
    const original=fs.fsyncSync;
    let injected=false;
    fs.fsyncSync=fd=>{
      let target='';try{target=fs.readlinkSync(`/proc/self/fd/${fd}`);}catch{}
      if(!injected&&target===dir&&
         JSON.parse(readFileSync(path.join(dir,'identity-v1.json'),'utf8')).version===3){
        injected=true;
        throw Object.assign(new Error('simulated directory fsync failure after rename'),
          {code:'EIO'});
      }
      return original(fd);
    };
    syncBuiltinESMExports();
    try{
      assert.throws(()=>bindApprovedDeviceIdentity({directory:dir,
        machineBinding:approvedBinding(identity.fingerprint)}),/uncertain|fsync/i);
      assert.equal(injected,true);
      assert.equal(analyzeDeviceIdentityBindingRecovery({directory:dir}).state,'ACTIVE_LOCK');
      assert.throws(()=>loadOrCreateDeviceIdentity({directory:dir}),/operator recovery/i);
    }finally{
      fs.fsyncSync=original;
      syncBuiltinESMExports();
    }
  });
});
test('legacy v2 identity binding loads but upgrades only when given the complete durable v3 decision',()=>{
  withTemp(dir=>{
    const identity=loadOrCreateDeviceIdentity({directory:dir});
    const filename=path.join(dir,'identity-v1.json');
    const envelope=JSON.parse(readFileSync(filename,'utf8'));
    const legacy={deviceId:DEVICE_ID,clientId:'vpsc-test-machine.access',
      fingerprint:identity.fingerprint,approvalEventId:APPROVAL_EVENT,
      trustRevisionBefore:0,trustRevisionAfter:1,trustRevision:1};
    writeFileSync(filename,JSON.stringify({...envelope,version:2,deviceBinding:legacy})+'\n',
      {mode:0o600});
    const loaded=loadOrCreateDeviceIdentity({directory:dir});
    assert.equal(loaded.deviceBinding,null);
    assert.deepEqual(loaded.legacyDeviceBinding,legacy);
    const migrated=approvedBinding(identity.fingerprint);
    const upgraded=bindApprovedDeviceIdentity({directory:dir,machineBinding:migrated});
    assert.deepEqual(upgraded.deviceBinding,migrated);
    assert.equal(JSON.parse(readFileSync(filename,'utf8')).version,3);
  });
});
test('on POSIX, directory 0700 and identity file 0600', {skip:process.platform==='win32'},()=>{
  withTemp(dir=>{
    loadOrCreateDeviceIdentity({directory:dir});
    assert.equal(lstatSync(dir).mode & 0o777,0o700);
    assert.equal(lstatSync(path.join(dir,'identity-v1.json')).mode & 0o777,0o600);
  });
});
test('POSIX identity never silently accepts world/group-readable file', {skip:process.platform==='win32'},()=>{
  withTemp(dir=>{
    loadOrCreateDeviceIdentity({directory:dir});
    chmodSync(path.join(dir,'identity-v1.json'),0o644);
    assert.throws(()=>loadOrCreateDeviceIdentity({directory:dir}),/Unsafe identity file/);
  });
});
test('POSIX identity never accepts world/group-readable directory',{skip:process.platform==='win32'},()=>{
  withTemp(dir=>{
    loadOrCreateDeviceIdentity({directory:dir});
    chmodSync(dir,0o755);
    assert.throws(()=>loadOrCreateDeviceIdentity({directory:dir}),/permissions must be owner-only/);
  });
});
test('file symlink is not followed',{skip:process.platform==='win32'},()=>{
  withTemp((dir,base)=>{
    mkdirSync(dir, {mode:0o700});
    writeFileSync(path.join(base,'outside'),'secret');
    symlinkSync(path.join(base,'outside'),path.join(dir,'identity-v1.json'));
    assert.throws(()=>loadOrCreateDeviceIdentity({directory:dir}));
    assert.equal(readFileSync(path.join(base,'outside'),'utf8'),'secret');
  });
});
test('directory symlink is rejected',{skip:process.platform==='win32'},()=>{
  withTemp((dir,base)=>{
    mkdirSync(path.join(base,'other'),{mode:0o700});
    symlinkSync(path.join(base,'other'),dir);
    assert.throws(()=>loadOrCreateDeviceIdentity({directory:dir}),/Unsafe identity directory/);
  });
});
test('corrupt or mismatched envelope is denied rather than creating another key',()=>{
  withTemp(dir=>{
    loadOrCreateDeviceIdentity({directory:dir});
    const f=path.join(dir,'identity-v1.json');
    let body=JSON.parse(readFileSync(f,'utf8'));
    body.fingerprint='0'.repeat(64);
    writeFileSync(f,JSON.stringify(body));
    assert.throws(()=>loadOrCreateDeviceIdentity({directory:dir}),/fingerprint mismatch/);
  });
});
test('malformed identity envelope fails closed',()=>{
  withTemp(dir=>{
    loadOrCreateDeviceIdentity({directory:dir});
    const f=path.join(dir,'identity-v1.json');
    writeFileSync(f,'{not json');
    assert.throws(()=>loadOrCreateDeviceIdentity({directory:dir}),/Invalid device identity envelope/);
  });
});
test('SIGKILL during identity binding leaves evidence that blocks identity loading',async()=>{
  await withTemp(async dir=>{
    const identity=loadOrCreateDeviceIdentity({directory:dir});
    const identityFingerprint=identity.fingerprint;
    const child=spawn(process.execPath,[fileURLToPath(new URL('./fixtures-identity-binding-lock.mjs',import.meta.url))],{
      env:{...process.env,VPSC_TEST_IDENTITY_DIR:dir},stdio:['ignore','pipe','ignore'],
    });
    const lines=createInterface({input:child.stdout,crlfDelay:Infinity});
    await new Promise((resolve,reject)=>{
      const timer=setTimeout(()=>reject(Error('identity lock fixture did not start')),5000);
      lines.once('line',line=>{clearTimeout(timer);try{
        assert.equal(JSON.parse(line).ready,true);resolve();
      }catch(error){reject(error);}});
      child.once('error',reject);
    });
    child.kill('SIGKILL');
    await new Promise(resolve=>child.once('close',resolve));
    assert.throws(()=>loadOrCreateDeviceIdentity({directory:dir}),/binding.*recovery|interrupted binding/i);
    const diagnosis=analyzeDeviceIdentityBindingRecovery({directory:dir});
    assert.equal(diagnosis.state,'STALE_LOCK');
    assert.throws(()=>clearStaleDeviceIdentityBindingLock({directory:dir,
      expectedLockDigest:diagnosis.lockDigest,verifyMachineBinding:()=>true}),/quiescence/);
    assert.equal(clearStaleDeviceIdentityBindingLock({directory:dir,
      expectedLockDigest:diagnosis.lockDigest,operatorConfirmedNoActiveWriters:true,
      verifyMachineBinding:({fingerprint,binding})=>fingerprint===identityFingerprint&&binding===null}),true);
    assert.equal(loadOrCreateDeviceIdentity({directory:dir}).fingerprint,identityFingerprint);
    lines.close();
  });
});
test('orphaned identity binding temp file fails closed after restart',()=>{
  withTemp(dir=>{
    loadOrCreateDeviceIdentity({directory:dir});
    writeFileSync(path.join(dir,'.identity-binding-interrupted.tmp'),'partial');
    assert.throws(()=>loadOrCreateDeviceIdentity({directory:dir}),/binding.*recovery|interrupted binding/i);
    assert.equal(analyzeDeviceIdentityBindingRecovery({directory:dir}).state,'TEMPORARY_EVIDENCE');
    assert.throws(()=>clearStaleDeviceIdentityBindingLock({directory:dir,
      operatorConfirmedNoActiveWriters:true,verifyMachineBinding:()=>true}),/blocked/);
  });
});
test('wrong platform or relative directory rejected',()=>{
  assert.throws(()=>loadOrCreateDeviceIdentity({platform:'not-a-platform'}),/cannot impersonate/);
  assert.throws(()=>loadOrCreateDeviceIdentity({directory:'relative-path'}),/directory/);
});
test('no private key bytes are passed through JSON serialization of public identity',()=>{
  withTemp(dir=>{
    const identity=loadOrCreateDeviceIdentity({directory:dir});
    assert.deepEqual(Object.keys(JSON.parse(JSON.stringify(identity))).sort(),
      ['deviceBinding','fingerprint','publicKeyPem']);
  });
});
test('Windows uses DPAPI CurrentUser ciphertext and survives repeated loads',{skip:process.platform!=='win32'},()=>{
  withTemp(dir=>{
    const a=loadOrCreateDeviceIdentity({directory:dir});
    const body=JSON.parse(readFileSync(path.join(dir,'identity-v1.json'),'utf8'));
    assert.equal(body.encoding,'dpapi-current-user');
    assert.equal(body.key.includes('PRIVATE KEY'),false);
    assert.equal(loadOrCreateDeviceIdentity({directory:dir}).fingerprint,a.fingerprint);
  });
});

test('new process reloads same identity without re-enrollment',()=>{
  withTemp(dir=>{
    const first=loadOrCreateDeviceIdentity({directory:dir});
    const file=path.resolve(path.dirname(new URL(import.meta.url).pathname),'../src/identity-store.mjs');
    const source = 'import {loadOrCreateDeviceIdentity as get} from '+JSON.stringify(new URL('../src/identity-store.mjs',import.meta.url).href)+
      ';console.log(get({directory:process.argv[1]}).fingerprint);';
    const child=execFileSync(process.execPath,['--input-type=module','-e',source,dir],{encoding:'utf8'});
    assert.equal(child.trim(),first.fingerprint);
  });
});
