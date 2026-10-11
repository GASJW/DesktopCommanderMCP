import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, chmodSync, mkdirSync, readFileSync, lstatSync,
  writeFileSync, symlinkSync, rmSync } from 'node:fs';
import os from 'node:os';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { createDeviceRegistry } from '../../../gateway/devices/registry.mjs';
import { createPairingCoordinator } from '../../../gateway/devices/pairing.mjs';
import { loadOrCreateDeviceIdentity } from '../src/identity-store.mjs';

function withTemp(fn) {
  const base=mkdtempSync(path.join(os.tmpdir(),'vpsc-agent-identity-test-'));
  const directory=path.join(base,'keys');
  try{return fn(directory,base);}finally{rmSync(base,{recursive:true,force:true});}
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
      ['fingerprint','prove','proveDeviceChallenge','publicKeyPem','signFrame']);
    assert.equal(JSON.stringify(identity).includes('PRIVATE KEY'),false);
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
test('wrong platform or relative directory rejected',()=>{
  assert.throws(()=>loadOrCreateDeviceIdentity({platform:'not-a-platform'}),/cannot impersonate/);
  assert.throws(()=>loadOrCreateDeviceIdentity({directory:'relative-path'}),/directory/);
});
test('no private key bytes are passed through JSON serialization of public identity',()=>{
  withTemp(dir=>{
    const identity=loadOrCreateDeviceIdentity({directory:dir});
    assert.deepEqual(Object.keys(JSON.parse(JSON.stringify(identity))).sort(),['fingerprint','publicKeyPem']);
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
