import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { execFileSync, spawn } from 'node:child_process';
import fs from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { chmodSync, lstatSync, mkdtempSync, mkdirSync, readFileSync, rmSync,
  symlinkSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createDurableDeviceTrustStore } from '../devices/durable-trust.mjs';
import { deviceChallengeMessage } from '../devices/registry.mjs';

const generate=()=>{
  const {publicKey,privateKey}=generateKeyPairSync('ed25519');
  return { publicKeyPem:publicKey.export({format:'pem',type:'spki'}),
    sign:challenge=>sign(null,challenge,privateKey).toString('base64url') };
};
const metadata=(key,name='Gui-PC')=>({name,platform:'win32',publicKeyPem:key.publicKeyPem});
function temp(testFn){
  const parent=mkdtempSync(path.join(os.tmpdir(),'vpsc-g7-trust-'));
  const directory=path.join(parent,'server');
  try{return testFn(directory,parent);}finally{rmSync(parent,{recursive:true,force:true});}
}
async function tempAsync(testFn){
  const parent=mkdtempSync(path.join(os.tmpdir(),'vpsc-g7-trust-'));
  const directory=path.join(parent,'server');
  try{return await testFn(directory,parent);}finally{rmSync(parent,{recursive:true,force:true});}
}
const file=directory=>path.join(directory,'trusted-devices-v1.json');

test('trust records persist deviceId and public fingerprint across server restart',()=>{
  temp(dir=>{
    const store=createDurableDeviceTrustStore({directory:dir});
    assert.deepEqual(store.registry.listDevices(),[]);
    assert.equal(store.revision(),0);
    const key=generate();
    const trusted=store.trustDevice(metadata(key));
    assert.equal(store.revision(),1);
    assert.equal(store.registry.listDevices()[0].deviceId,trusted.deviceId);
    assert.equal(store.registry.listDevices()[0].online,false);
    const another=createDurableDeviceTrustStore({directory:dir});
    assert.equal(another.registry.listDevices()[0].deviceId,trusted.deviceId);
    assert.equal(another.registry.listDevices()[0].online,false);
    assert.equal(another.revision(),1);
    assert.equal(another.registry.snapshotTrustedDevices()[0].fingerprint,trusted.fingerprint);
  });
});
test('restarted OS process reads same deviceId, never an inherited online session',()=>{
  temp(dir=>{
    const key=generate();
    const store=createDurableDeviceTrustStore({directory:dir});
    const dev=store.trustDevice(metadata(key));
    const challenge=store.registry.beginHandshake(dev.deviceId);
    const proof=key.sign(deviceChallengeMessage(dev.deviceId,challenge.nonce));
    const {sessionId}=store.registry.completeHandshake(dev.deviceId,proof);
    assert.equal(store.registry.heartbeat(dev.deviceId,sessionId,1),true);
    const source='import {createDurableDeviceTrustStore as open} from '+
      JSON.stringify(new URL('../devices/durable-trust.mjs',import.meta.url).href)+
      ';const s=open({directory:process.argv[1]});console.log(JSON.stringify(s.registry.listDevices()))';
    const other=JSON.parse(execFileSync(process.execPath,['--input-type=module','-e',source,dir],{encoding:'utf8'}));
    assert.equal(other[0].deviceId,dev.deviceId);
    assert.equal(other[0].online,false);
    assert.equal(other[0].lastSeenAt,null);
  });
});
test('saved file exposes no session secrets or private key material and retains strict modes',()=>{
  temp(dir=>{
    const store=createDurableDeviceTrustStore({directory:dir});
    const key=generate();
    const d=store.trustDevice(metadata(key));
    assert.equal(lstatSync(dir).mode&0o777,0o700);
    assert.equal(lstatSync(file(dir)).mode&0o777,0o600);
    const saved=readFileSync(file(dir),'utf8');
    assert.equal(saved.includes('PRIVATE KEY'),false);
    assert.equal(saved.includes('sessionId'),false);
    assert.equal(saved.includes('nonce'),false);
    const object=JSON.parse(saved);
    assert.deepEqual(Object.keys(object).sort(),['devices','revision','version']);
    assert.deepEqual(Object.keys(object.devices[0]).sort(),
      ['deviceId','fingerprint','name','platform','publicKeyPem']);
    assert.equal(object.devices[0].deviceId,d.deviceId);
  });
});
test('revocation persists to disk and invalidates a live session',()=>{
  temp(dir=>{
    const key=generate();
    const store=createDurableDeviceTrustStore({directory:dir});
    const d=store.trustDevice(metadata(key));
    const {nonce}=store.registry.beginHandshake(d.deviceId);
    const {sessionId}=store.registry.completeHandshake(d.deviceId,key.sign(deviceChallengeMessage(d.deviceId,nonce)));
    assert.equal(store.registry.heartbeat(d.deviceId,sessionId,1),true);
    assert.equal(store.registry.isLiveSession(d.deviceId,sessionId),true);
    assert.equal(store.revokeDevice(d.deviceId),true);
    assert.equal(store.registry.isLiveSession(d.deviceId,sessionId),false);
    assert.equal(store.registry.listDevices().length,0);
    assert.equal(createDurableDeviceTrustStore({directory:dir}).registry.listDevices().length,0);
    assert.equal(store.revision(),2);
    assert.equal(store.revokeDevice(d.deviceId),false);
  });
});
test('adding another trusted record fences all pre-existing sessions',()=>{
  temp(dir=>{
    const store=createDurableDeviceTrustStore({directory:dir});
    const key=generate();
    const d=store.trustDevice(metadata(key));
    const {nonce}=store.registry.beginHandshake(d.deviceId);
    const {sessionId}=store.registry.completeHandshake(d.deviceId,key.sign(deviceChallengeMessage(d.deviceId,nonce)));
    store.registry.heartbeat(d.deviceId,sessionId,1);
    store.trustDevice(metadata(generate(),'VPS gui'));
    assert.equal(store.registry.isLiveSession(d.deviceId,sessionId),false);
    assert.equal(store.registry.listDevices().length,2);
  });
});
test('invalid duplicate public keys and capacity fail without revision change',()=>{
  temp(dir=>{
    const store=createDurableDeviceTrustStore({directory:dir,maxDevices:1});
    const key=generate();
    store.trustDevice(metadata(key));
    assert.throws(()=>store.trustDevice(metadata(key)),/capacity/);
    assert.throws(()=>store.trustDevice(metadata(generate())),/capacity/);
    assert.equal(store.revision(),1);
    assert.equal(store.registry.listDevices().length,1);
  });
});
test('write failure poisons in-memory trust facade rather than allowing session continuation',()=>{
  temp(dir=>{
    const store=createDurableDeviceTrustStore({directory:dir});
    const d=store.trustDevice(metadata(generate()));
    chmodSync(dir,0o500);
    try{
      assert.throws(()=>store.revokeDevice(d.deviceId));
      assert.throws(()=>store.registry.listDevices(),/Trust store unavailable/);
      assert.throws(()=>store.registry.isLiveSession(d.deviceId,'fake'),/Trust store unavailable/);
      assert.throws(()=>store.trustDevice(metadata(generate())),/Trust store unavailable/);
    }finally{chmodSync(dir,0o700);}
  });
});
test('world-readable store is refused',()=>{
  temp(dir=>{
    const store=createDurableDeviceTrustStore({directory:dir});
    store.trustDevice(metadata(generate()));
    chmodSync(file(dir),0o644);
    assert.throws(()=>createDurableDeviceTrustStore({directory:dir}),/Unsafe trust file/);
  });
});
test('world-readable or symlinked directory is refused',()=>{
  temp((dir,parent)=>{
    const store=createDurableDeviceTrustStore({directory:dir});
    store.trustDevice(metadata(generate()));
    chmodSync(dir,0o755);
    assert.throws(()=>createDurableDeviceTrustStore({directory:dir}),/Unsafe trust directory/);
    chmodSync(dir,0o700);
    symlinkSync(dir,path.join(parent,'link'));
    assert.throws(()=>createDurableDeviceTrustStore({directory:path.join(parent,'link')}),/Unsafe trust directory/);
  });
});
test('corrupt trust file never silently reapproves a device',()=>{
  temp(dir=>{
    const store=createDurableDeviceTrustStore({directory:dir});
    store.trustDevice(metadata(generate()));
    writeFileSync(file(dir),'{garbage');
    assert.throws(()=>createDurableDeviceTrustStore({directory:dir}),/Invalid trust document/);
  });
});
test('tampered metadata and fingerprint fail closed on restoration',()=>{
  temp(dir=>{
    const store=createDurableDeviceTrustStore({directory:dir});
    store.trustDevice(metadata(generate()));
    const o=JSON.parse(readFileSync(file(dir),'utf8'));
    o.devices[0].fingerprint='0'.repeat(64);
    writeFileSync(file(dir),JSON.stringify(o));
    assert.throws(()=>createDurableDeviceTrustStore({directory:dir}),/Invalid or duplicated trusted identity/);
  });
});
test('stored revisions reject unknown schema or invalid values',()=>{
  temp(dir=>{
    const store=createDurableDeviceTrustStore({directory:dir});
    store.trustDevice(metadata(generate()));
    const o=JSON.parse(readFileSync(file(dir),'utf8'));
    o.revision=-1;
    writeFileSync(file(dir),JSON.stringify(o));
    assert.throws(()=>createDurableDeviceTrustStore({directory:dir}),/Invalid trust document/);
    o.revision=1;o.extra='unexpected';
    writeFileSync(file(dir),JSON.stringify(o));
    assert.throws(()=>createDurableDeviceTrustStore({directory:dir}),/Invalid trust document/);
  });
});
test('file symlink cannot be followed',{skip:process.platform==='win32'},()=>{
  temp((dir,parent)=>{
    const store=createDurableDeviceTrustStore({directory:dir});
    store.trustDevice(metadata(generate()));
    const backup=path.join(parent,'saved.json');
    const original=readFileSync(file(dir));
    writeFileSync(backup,original,{mode:0o600});
    rmSync(file(dir));
    symlinkSync(backup,file(dir));
    assert.throws(()=>createDurableDeviceTrustStore({directory:dir}));
  });
});
test('read-only registry facade does not expose mutating trust methods',()=>{
  temp(dir=>{
    const store=createDurableDeviceTrustStore({directory:dir});
    assert.equal(store.registry.trustDevice,undefined);
    assert.equal(store.registry.revokeDevice,undefined);
  });
});

test('dangling symlink at trust path is rejected instead of becoming a fresh empty registry',()=>{
  temp((dir,parent)=>{
    createDurableDeviceTrustStore({directory:dir});
    symlinkSync(path.join(parent,'missing-trust-file'),file(dir));
    assert.throws(()=>createDurableDeviceTrustStore({directory:dir}),/Unsafe trust file/);
  });
});
test('trust revision exhaustion denies mutation and blocks further session access',()=>{
  temp(dir=>{
    const store=createDurableDeviceTrustStore({directory:dir});
    store.trustDevice(metadata(generate()));
    const snapshot=JSON.parse(readFileSync(file(dir),'utf8'));
    snapshot.revision=Number.MAX_SAFE_INTEGER;
    writeFileSync(file(dir),JSON.stringify(snapshot));
    const restarted=createDurableDeviceTrustStore({directory:dir});
    assert.throws(()=>restarted.trustDevice(metadata(generate())),/revision exhausted/);
    assert.throws(()=>restarted.registry.listDevices(),/Trust store unavailable/);
  });
});
test('stale second writer cannot overwrite another process trust revision',()=>{
  temp(dir=>{
    const first=createDurableDeviceTrustStore({directory:dir});
    const second=createDurableDeviceTrustStore({directory:dir});
    first.trustDevice(metadata(generate(),'first'));
    assert.throws(()=>second.trustDevice(metadata(generate(),'second')),/changed by another process/);
    assert.throws(()=>second.registry.listDevices(),/Trust store unavailable/);
    const read=createDurableDeviceTrustStore({directory:dir});
    assert.equal(read.registry.listDevices().length,1);
  });
});
test('pre-commit stale snapshot releases its own lock for recovery',()=>{
  temp(dir=>{
    const store=createDurableDeviceTrustStore({directory:dir});
    store.trustDevice(metadata(generate(),'first'));
    const lock=path.join(dir,'.trusted-devices-writer.lock');
    const originalMkdirSync=fs.mkdirSync;
    fs.mkdirSync=(...args)=>{
      const result=originalMkdirSync(...args);
      if(args[0]===lock){
        const snapshot=JSON.parse(readFileSync(file(dir),'utf8'));
        snapshot.revision++;
        writeFileSync(file(dir),JSON.stringify(snapshot)+'\n');
      }
      return result;
    };
    syncBuiltinESMExports();
    try{
      assert.throws(()=>store.trustDevice(metadata(generate(),'second')),
        /Trust store changed by another process/);
      assert.throws(()=>lstatSync(lock),{code:'ENOENT'});
      const recovered=createDurableDeviceTrustStore({directory:dir});
      assert.equal(recovered.revision(),2);
      assert.equal(recovered.registry.listDevices().length,1);
    }finally{
      fs.mkdirSync=originalMkdirSync;
      syncBuiltinESMExports();
    }
  });
});
test('two OS processes racing from one trust revision commit at most one writer',async()=>{
  await tempAsync(dir=>new Promise((resolve,reject)=>{
    const source=`
      const {createDurableDeviceTrustStore}=await import('./gateway/devices/durable-trust.mjs');
      const {generateKeyPairSync}=await import('node:crypto');
      const store=createDurableDeviceTrustStore({directory:process.argv[1]});
      process.stdout.write('READY\\n');
      process.stdin.once('data',()=>{
        try{
          const {publicKey}=generateKeyPairSync('ed25519');
          store.trustDevice({name:process.argv[2],platform:'linux',
            publicKeyPem:publicKey.export({format:'pem',type:'spki'})});
          process.stdout.write('RESULT:OK\\n');
        }catch{process.stdout.write('RESULT:ERR\\n');}
        process.stdin.destroy();
      });
    `;
    const children=['first','second'].map(name=>spawn(process.execPath,
      ['--input-type=module','-e',source,dir,name],{cwd:process.cwd()}));
    const outputs=children.map(()=> '');
    let ready=0;
    const maybeGo=()=>{
      if(ready===children.length){for(const child of children)child.stdin.write('go\n');}
    };
    const results=[];
    let exited=0;
    children.forEach((child,index)=>{
      child.stdout.setEncoding('utf8');
      child.stderr.setEncoding('utf8');
      child.stdout.on('data',chunk=>{
        outputs[index]+=chunk;
        if(outputs[index].includes('READY\n')){ready++;maybeGo();}
        for(const match of chunk.matchAll(/RESULT:(OK|ERR)\n/g))results.push(match[1]);
      });
      child.on('error',reject);
      child.on('exit',(code,signal)=>{
        if(code!==0)reject(Error(`writer child failed: ${code??signal}; ${outputs[index]}`));
        exited++;
        if(exited===children.length){
          try{
            assert.equal(results.filter(x=>x==='OK').length,1);
            assert.equal(results.filter(x=>x==='ERR').length,1);
            const restarted=createDurableDeviceTrustStore({directory:dir});
            assert.equal(restarted.revision(),1);
            assert.equal(restarted.registry.listDevices().length,1);
            resolve();
          }catch(error){reject(error);}
        }
      });
    });
    setTimeout(()=>reject(Error(`writer children did not finish: ${outputs.join(' | ')}`)),10_000).unref();
  }));
});
test('exclusive lock blocks writers and keeps service fail-closed',()=>{
  temp(dir=>{
    const store=createDurableDeviceTrustStore({directory:dir});
    const lock=path.join(dir,'.trusted-devices-writer.lock');
    mkdirSync(lock,{mode:0o700});
    assert.throws(()=>store.trustDevice(metadata(generate())),/EEXIST/);
    assert.throws(()=>store.registry.listDevices(),/Trust store unavailable/);
  });
});
