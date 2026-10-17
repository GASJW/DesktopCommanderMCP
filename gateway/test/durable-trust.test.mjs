import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPublicKey, generateKeyPairSync, randomUUID, sign } from 'node:crypto';
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
function runTrustRace(directory,jobs){
  return new Promise((resolve,reject)=>{
    const source=`
      import {createDurableDeviceTrustStore} from './gateway/devices/durable-trust.mjs';
      const [directory,operation,deviceId,name,publicKeyPem,eventId,requestId,fingerprint]=process.argv.slice(1);
      const store=createDurableDeviceTrustStore({directory});
      process.stdout.write('READY\\n');
      process.stdin.once('data',()=>{
        try{
          if(operation==='approve')store.trustDevice({name,platform:'linux',publicKeyPem},
            {expectedRevision:store.revision(),decision:{eventId,requestId,fingerprint}});
          else store.revokeDevice(deviceId);
          process.stdout.write('RESULT:OK\\n');
        }catch{process.stdout.write('RESULT:ERR\\n');}
        process.stdin.destroy();
      });
    `;
    const children=jobs.map(job=>spawn(process.execPath,
      ['--input-type=module','-e',source,directory,job.operation,job.deviceId??'',
        job.name??'',job.publicKeyPem??'',job.eventId??'',job.requestId??'',job.fingerprint??''],
      {cwd:process.cwd()}));
    const output=children.map(()=> '');
    const ready=children.map(()=> false);
    let exited=0,finished=false;
    const timer=setTimeout(()=>{
      if(finished)return;
      for(const child of children)child.kill('SIGKILL');
      finished=true;reject(Error(`trust race timed out: ${output.join(' | ')}`));
    },10_000);
    const maybeStart=()=>{
      if(ready.every(Boolean))for(const child of children)child.stdin.write('go\n');
    };
    children.forEach((child,index)=>{
      child.stdout.setEncoding('utf8');child.stderr.setEncoding('utf8');
      child.stdout.on('data',chunk=>{
        output[index]+=chunk;
        if(!ready[index]&&output[index].includes('READY\n')){ready[index]=true;maybeStart();}
      });
      child.on('error',error=>{if(!finished){finished=true;clearTimeout(timer);reject(error);}});
      child.on('exit',(code,signal)=>{
        if(code!==0&&!finished){finished=true;clearTimeout(timer);
          reject(Error(`trust race child failed: ${code??signal}; ${output[index]}`));return;}
        exited++;
        if(exited===children.length&&!finished){
          finished=true;clearTimeout(timer);
          const results=output.map(text=>text.match(/RESULT:(OK|ERR)\n/)?.[1]);
          if(results.some(result=>!result))reject(Error(`missing trust race result: ${output.join(' | ')}`));
          else resolve(results);
        }
      });
    });
  });
}
async function tempProcess(testFn){
  const parent=mkdtempSync(path.join(os.tmpdir(),'vpsc-g7-crash-'));
  const directory=path.join(parent,'server');
  try{return await testFn(directory);}finally{rmSync(parent,{recursive:true,force:true});}
}
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
test('owner trust transition atomically stores the audit event binding and revision pair',()=>{
  temp(dir=>{
    const store=createDurableDeviceTrustStore({directory:dir});
    const key=generate();
    const fingerprint=createHash('sha256').update(createPublicKey(key.publicKeyPem)
      .export({type:'spki',format:'der'})).digest('hex');
    const decision={eventId:randomUUID(),requestId:randomUUID(),fingerprint};
    const trusted=store.trustDevice(metadata(key),{expectedRevision:0,decision});
    const snapshot=JSON.parse(readFileSync(file(dir),'utf8'));
    assert.equal(snapshot.version,2);
    assert.equal(snapshot.revision,1);
    assert.deepEqual(snapshot.transitions,[{
      eventId:decision.eventId,requestId:decision.requestId,fingerprint,
      deviceId:trusted.deviceId,operation:'approve',previousRevision:0,revision:1,
    }]);
  });
});
test('eventId and requestId cannot authorize a second trust transition after restart',()=>{
  temp(dir=>{
    const first=createDurableDeviceTrustStore({directory:dir});
    const eventId=randomUUID(),requestId=randomUUID();
    const key=generate();
    const fingerprint=createHash('sha256').update(createPublicKey(key.publicKeyPem)
      .export({type:'spki',format:'der'})).digest('hex');
    first.trustDevice(metadata(key),{expectedRevision:0,decision:{eventId,requestId,fingerprint}});
    const restarted=createDurableDeviceTrustStore({directory:dir});
    const different=generate();
    const otherFingerprint=createHash('sha256').update(createPublicKey(different.publicKeyPem)
      .export({type:'spki',format:'der'})).digest('hex');
    assert.throws(()=>restarted.trustDevice(metadata(different),{expectedRevision:1,
      decision:{eventId,requestId:randomUUID(),fingerprint:otherFingerprint}}),/already applied/);
    assert.throws(()=>restarted.trustDevice(metadata(different),{expectedRevision:1,
      decision:{eventId:randomUUID(),requestId,fingerprint:otherFingerprint}}),/already applied/);
    assert.equal(restarted.revision(),1);
    assert.equal(restarted.registry.listDevices().length,1);
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
    assert.deepEqual(Object.keys(object).sort(),
      ['devices','historyStartDevices','historyStartRevision','revision','transitions','version']);
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
    assert.throws(()=>createDurableDeviceTrustStore({directory:dir}),
      /Invalid or duplicated trusted identity|contradicts transition history/);
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
    snapshot.version=1;
    delete snapshot.historyStartRevision;
    delete snapshot.historyStartDevices;
    delete snapshot.transitions;
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
        snapshot.historyStartRevision=snapshot.revision;
        snapshot.historyStartDevices=snapshot.devices.map(({deviceId,fingerprint})=>({deviceId,fingerprint}));
        snapshot.transitions=[];
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
test('two OS processes cannot apply one owner decision to two device keys',async()=>{
  await tempAsync(async dir=>{
    createDurableDeviceTrustStore({directory:dir});
    const eventId=randomUUID(),requestId=randomUUID();
    const keys=[generate(),generate()];
    const jobs=keys.map((key,index)=>({operation:'approve',name:`device-${index}`,
      publicKeyPem:key.publicKeyPem,eventId,requestId,
      fingerprint:createHash('sha256').update(createPublicKey(key.publicKeyPem)
        .export({type:'spki',format:'der'})).digest('hex')}));
    const results=await runTrustRace(dir,jobs);
    assert.equal(results.filter(result=>result==='OK').length,1);
    assert.equal(results.filter(result=>result==='ERR').length,1);
    const restarted=createDurableDeviceTrustStore({directory:dir});
    assert.equal(restarted.revision(),1);
    assert.equal(restarted.registry.snapshotTrustedDevices().length,1);
    const snapshot=JSON.parse(readFileSync(file(dir),'utf8'));
    assert.equal(snapshot.transitions.filter(item=>item.eventId===eventId).length,1);
    assert.equal(snapshot.transitions[0].requestId,requestId);
  });
});
test('approval racing a revocation cannot overwrite the competing trust revision',async()=>{
  await tempAsync(async dir=>{
    const initial=createDurableDeviceTrustStore({directory:dir});
    const existing=initial.trustDevice(metadata(generate(),'existing'));
    const next=generate(),eventId=randomUUID(),requestId=randomUUID();
    const fingerprint=createHash('sha256').update(createPublicKey(next.publicKeyPem)
      .export({type:'spki',format:'der'})).digest('hex');
    const results=await runTrustRace(dir,[
      {operation:'revoke',deviceId:existing.deviceId},
      {operation:'approve',name:'new',publicKeyPem:next.publicKeyPem,eventId,requestId,fingerprint},
    ]);
    assert.equal(results.filter(result=>result==='OK').length,1);
    assert.equal(results.filter(result=>result==='ERR').length,1);
    const restarted=createDurableDeviceTrustStore({directory:dir});
    assert.equal(restarted.revision(),2);
    const snapshot=JSON.parse(readFileSync(file(dir),'utf8'));
    if(snapshot.transitions[1].operation==='revoke'){
      assert.equal(results[0],'OK');assert.equal(results[1],'ERR');
      assert.deepEqual(restarted.registry.snapshotTrustedDevices(),[]);
    }else{
      assert.equal(snapshot.transitions[1].operation,'approve');
      assert.equal(results[0],'ERR');assert.equal(results[1],'OK');
      assert.deepEqual(new Set(restarted.registry.snapshotTrustedDevices().map(d=>d.deviceId)),
        new Set([existing.deviceId,snapshot.transitions[1].deviceId]));
    }
  });
});
test('exclusive lock blocks writers and keeps service fail-closed',()=>{
  temp(dir=>{
    const store=createDurableDeviceTrustStore({directory:dir});
    const lock=path.join(dir,'.trusted-devices-writer.lock');
    mkdirSync(lock,{mode:0o700});
    assert.throws(()=>store.trustDevice(metadata(generate())),/EEXIST|lock present/);
    assert.throws(()=>store.registry.listDevices(),/Trust store unavailable/);
  });
});
test('killed writer process leaves a durable lock that blocks restart',async()=>{
  await tempProcess(dir=>new Promise((resolve,reject)=>{
    const source=`
      import fs from 'node:fs';
      import {syncBuiltinESMExports} from 'node:module';
      fs.fsyncSync=()=>{
        process.stdout.write('LOCKED\\n');
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,120000);
      };
      syncBuiltinESMExports();
      const {createDurableDeviceTrustStore}=await import('./gateway/devices/durable-trust.mjs');
      const {generateKeyPairSync}=await import('node:crypto');
      const store=createDurableDeviceTrustStore({directory:process.argv[1]});
      const {publicKey}=generateKeyPairSync('ed25519');
      store.trustDevice({name:'crash-writer',platform:'linux',
        publicKeyPem:publicKey.export({format:'pem',type:'spki'})});
    `;
    const child=spawn(process.execPath,['--input-type=module','-e',source,dir],
      {cwd:process.cwd(),stdio:['ignore','pipe','pipe']});
    let output='';
    child.stdout.setEncoding('utf8');
    child.stdout.on('data',chunk=>{
      output+=chunk;
      if(output.includes('LOCKED\n'))child.kill('SIGKILL');
    });
    child.on('error',reject);
    child.on('exit',(code,signal)=>{
      try{
        assert.equal(signal,'SIGKILL');
        assert.equal(lstatSync(path.join(dir,'.trusted-devices-writer.lock')).isDirectory(),true);
        assert.throws(()=>createDurableDeviceTrustStore({directory:dir}),
          /Trust writer lock present/);
        resolve();
      }catch(error){reject(error);}
    });
    setTimeout(()=>{child.kill('SIGKILL');reject(Error(`writer did not reach lock: ${output}`));},10_000).unref();
  }));
});
