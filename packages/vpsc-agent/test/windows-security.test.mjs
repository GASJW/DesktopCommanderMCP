import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { analyzeDeviceIdentityBindingRecovery, bindApprovedDeviceIdentity,
  clearStaleDeviceIdentityBindingLock, loadOrCreateDeviceIdentity } from '../src/identity-store.mjs';
import { createWindowsDurableProcessLock, createWindowsFileBeneath,
  inspectWindowsFileLock, listWindowsDirectoryBeneath, moveWindowsFileWriteThrough,
  readWindowsFileBeneath, removeDeadWindowsFileLock, removeOwnedWindowsDurableProcessLock,
  securePrivateWindowsDirectory, securePrivateWindowsFile, verifyPrivateWindowsDirectory, verifyPrivateWindowsFile,
  verifyWindowsOperationRoot } from '../src/windows-security.mjs';

const windowsOnly={skip:process.platform!=='win32'};
async function sandbox(fn){
  const base=mkdtempSync(path.join(os.tmpdir(),'g7-windows-security-'));
  try{return await fn(base);}finally{rmSync(base,{recursive:true,force:true});}
}

test('Windows Ed25519 identity survives DPAPI reload, durable binding replacement and stale-lock recovery',windowsOnly,async()=>{
  await sandbox(base=>{
    const directory=path.join(base,'identity');mkdirSync(directory);securePrivateWindowsDirectory(directory);
    const identity=loadOrCreateDeviceIdentity({directory});
    const binding={deviceId:randomUUID(),clientId:'g7-windows-pilot.synthetic',
      fingerprint:identity.fingerprint,approvalEventId:randomUUID(),bindingEventId:randomUUID(),
      bindingRevision:2,ownerId:'a'.repeat(24),ownerDigest:'b'.repeat(64),
      trustRevisionBefore:4,trustRevisionAfter:5,trustRevision:5};
    const bound=bindApprovedDeviceIdentity({directory,machineBinding:binding});
    assert.equal(bound.deviceBinding.bindingEventId,binding.bindingEventId);
    assert.equal(loadOrCreateDeviceIdentity({directory}).fingerprint,identity.fingerprint);
    verifyPrivateWindowsFile(path.join(directory,'identity-v1.json'));
    const deadOwner={version:1,kind:'device-identity-binding',pid:2147483647,startTicks:'0',token:randomUUID()};
    const lockPath=path.join(directory,'identity-binding.lock');
    createWindowsFileBeneath(directory,lockPath,Buffer.from(JSON.stringify(deadOwner)+'\n'));
    securePrivateWindowsFile(lockPath);
    const diagnosis=analyzeDeviceIdentityBindingRecovery({directory});
    assert.equal(diagnosis.state,'STALE_LOCK');
    const cleared=clearStaleDeviceIdentityBindingLock({directory,
      expectedLockDigest:diagnosis.lockDigest,operatorConfirmedNoActiveWriters:true,
      verifyMachineBinding:value=>value.fingerprint===identity.fingerprint&&
        value.binding?.bindingEventId===binding.bindingEventId});
    assert.equal(cleared,true);
    assert.equal(analyzeDeviceIdentityBindingRecovery({directory}).state,'CLEAN');
    assert.equal(loadOrCreateDeviceIdentity({directory}).deviceBinding.bindingEventId,binding.bindingEventId);
    const stored=JSON.parse(readFileSync(path.join(directory,'identity-v1.json'),'utf8'));
    assert.equal(stored.encoding,'dpapi-current-user');
    assert.equal(stored.key.includes('PRIVATE KEY'),false);
  });
});

test('Windows file handles reject junction escapes and preserve write-through create semantics',windowsOnly,async()=>{
  await sandbox(base=>{
    const root=path.join(base,'approved'),outside=path.join(base,'outside');
    mkdirSync(root);mkdirSync(outside);securePrivateWindowsDirectory(root);securePrivateWindowsDirectory(outside);
    writeFileSync(path.join(outside,'secret.txt'),'outside secret\n');
    const junction=path.join(root,'escape');symlinkSync(outside,junction,'junction');
    assert.throws(()=>readWindowsFileBeneath(root,path.join(junction,'secret.txt')));
    assert.throws(()=>listWindowsDirectoryBeneath(root,junction,{depth:1}));
    const escapedWrite=path.join(junction,'escaped.txt');
    assert.throws(()=>createWindowsFileBeneath(root,escapedWrite,Buffer.from('must not escape')));
    assert.equal(existsSync(path.join(outside,'escaped.txt')),false);
    assert.equal(verifyWindowsOperationRoot(root),root);
    const target=path.join(root,'state.txt'),temp=path.join(root,'state.next');
    createWindowsFileBeneath(root,target,Buffer.from('first\n'));
    createWindowsFileBeneath(root,temp,Buffer.from('second\n'));
    securePrivateWindowsFile(temp);
    moveWindowsFileWriteThrough(temp,target);
    assert.equal(readWindowsFileBeneath(root,target).toString(),'second\n');
    const createOnly=path.join(root,'create-only.next');
    createWindowsFileBeneath(root,createOnly,Buffer.from('third\n'));
    assert.throws(()=>moveWindowsFileWriteThrough(createOnly,target,{replace:false}));
    assert.equal(readWindowsFileBeneath(root,target).toString(),'second\n');
    assert.deepEqual(listWindowsDirectoryBeneath(root,root,{depth:0,limit:10}).entries
      .filter(item=>item.type==='reparse').map(item=>item.name),['escape']);
  });
});

test('Windows private-state verification rejects a broad Everyone write ACL',windowsOnly,async()=>{
  await sandbox(base=>{
    const directory=path.join(base,'private');mkdirSync(directory);securePrivateWindowsDirectory(directory);
    const icacls=path.join(process.env.SystemRoot??'C:\\Windows','System32','icacls.exe');
    execFileSync(icacls,[directory,'/grant','*S-1-1-0:(OI)(CI)M'],{windowsHide:true});
    assert.throws(()=>verifyPrivateWindowsDirectory(directory),error=>error.code==='WINDOWS_SECURITY');
  });
});

test('Windows identity storage rejects a reparse-point ancestor',windowsOnly,async()=>{
  await sandbox(base=>{
    const target=path.join(base,'actual');mkdirSync(target);securePrivateWindowsDirectory(target);
    const junction=path.join(base,'state-link');symlinkSync(target,junction,'junction');
    assert.throws(()=>loadOrCreateDeviceIdentity({directory:junction}));
    assert.equal(existsSync(path.join(target,'identity-v1.json')),false);
  });
});

test('Windows execution lock excludes a second writer and releases by owner identity',windowsOnly,async()=>{
  await sandbox(async base=>{
    const directory=path.join(base,'state');mkdirSync(directory);securePrivateWindowsDirectory(directory);
    const owner=await createWindowsDurableProcessLock(directory,'execution.lock','i4-agent-op');
    assert.equal(inspectWindowsFileLock(directory,'execution.lock').status,'active');
    await assert.rejects(createWindowsDurableProcessLock(directory,'execution.lock','i4-agent-op'),
      error=>error.code==='EEXIST');
    await removeOwnedWindowsDurableProcessLock({directory,name:'execution.lock',owner});
    assert.equal(inspectWindowsFileLock(directory,'execution.lock').status,'absent');
  });
});
