#!/usr/bin/env node
import { request as httpsRequest } from 'node:https';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { bindApprovedDeviceIdentity, loadOrCreateDeviceIdentity } from '../packages/vpsc-agent/src/identity-store.mjs';
import { readPrivateStagingFile } from '../gateway/staging/private-file.mjs';
import { assertNotElevatedWindows, readPrivateWindowsFile } from '../packages/vpsc-agent/src/windows-security.mjs';

const HOST='g7-staging.test';
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&
  Object.getPrototypeOf(value)===Object.prototype&&Object.keys(value).sort().join(',')===keys;
const failure=code=>Object.assign(new Error(code),{code});
function privateFile(filename,{privateOnly=true}={}){
  return process.platform==='win32'
    ?readPrivateWindowsFile(filename,{privateOnly,maxBytes:64*1024})
    :readPrivateStagingFile(filename,{privateOnly});
}
function configFrom(filename){
  if(process.platform==='win32')assertNotElevatedWindows();
  else if(process.platform!=='linux'||typeof process.getuid!=='function'||process.getuid()===0)throw failure('PRIVILEGE');
  let config;
  try{config=JSON.parse(privateFile(filename).toString('utf8'));}
  catch{throw failure('CONFIG_FILE');}
  if(!exact(config,'caPath,deviceName,hostname,identityDirectory,port,version')||config.version!==1||
     config.hostname!==HOST||typeof config.deviceName!=='string'||
     !/^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$/.test(config.deviceName)||
     typeof config.port!=='number'||!Number.isSafeInteger(config.port)||config.port<1||config.port>65535||
     ![config.caPath,config.identityDirectory].every(value=>typeof value==='string'&&
       path.isAbsolute(value)&&path.normalize(value)===value))throw failure('CONFIG_INVALID');
  try{config.ca=privateFile(config.caPath,{privateOnly:false});}
  catch(error){throw failure(error?.message==='Unsafe staging configuration directory'
    ?'CONFIG_CA_DIRECTORY':error?.message==='Unsafe staging configuration file'
      ?'CONFIG_CA_FILE':'CONFIG_CA_READ');}
  return config;
}
function post(config,pathname,body){
  const data=Buffer.from(JSON.stringify(body));
  return new Promise((resolve,reject)=>{
    const req=httpsRequest({hostname:'127.0.0.1',port:config.port,servername:HOST,
      method:'POST',path:pathname,headers:{host:HOST,'content-type':'application/json',
        accept:'application/json','content-length':data.length},ca:config.ca,rejectUnauthorized:true},res=>{
      const chunks=[];let size=0;
      res.on('data',chunk=>{size+=chunk.length;if(size>64*1024){req.destroy();return;}chunks.push(chunk);});
      res.on('end',()=>{
        try{resolve({status:res.statusCode,json:JSON.parse(Buffer.concat(chunks,size).toString('utf8'))});}
        catch{reject(failure('TRANSPORT'));}
      });
    });
    req.setTimeout(12_000,()=>req.destroy());
    req.once('error',error=>reject(Object.assign(failure('TRANSPORT'),{
      causeCode:/^[A-Z][A-Z0-9_]{1,40}$/.test(error?.code??'')?error.code:'UNKNOWN',
    })));
    req.end(data);
  });
}
async function run(args){
  let phase='CONFIG';
  try{
  const receiptMode=args.length===4&&args[0]==='--config'&&args[2]==='--binding-receipt';
  const pairMode=args.length===2&&args[0]==='--config';
  if(!receiptMode&&!pairMode)throw failure('USAGE');
  const config=configFrom(args[1]);
  phase='IDENTITY';
  const identity=loadOrCreateDeviceIdentity({directory:config.identityDirectory,platform:process.platform});
  if(receiptMode){
    phase='BINDING';
    const receipt=JSON.parse(privateFile(args[3]).toString('utf8'));
    const binding=receipt?.binding;
    if(receipt?.status!=='provisioned'||receipt.fingerprint!==identity.fingerprint||
       !binding||binding.fingerprint!==identity.fingerprint||binding.deviceId!==receipt.deviceId||
       binding.clientId!==receipt.clientId)throw failure('RECEIPT');
    const stored=bindApprovedDeviceIdentity({directory:config.identityDirectory,machineBinding:binding});
    process.stdout.write(JSON.stringify({status:'bound',deviceId:stored.deviceBinding.deviceId,
      clientId:stored.deviceBinding.clientId,fingerprint:identity.fingerprint,
      bindingRevision:stored.deviceBinding.bindingRevision})+'\n');
    return;
  }
  if(identity.deviceBinding||identity.legacyDeviceBinding)throw failure('ALREADY_BOUND');
  phase='PAIRING';
  const started=await post(config,'/pairing/start',{name:config.deviceName,platform:process.platform,
    publicKeyPem:identity.publicKeyPem});
  if(started.status!==201||!exact(started.json,'displayCode,expiresInMs,fingerprint,nonce,requestId')||
     started.json.fingerprint!==identity.fingerprint||
     !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(started.json.requestId)||
     !/^[A-F0-9]{10}$/.test(started.json.displayCode)||
     !/^[A-Za-z0-9_-]{43}$/.test(started.json.nonce)||
     !Number.isSafeInteger(started.json.expiresInMs)||started.json.expiresInMs<1||started.json.expiresInMs>600_000)
    throw failure('PAIRING');
  const proved=await post(config,'/pairing/prove',{requestId:started.json.requestId,
    proof:identity.prove(started.json)});
  if(proved.status!==200||!exact(proved.json,'proved')||proved.json.proved!==true)throw failure('PAIRING');
  process.stdout.write(JSON.stringify({status:'proof_verified',requestId:started.json.requestId,
    displayCode:started.json.displayCode,fingerprint:identity.fingerprint,
    deviceName:config.deviceName,platform:process.platform})+'\n');
  }catch(error){
    if(!error?.code)error.code=phase;
    throw error;
  }
}

if(process.argv[1]&&import.meta.url===pathToFileURL(path.resolve(process.argv[1])).href){
  run(process.argv.slice(2)).catch(error=>{
    const code=['USAGE','CONFIG','CONFIG_FILE','CONFIG_INVALID','CONFIG_CA','CONFIG_CA_DIRECTORY',
      'CONFIG_CA_FILE','CONFIG_CA_READ','IDENTITY','BINDING',
      'PRIVILEGE','TRANSPORT','PAIRING','RECEIPT','ALREADY_BOUND']
      .includes(error?.code)?error.code:'PAIRING';
    const detail=error?.causeCode?`/${error.causeCode}`:'';
    process.stderr.write(`G7 staging device pairing stopped (${code}${detail}); inspect the Owner and Gateway state before retrying.\n`);
    process.exitCode=1;
  });
}
