#!/usr/bin/env node
// G3.5 preflight: real MCP executor, synthetic signed Access JWT, private socket and ephemeral port.
// Never connects to the live tunnel, writes credentials, or changes systemd.
import {generateKeyPairSync,sign} from 'node:crypto';
import {mkdtempSync,rmSync} from 'node:fs';
import path from 'node:path';
import {startExecutor} from '../gateway/executor-socket.mjs';
import {startGateway} from '../gateway/server.mjs';

const dir=mkdtempSync('/var/lib/vps-commander/workspace/.g35-');
const socketPath=path.join(dir,'executor.sock');
const issuer='https://example.cloudflareaccess.com';
const audience='b'.repeat(64);
const allowedEmails='owner@example.test';
const keyPair=generateKeyPairSync('rsa',{modulusLength:2048});
const publicJwk={...keyPair.publicKey.export({format:'jwk'}),kid:'test-origin',alg:'RS256',use:'sig'};
const jwt=(email=allowedEmails)=>{
  const now=Math.floor(Date.now()/1000);
  const h=Buffer.from(JSON.stringify({alg:'RS256',kid:'test-origin'})).toString('base64url');
  const p=Buffer.from(JSON.stringify({iss:issuer,aud:[audience],sub:'authorized-test',email,iat:now,exp:now+900})).toString('base64url');
  const msg=h+'.'+p;
  return msg+'.'+sign('RSA-SHA256',Buffer.from(msg),keyPair.privateKey).toString('base64url');
};
let worker,gateway;
try {
  worker=await startExecutor({socketPath,executorFile:'/opt/vps-commander/code/dist/index.js',cwd:dir});
  gateway=await startGateway({authMode:'access',accessIssuer:issuer,accessAudience:audience,
    allowedEmails,accessKeyProvider:async()=>({keys:[publicJwk]}),
    executorSocket:socketPath,port:0});
  const request=async(id,method,params={},assertion=jwt())=>{
    const res=await fetch(gateway.address+'/mcp',{method:'POST',headers:{'content-type':'application/json',
      ...(assertion?{'cf-access-jwt-assertion':assertion}:{})},
      body:JSON.stringify({jsonrpc:'2.0',id,method,params})});
    return {status:res.status,data:await res.json()};
  };
  const list=await request(1,'tools/list');
  const tools=list.data.result?.tools;
  if(list.status!==200||!tools?.some(t=>t.name==='start_process'))throw Error('Real authenticated tools/list failed');
  console.log('G3_5_REAL_TOOLS='+tools.length);
  const shell=await request(2,'tools/call',{name:'start_process',
    arguments:{command:'printf G3_5_REAL_OAUTH_GREEN',timeout_ms:1000}});
  if(shell.status!==200||shell.data.result?.isError||
     !JSON.stringify(shell.data.result?.content).includes('G3_5_REAL_OAUTH_GREEN'))
       throw Error('Authenticated shell call failed');
  console.log('G3_5_REAL_SHELL=GREEN');
  const file=await request(3,'tools/call',{name:'read_file',arguments:{path:'/etc/os-release',length:3}});
  if(file.status!==200||file.data.result?.isError||
    !JSON.stringify(file.data.result?.content).includes('Ubuntu'))throw Error('Authenticated read_file failed');
  console.log('G3_5_REAL_FILE=GREEN');
  if((await request(4,'tools/list',{},jwt('intruder@example.test'))).status!==401)
    throw Error('Nonowner token was accepted');
  if((await request(5,'tools/list',{},'')).status!==401)
    throw Error('Missing assertion was accepted');
  if((await request(6,'sampling/createMessage',{})).status!==404)
    throw Error('Unsupported method forwarded');
  if((await request(7,'tools/call',{name:'../invalid',arguments:{}})).status!==400)
    throw Error('Invalid tool params accepted');
  console.log('G3_5_NEGATIVE_AUTHORIZATION=GREEN');
} finally {
  await gateway?.close();await worker?.close();rmSync(dir,{recursive:true,force:true});
}
