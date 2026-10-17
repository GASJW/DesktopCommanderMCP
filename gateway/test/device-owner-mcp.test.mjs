import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request as httpRequest } from 'node:http';
import { generateKeyPairSync, sign } from 'node:crypto';
import { createAccessVerifier } from '../access-auth.mjs';
import { createRemoteDeviceMcpHandler } from '../devices/remote-mcp-handler.mjs';

const ISSUER='https://i3-owner-test.cloudflareaccess.com';
const AUD='d'.repeat(64);
const OWNER='i3-owner@example.com';
const DEVICE='b7e92caf-f591-44c4-8fb7-6c489ea573f4';

async function setup(t,{authorizeTool,onResponseClose}={}){
  const {publicKey,privateKey}=generateKeyPairSync('rsa',{modulusLength:2048});
  const jwk={...publicKey.export({format:'jwk'}),kid:'i3-owner',alg:'RS256'};
  const accessVerifier=createAccessVerifier({issuer:ISSUER,audience:AUD,
    allowedEmails:OWNER+',other@example.com',keyProvider:async()=>({keys:[jwk]})});
  const now=Math.floor(Date.now()/1000);
  const tokenFor=(email=OWNER)=>{
    const header=Buffer.from(JSON.stringify({alg:'RS256',kid:'i3-owner'})).toString('base64url');
    const payload=Buffer.from(JSON.stringify({iss:ISSUER,aud:AUD,email,
      sub:email===OWNER?'owner-1':'owner-2',
      iat:now-1,exp:now+300})).toString('base64url');
    return header+'.'+payload+'.'+sign('RSA-SHA256',Buffer.from(header+'.'+payload),privateKey).toString('base64url');
  };
  const machineToken=()=>{
    const header=Buffer.from(JSON.stringify({alg:'RS256',kid:'i3-owner'})).toString('base64url');
    const payload=Buffer.from(JSON.stringify({iss:ISSUER,aud:AUD,sub:'',type:'app',
      common_name:'synthetic-machine-id',iat:now-1,exp:now+300})).toString('base64url');
    return header+'.'+payload+'.'+sign('RSA-SHA256',Buffer.from(header+'.'+payload),privateKey).toString('base64url');
  };
  const calls=[];
  const router={callDevice:async frame=>{
    calls.push(frame);
    return {content:[{type:'text',text:'remote-read-ok'}]};
  }};
  const deviceRegistry={listDevices:()=>[{deviceId:DEVICE}]};
  const handler=createRemoteDeviceMcpHandler({
    accessVerifier,deviceRegistry,router,
    authorizeDevice:(owner,deviceId)=>owner.subject==='owner-1'&&deviceId===DEVICE,
    authorizeTool:authorizeTool??((owner,deviceId,name)=>owner.subject==='owner-1'&&deviceId===DEVICE&&name==='read_file'),
    getTrustRevision:()=>3,getDeviceApprovalReceipt:()=>({
      eventId:'b7e92caf-f591-44c4-8fb7-6c489ea573f5',deviceId:DEVICE,fingerprint:'b'.repeat(64),
      trustRevisionBefore:2,trustRevisionAfter:3,trustRevision:3,
    }),authorizationPolicyRevision:'i4-test-policy-v1',
  });
  const server=createServer((req,res)=>{
    if(onResponseClose)res.once('close',onResponseClose);
    void handler(req,res);
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const endpoint=`http://127.0.0.1:${server.address().port}/mcp`;
  t.after(()=>new Promise(resolve=>server.close(resolve)));
  const call=async(payload,{token=tokenFor(),headers={}}={})=>{
    const response=await fetch(endpoint,{method:'POST',headers:{
      'content-type':'application/json','cf-access-jwt-assertion':token,...headers,
    },body:JSON.stringify(payload)});
    return {status:response.status,body:await response.json()};
  };
  return {call,calls,tokenFor,machineToken,deviceRegistry,router,endpoint};
}

test('owner MCP read call routes only the named trusted device and read_file',async t=>{
  const x=await setup(t);
  const response=await x.call({jsonrpc:'2.0',id:1,method:'tools/call',params:{
    name:'read_file',arguments:{deviceId:DEVICE,path:'/approved/readme.txt',offset:0,length:20},
  }});
  assert.equal(response.status,200);
  assert.equal(response.body.jsonrpc,'2.0');
  assert.equal(response.body.id,1);
  assert.equal(response.body.result.content[0].text,'remote-read-ok');
  assert.equal(x.calls.length,1);
  assert.match(x.calls[0].requestId,/^[0-9a-f-]{36}$/i);
  assert.deepEqual({...x.calls[0],requestId:undefined,authorization:undefined,signal:undefined},{requestId:undefined,
    authorization:undefined,signal:undefined,deviceId:DEVICE,
    name:'read_file',arguments:{path:'/approved/readme.txt',offset:0,length:20}});
});

test('unauthenticated, invalid-owner, and machine-only assertions never dispatch',async t=>{
  const x=await setup(t);
  const payload={jsonrpc:'2.0',id:2,method:'tools/call',params:{
    name:'read_file',arguments:{deviceId:DEVICE,path:'/approved/readme.txt'},
  }};
  for(const token of [null,'not-a-jwt',x.tokenFor('invalid@example.com'),x.machineToken()]){
    const headers=token===null?{'cf-access-jwt-assertion':''}:{'cf-access-jwt-assertion':token};
    const response=await x.call(payload,{token:token??'',headers});
    assert.equal(response.status,401);
  }
  assert.equal(x.calls.length,0);
});

test('remote MCP rejects non-read tools, implicit devices, and untrusted devices',async t=>{
  const x=await setup(t);
  const payloads=[
    {jsonrpc:'2.0',id:3,method:'tools/call',params:{name:'start_process',arguments:{deviceId:DEVICE,command:'id'}}},
    {jsonrpc:'2.0',id:4,method:'tools/call',params:{name:'read_file',arguments:{path:'/approved/readme.txt'}}},
    {jsonrpc:'2.0',id:5,method:'tools/call',params:{name:'read_file',arguments:{deviceId:'00000000-0000-4000-8000-000000000000',path:'/approved/readme.txt'}}},
    {jsonrpc:'2.0',id:6,method:'tools/call',params:{name:'read_file',arguments:{deviceId:DEVICE,path:'https://example.invalid/data'}}},
    {jsonrpc:'2.0',id:7,method:'tools/call',params:{name:'read_file',arguments:{deviceId:DEVICE,path:'/approved/readme.txt',isUrl:true}}},
  ];
  for(const [index,payload] of payloads.entries()){
    const response=await x.call(payload);
    assert.equal(response.status,index===2?403:400);
  }
  assert.equal(x.calls.length,0);
});

test('valid owner Access does not authorize a device without a matching owner-device grant',async t=>{
  const x=await setup(t);
  const response=await x.call({jsonrpc:'2.0',id:12,method:'tools/call',params:{
    name:'read_file',arguments:{deviceId:DEVICE,path:'/approved/readme.txt'},
  }},{token:x.tokenFor('other@example.com')});
  assert.equal(response.status,403);
  assert.equal(response.body.error.code,-32007);
  assert.equal(x.calls.length,0);
});

test('disconnect during tool authorization prevents dispatch to the device',async t=>{
  let enteredAuthorization;
  const authorizationEntered=new Promise(resolve=>{enteredAuthorization=resolve;});
  let releaseAuthorization;
  const authorizationGate=new Promise(resolve=>{releaseAuthorization=resolve;});
  let responseClosed;
  const responseDidClose=new Promise(resolve=>{responseClosed=resolve;});
  const x=await setup(t,{onResponseClose:responseClosed,authorizeTool:async()=>{
    enteredAuthorization();
    await authorizationGate;
    return true;
  }});
  const endpoint=new URL(x.endpoint);
  const request=httpRequest({hostname:endpoint.hostname,port:endpoint.port,path:endpoint.pathname,
    method:'POST',headers:{'content-type':'application/json',
      'cf-access-jwt-assertion':x.tokenFor()} });
  request.on('error',()=>{});
  request.end(JSON.stringify({jsonrpc:'2.0',id:18,method:'tools/call',params:{
    name:'read_file',arguments:{deviceId:DEVICE,path:'/approved/file'},
  }}));
  await authorizationEntered;
  request.destroy();
  await responseDidClose;
  releaseAuthorization();
  await new Promise(resolve=>setImmediate(resolve));
  assert.equal(x.calls.length,0,'a disconnected owner request must not dispatch a device operation');
});

test('wrong HTTP method and browser-origin requests are rejected before dispatch',async t=>{
  const x=await setup(t);
  const payload={jsonrpc:'2.0',id:8,method:'tools/call',params:{
    name:'read_file',arguments:{deviceId:DEVICE,path:'/approved/readme.txt'},
  }};
  const response=await fetch(x.endpoint,{method:'GET',headers:{
    'cf-access-jwt-assertion':x.tokenFor(),
  }});
  assert.equal(response.status,405);
  const originResponse=await x.call(payload,{headers:{origin:'https://evil.invalid'}});
  assert.equal(originResponse.status,403);
  assert.equal(x.calls.length,0);
});

test('trust-store failure and ambiguous router outcome fail closed without retry',async t=>{
  const x=await setup(t);
  const payload={jsonrpc:'2.0',id:9,method:'tools/call',params:{name:'read_file',
    arguments:{deviceId:DEVICE,path:'/approved/readme.txt'}}};
  x.deviceRegistry.listDevices=()=>{throw Error('trust store unavailable');};
  const unavailable=await x.call(payload);
  assert.equal(unavailable.status,503);
  assert.equal(x.calls.length,0);
  x.deviceRegistry.listDevices=()=>[{deviceId:DEVICE}];
  let dispatches=0;
  x.router.callDevice=async()=>{
    dispatches++;
    throw Object.assign(Error('outcome unknown'),{code:'AMBIGUOUS_TIMEOUT'});
  };
  const ambiguous=await x.call(payload);
  assert.equal(ambiguous.status,503);
  assert.equal(ambiguous.body.error.data.code,'AMBIGUOUS_TIMEOUT');
  assert.equal(dispatches,1);
});

test('MCP initialized notification is acknowledged without turning into a device call',async t=>{
  const x=await setup(t);
  const response=await fetch(x.endpoint,{method:'POST',headers:{
    'content-type':'application/json','cf-access-jwt-assertion':x.tokenFor(),
  },body:JSON.stringify({jsonrpc:'2.0',method:'notifications/initialized',params:{}})});
  assert.equal(response.status,202);
  assert.equal(await response.text(),'');
  assert.equal(x.calls.length,0);
});

test('standard MCP clients may omit params on initialized notification and tools/list',async t=>{
  const x=await setup(t);
  const notification=await fetch(x.endpoint,{method:'POST',headers:{
    'content-type':'application/json','cf-access-jwt-assertion':x.tokenFor(),
  },body:JSON.stringify({jsonrpc:'2.0',method:'notifications/initialized'})});
  assert.equal(notification.status,202);
  assert.equal(await notification.text(),'');
  const list=await x.call({jsonrpc:'2.0',id:10,method:'tools/list'});
  assert.equal(list.status,200);
  assert.deepEqual(list.body.result.tools.map(tool=>tool.name),[
    'read_file','list_directory','write_file','list_processes','run_command',
  ]);
  assert.equal(x.calls.length,0);
});

test('MCP metadata and tools/list cursor are accepted without changing read arguments',async t=>{
  const x=await setup(t);
  const list=await x.call({jsonrpc:'2.0',id:12,method:'tools/list',params:{
    cursor:'',_meta:{progressToken:'trace-1'},
  }});
  assert.equal(list.status,200);
  const result=await x.call({jsonrpc:'2.0',id:13,method:'tools/call',params:{
    name:'read_file',arguments:{deviceId:DEVICE,path:'/approved/file'},
    _meta:{progressToken:'trace-2'},
  }});
  assert.equal(result.status,200);
  assert.equal(x.calls.length,1);
  assert.deepEqual({...x.calls[0],requestId:undefined,authorization:undefined,signal:undefined},{requestId:undefined,
    authorization:undefined,signal:undefined,deviceId:DEVICE,name:'read_file',arguments:{path:'/approved/file'}});
});

test('initialize rejects protocol versions this Gateway does not implement',async t=>{
  const x=await setup(t);
  const response=await x.call({jsonrpc:'2.0',id:11,method:'initialize',params:{
    protocolVersion:'unsupported-protocol',capabilities:{},clientInfo:{name:'test',version:'1'},
  }});
  assert.equal(response.status,400);
  assert.equal(response.body.error.code,-32602);
  assert.equal(x.calls.length,0);
});
