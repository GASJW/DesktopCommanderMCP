import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { generateKeyPairSync, sign } from 'node:crypto';
import { createChatGptReadOnlyBridge, CHATGPT_MCP_ROUTE,
  CHATGPT_RESOURCE_METADATA_PATH, getChatGptResourceMetadataPath,
  validateChatGptBridgeConfig } from '../chatgpt/read-only-bridge.mjs';

const OWNER={issuer:'https://g7-owner-staging.cloudflareaccess.com',subject:'synthetic-owner'};
const DEVICE='b7e92caf-f591-44c4-8fb7-6c489ea573f4';
const OTHER_DEVICE='b7e92caf-f591-44c4-8fb7-6c489ea573f5';
const SESSION='ab000000-0000-4000-8000-000000000001';
const APPROVAL='b7e92caf-f591-44c4-8fb7-6c489ea573f6';
const FINGERPRINT='b'.repeat(64);
const GRANT='b7e92caf-f591-44c4-8fb7-6c489ea573f7';

async function setup(t,{onExecute}={}){
  const {publicKey,privateKey}=generateKeyPairSync('rsa',{modulusLength:2048});
  const config={issuer:'https://auth.i8a.example.test',
    resource:'https://g7-tunnel.example.test/chatgpt/mcp',
    resourceMetadataUrl:'https://g7-tunnel.example.test/.well-known/oauth-protected-resource/chatgpt/mcp',
    clientIds:['chatgpt-client-i8a'],jwks:[{...publicKey.export({format:'jwk'}),
      kid:'i8a-test-key',alg:'RS256',use:'sig'}],
    principalMapping:{subject:'chatgpt-user-i8a',ownerIssuer:OWNER.issuer,ownerSubject:OWNER.subject}};
  const token=(claims={},headerClaims={})=>{
    const now=Math.floor(Date.now()/1000);
    const header=Buffer.from(JSON.stringify({alg:'RS256',kid:'i8a-test-key',typ:'at+jwt',...headerClaims})).toString('base64url');
    const payload=Buffer.from(JSON.stringify({iss:config.issuer,aud:config.resource,
      sub:config.principalMapping.subject,client_id:config.clientIds[0],scope:'g7.read',
      iat:now-2,exp:now+300,...claims})).toString('base64url');
    const input=`${header}.${payload}`;
    return `${input}.${sign('RSA-SHA256',Buffer.from(input),privateKey).toString('base64url')}`;
  };
  const executions=new Set(),calls=[],diagnostics=[];
  const router={callDevice:async({beforeDispatch,...frame})=>{
    const permit=await beforeDispatch({deviceId:frame.deviceId,requestId:frame.requestId,sessionId:SESSION});
    try{
      calls.push({...frame,owner:OWNER});
      if(executions.has(frame.requestId))throw Object.assign(Error('duplicate delivery'),{code:'DUPLICATE_DELIVERY'});
      executions.add(frame.requestId);
      return onExecute?await onExecute(frame):{content:[{type:'text',text:'synthetic approved file'}]};
    }finally{permit.release();}
  }};
  const deviceRegistry={listDevices:()=>[{deviceId:DEVICE}],isLiveSession:(_id,sessionId)=>sessionId===SESSION};
  const trustStore={acquireDispatchPermit:()=>({release:()=>true}),
    withCurrentSession:(_context,callback)=>callback({sessionId:SESSION})};
  const grantStore={
    authorizeAndPermit:async({deviceId,fingerprint,tool,arguments:args})=>{
      if(deviceId!==DEVICE||fingerprint!==FINGERPRINT||tool!=='read_file'||
         typeof args.path!=='string'||!args.path.startsWith('/approved/'))
        throw Object.assign(Error('grant scope denied'),{code:'GRANT_SCOPE_DENIED'});
      return {grantId:GRANT,policyRevision:2,authorization:{claims:{tool,deviceId}},release:()=>true};
    },
    withCurrentAuthorization:(_context,callback)=>callback(),
  };
  const gateway={deviceRegistry,trustStore,router,
    authorizeDevice:async(owner,deviceId)=>owner.issuer===OWNER.issuer&&owner.subject===OWNER.subject&&deviceId===DEVICE,
    grantStore,policySigningKey:generateKeyPairSync('ed25519').privateKey,
    getTrustRevision:()=>3,
    getDeviceApprovalReceipt:()=>({eventId:APPROVAL,deviceId:DEVICE,fingerprint:FINGERPRINT,
      trustRevisionBefore:2,trustRevisionAfter:3,trustRevision:3}),
    onDiagnostic:event=>diagnostics.push(event)};
  const handler=createChatGptReadOnlyBridge({oauth:config,owner:OWNER,...gateway});
  const server=createServer(handler);
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
  assert.equal(server.address().address,'127.0.0.1');
  t.after(()=>new Promise(resolve=>server.close(resolve)));
  const endpoint=`http://127.0.0.1:${server.address().port}`;
  const call=async(message,{accessToken=token(),headers={},protocolVersion='2025-11-25'}={})=>{
    const response=await fetch(endpoint+CHATGPT_MCP_ROUTE,{method:'POST',headers:{
      accept:'application/json, text/event-stream','content-type':'application/json',
      ...(protocolVersion?{'mcp-protocol-version':protocolVersion}:{}),
      'authorization':`Bearer ${accessToken}`,...headers,
    },body:JSON.stringify(message)});
    return {status:response.status,headers:response.headers,body:await response.json()};
  };
  return {config,token,call,calls,executions,diagnostics,endpoint};
}

function rpc(id,method,params){return {jsonrpc:'2.0',id,method,...(params===undefined?{}:{params})};}
function readCall(id,path='/approved/proof.txt',deviceId=DEVICE,session='chat-session-i8a'){
  return rpc(id,'tools/call',{name:'read_file',arguments:{deviceId,path},_meta:{'openai/session':session}});
}

test('I8A exposes unauthenticated MCP discovery, one read-only tool and protected-resource metadata',async t=>{
  const x=await setup(t);
  const initialize=await x.call(rpc(1,'initialize',{capabilities:{},clientInfo:{name:'test',version:'1'},
    protocolVersion:'2025-11-25'}),{accessToken:'',protocolVersion:''});
  assert.equal(initialize.status,200);
  assert.equal(initialize.body.result.protocolVersion,'2025-11-25');
  for(const version of ['2025-06-18','2025-03-26']){
    const negotiated=await x.call(rpc(`initialize-${version}`,'initialize',{
      capabilities:{},clientInfo:{name:'test',version:'1'},protocolVersion:version,
    }),{accessToken:'',protocolVersion:''});
    assert.equal(negotiated.status,200);
    assert.equal(negotiated.body.result.protocolVersion,version);
  }
  const listed=await x.call(rpc(2,'tools/list'),{accessToken:''});
  assert.equal(listed.status,200);
  assert.deepEqual(listed.body.result.tools.map(tool=>tool.name),['read_file']);
  assert.deepEqual(listed.body.result.tools[0].securitySchemes,[{type:'oauth2',scopes:['g7.read']}]);
  assert.deepEqual(listed.body.result.tools[0].annotations,
    {readOnlyHint:true,destructiveHint:false,openWorldHint:false});
  const metadataPath=getChatGptResourceMetadataPath(x.config.resource);
  assert.equal(metadataPath,`${CHATGPT_RESOURCE_METADATA_PATH}/chatgpt/mcp`);
  const metadata=await fetch(x.endpoint+metadataPath);
  assert.equal(metadata.status,200);
  assert.deepEqual(await metadata.json(),{resource:x.config.resource,
    authorization_servers:[x.config.issuer],scopes_supported:['g7.read'],bearer_methods_supported:['header']});
  assert.notEqual((await fetch(x.endpoint+CHATGPT_RESOURCE_METADATA_PATH)).status,200);
});

test('I8C accepts Auth0 default azp and RFC 9068 client_id access-token profiles',async t=>{
  const x=await setup(t);
  for(const [claims,header] of [
    [{client_id:undefined,azp:x.config.clientIds[0]},{typ:'JWT'}],
    [{azp:undefined,client_id:x.config.clientIds[0]},{typ:'at+jwt'}],
  ]){
    const reply=await x.call(readCall(`auth0-profile-${x.calls.length}`),
      {accessToken:x.token(claims,header)});
    assert.equal(reply.status,200,JSON.stringify(reply.body));
  }
  assert.equal(x.calls.length,2);
  const mismatched=await x.call(readCall('auth0-profile-mismatch'),
    {accessToken:x.token({client_id:x.config.clientIds[0],azp:'another-client'})});
  assert.equal(mismatched.body.result.isError,true);
  assert.equal(x.calls.length,2);
});

test('I8A validates OAuth JWT and maps only the configured subject to the existing G7 Owner',async t=>{
  const x=await setup(t);
  const accessToken=x.token();
  const reply=await x.call(readCall('read-i8a-1'),{accessToken,headers:{'cf-access-jwt-assertion':'forged-owner-header'}});
  assert.equal(reply.status,200,JSON.stringify({body:reply.body,calls:x.calls.length,diagnostics:x.diagnostics}));
  assert.equal(x.calls.length,1);
  assert.deepEqual(x.calls[0].owner,OWNER);
  assert.equal(x.calls[0].deviceId,DEVICE);
  assert.equal(x.calls[0].name,'read_file');
  assert.equal(reply.body.result.content[0].text,'synthetic approved file');
  assert.ok(x.diagnostics.some(event=>event.route===CHATGPT_MCP_ROUTE&&event.phase==='owner_dispatch'));
  assert.equal(JSON.stringify(x.diagnostics).includes(accessToken),false);
});

test('I8A rejects missing, forged, stale, wrong-audience, wrong-client and insufficient-scope tokens',async t=>{
  const x=await setup(t);
  const requests=[
    {accessToken:'',headers:{'cf-access-jwt-assertion':x.token()}},
    {accessToken:`${x.token().slice(0,-1)}x`},
    {accessToken:x.token({exp:Math.floor(Date.now()/1000)-1})},
    {accessToken:x.token({iss:'https://attacker.example.test'})},
    {accessToken:x.token({aud:'https://other.example.test/mcp'})},
    {accessToken:x.token({client_id:'unregistered-client'})},
    {accessToken:x.token({scope:'profile'})},
    {accessToken:x.token({nbf:Math.floor(Date.now()/1000)+120})},
    {accessToken:x.token({sub:'another-chatgpt-user'})},
  ];
  for(const options of requests){
    const reply=await x.call(readCall('auth-denied'),options);
    assert.equal(reply.status,200);
    assert.equal(reply.body.result.isError,true);
    assert.ok(reply.body.result._meta['mcp/www_authenticate'][0].includes('resource_metadata='));
  }
  assert.equal(x.calls.length,0);
});

test('I8A enforces Streamable HTTP Accept and rejects unsupported protocol headers',async t=>{
  const x=await setup(t);
  const badAccept=await fetch(x.endpoint+CHATGPT_MCP_ROUTE,{method:'POST',headers:{
    accept:'application/json','content-type':'application/json','mcp-protocol-version':'2025-11-25',
  },body:JSON.stringify(rpc(1,'tools/list'))});
  assert.equal(badAccept.status,406);
  const badVersion=await x.call(readCall('bad-version'),{headers:{'mcp-protocol-version':'2024-11-05'}});
  assert.equal(badVersion.status,400);
  const get=await fetch(x.endpoint+CHATGPT_MCP_ROUTE,{headers:{accept:'text/event-stream'}});
  assert.equal(get.status,405);
  assert.equal(x.calls.length,0);
});

test('I8A keeps device, grant-root and tool authorization in the existing G7 policy path',async t=>{
  const x=await setup(t);
  const crossDevice=await x.call(readCall('cross-device',undefined,OTHER_DEVICE));
  assert.equal(crossDevice.status,403);
  const outOfScope=await x.call(readCall('outside-grant','/outside/private.txt'));
  assert.equal(outOfScope.status,403);
  const escalated=await x.call(rpc('write-attempt','tools/call',{name:'write_file',arguments:{
    deviceId:DEVICE,path:'/approved/new.txt',content:'no',mode:'create'}}));
  assert.equal(escalated.status,400);
  assert.equal(x.calls.length,0);
});

test('I8A keeps the same request identity across a transport retry and OAuth token refresh',async t=>{
  const x=await setup(t);
  const message=readCall('stable-jsonrpc-id');
  const first=await x.call(message,{accessToken:x.token({jti:'first-token'})});
  const retry=await x.call(message,{accessToken:x.token({jti:'refreshed-token'})});
  assert.equal(first.status,200,JSON.stringify({body:first.body,calls:x.calls.length,diagnostics:x.diagnostics}));
  assert.equal(retry.status,503);
  assert.equal(x.calls.length,2);
  assert.equal(x.executions.size,1);
  assert.equal(x.calls[0].requestId,x.calls[1].requestId);
});

test('I8A allows a new call that reuses a JSON-RPC ID for different read arguments',async t=>{
  const x=await setup(t);
  const first=await x.call(readCall('reused-jsonrpc-id','/approved/first.txt'));
  const second=await x.call(readCall('reused-jsonrpc-id','/approved/second.txt'));
  assert.equal(first.status,200);
  assert.equal(second.status,200);
  assert.notEqual(x.calls[0].requestId,x.calls[1].requestId);
  assert.equal(x.executions.size,2);
});

test('I8A scopes identical calls to the ChatGPT conversation so a new conversation is a new invocation',async t=>{
  const x=await setup(t);
  const first=await x.call(readCall('conversation-local-id','/approved/same.txt',DEVICE,'conversation-one'));
  const second=await x.call(readCall('conversation-local-id','/approved/same.txt',DEVICE,'conversation-two'));
  assert.equal(first.status,200);
  assert.equal(second.status,200);
  assert.notEqual(x.calls[0].requestId,x.calls[1].requestId);
  assert.equal(x.executions.size,2);
  assert.doesNotMatch(JSON.stringify(x.diagnostics),/conversation-one|conversation-two/);
});

test('I8A fails closed without a ChatGPT conversation identity',async t=>{
  const x=await setup(t);
  const reply=await x.call(rpc('missing-session','tools/call',{name:'read_file',arguments:{
    deviceId:DEVICE,path:'/approved/proof.txt'}}));
  assert.equal(reply.status,503);
  assert.equal(x.calls.length,0);
  assert.equal(x.executions.size,0);
});

test('I8A does not replay an ambiguous remote execution on a retry',async t=>{
  let executionCount=0;
  const x=await setup(t,{onExecute:async()=>{
    executionCount++;
    throw Object.assign(Error('synthetic response lost after execution'),{code:'AMBIGUOUS_TIMEOUT'});
  }});
  const message=readCall('ambiguous-retry');
  const first=await x.call(message);
  const retry=await x.call(message);
  assert.equal(first.status,503);
  assert.equal(retry.status,503);
  assert.equal(executionCount,1);
  assert.equal(x.executions.size,1);
  assert.equal(x.calls[0].requestId,x.calls[1].requestId);
});

test('I8A treats an exact reused ID and payload in the same conversation as an ambiguous retry',async t=>{
  const x=await setup(t);
  const message=readCall('same-session-same-invocation');
  const first=await x.call(message);
  const repeated=await x.call(message);
  assert.equal(first.status,200);
  assert.equal(repeated.status,503);
  assert.equal(x.executions.size,1);
});

test('I8A rejects a principal map to any Owner other than the current G7 Owner',()=>{
  const {publicKey}=generateKeyPairSync('rsa',{modulusLength:2048});
  const config={issuer:'https://auth.i8a.example.test',resource:'https://g7.example.test/chatgpt/mcp',
    resourceMetadataUrl:'https://g7.example.test/.well-known/oauth-protected-resource/chatgpt/mcp',
    clientIds:['chatgpt-client-i8a'],jwks:[{...publicKey.export({format:'jwk'}),kid:'test',alg:'RS256'}],
    principalMapping:{subject:'user',ownerIssuer:'https://unrelated.example.test',ownerSubject:'other'}};
  assert.throws(()=>validateChatGptBridgeConfig(config,OWNER),/Invalid ChatGPT read-only bridge OAuth configuration/);
  const validMapping={...config,principalMapping:{...config.principalMapping,
    ownerIssuer:OWNER.issuer,ownerSubject:OWNER.subject}};
  assert.throws(()=>validateChatGptBridgeConfig({...validMapping,
    resourceMetadataUrl:'https://g7.example.test/.well-known/oauth-protected-resource'},OWNER),
  /Invalid ChatGPT read-only bridge OAuth configuration/);
  assert.throws(()=>validateChatGptBridgeConfig({...validMapping,
    resourceMetadataUrl:'https://g7.example.test/not-protected-resource'},OWNER),
  /Invalid ChatGPT read-only bridge OAuth configuration/);
});
