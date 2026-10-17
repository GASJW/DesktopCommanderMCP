// Inert G7 Gateway-to-device MCP candidate. This handler is not imported by
// gateway/server.mjs; callers must mount it only behind the owner Access
// boundary after reviewing the deployment-specific policy.
const MAX_REQUEST_BYTES=16*1024;
const MAX_RESPONSE_BYTES=1024*1024;
const MCP_PROTOCOL_VERSION='2025-03-26';
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const ABSOLUTE_PATH=/^(?:\/|[A-Za-z]:[\\/])[^\0]*$/;

function send(res,status,body){
  res.writeHead(status,{'content-type':'application/json; charset=utf-8',
    'cache-control':'no-store','x-content-type-options':'nosniff'});
  res.end(JSON.stringify(body));
}
function acknowledge(res){
  res.writeHead(202,{'cache-control':'no-store','x-content-type-options':'nosniff'});
  res.end();
}
function jsonError(res,status,id,code,message){
  return send(res,status,{jsonrpc:'2.0',id,error:{code,message}});
}
function exactKeys(value,expected){
  return value&&typeof value==='object'&&!Array.isArray(value)&&
    Object.getPrototypeOf(value)===Object.prototype&&
    Object.keys(value).sort().join(',')===expected;
}
function validMeta(value){
  return value&&typeof value==='object'&&!Array.isArray(value)&&
    Object.getPrototypeOf(value)===Object.prototype;
}
function keysAre(value,required,optional=''){
  if(!value||typeof value!=='object'||Array.isArray(value)||
     Object.getPrototypeOf(value)!==Object.prototype)return false;
  const keys=Object.keys(value).sort();
  const expected=required.split(',').filter(Boolean);
  const allowed=new Set([...expected,...optional.split(',').filter(Boolean)]);
  return expected.every(key=>Object.hasOwn(value,key))&&keys.every(key=>allowed.has(key))&&
    (!Object.hasOwn(value,'_meta')||validMeta(value._meta));
}
function validId(value){
  return typeof value==='string'&&value.length>0&&value.length<=128||
    Number.isSafeInteger(value)&&value>=0;
}
async function readRequest(req){
  const parts=[];let total=0;
  for await(const chunk of req){
    total+=chunk.length;
    if(total>MAX_REQUEST_BYTES)throw Object.assign(Error('Request too large'),{code:'TOO_LARGE'});
    parts.push(chunk);
  }
  let text;
  try{text=new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(parts,total));}
  catch{throw Object.assign(Error('Invalid UTF-8'),{code:'BAD_JSON'});}
  try{return JSON.parse(text);}
  catch{throw Object.assign(Error('Invalid JSON'),{code:'BAD_JSON'});}
}

export function createRemoteDeviceMcpHandler({accessVerifier,deviceRegistry,router,
  authorizeDevice}={}){
  if(!accessVerifier||typeof accessVerifier.verifyPrincipal!=='function'||
     !deviceRegistry||typeof deviceRegistry.listDevices!=='function'||
     !router||typeof router.callDevice!=='function'||typeof authorizeDevice!=='function'){
    throw new TypeError('Owner verifier, device registry, router and owner-device policy are required');
  }
  return async function handleRemoteDeviceMcp(req,res){
    if(req.url!=='/mcp')return send(res,404,{error:'Not found'});
    if(req.method!=='POST')return send(res,405,{error:'Method not allowed'});
    if(req.headers.origin)return send(res,403,{error:'Browser origin denied'});
    if(!/^application\/json(?:\s*;|$)/i.test(req.headers['content-type']??'')){
      return send(res,415,{error:'JSON required'});
    }
    let message;
    try{message=await readRequest(req);}
    catch(error){return send(res,error?.code==='TOO_LARGE'?413:400,{error:error.message});}
    const initializedNotification=message?.jsonrpc==='2.0'&&
      message.method==='notifications/initialized'&&(
        exactKeys(message,'jsonrpc,method')||
        exactKeys(message,'jsonrpc,method,params')&&
          (exactKeys(message.params,'')||keysAre(message.params,'','_meta')));
    const toolsListWithoutParams=message?.jsonrpc==='2.0'&&
      message.method==='tools/list'&&exactKeys(message,'id,jsonrpc,method')&&validId(message.id);
    const toolsListWithEmptyParams=message?.jsonrpc==='2.0'&&
      message.method==='tools/list'&&exactKeys(message,'id,jsonrpc,method,params')&&
      validId(message.id)&&keysAre(message.params,'','_meta,cursor')&&
      (message.params.cursor===undefined||typeof message.params.cursor==='string'&&
        message.params.cursor.length<=512);
    const requestWithParams=exactKeys(message,'id,jsonrpc,method,params')&&
      message.jsonrpc==='2.0'&&validId(message.id)&&typeof message.method==='string'&&
      message.params&&typeof message.params==='object'&&!Array.isArray(message.params);
    if(!initializedNotification&&!toolsListWithoutParams&&!toolsListWithEmptyParams&&
       !requestWithParams){
      return jsonError(res,400,null,-32600,'Invalid MCP request');
    }
    let owner;
    try{
      owner=await accessVerifier.verifyPrincipal(req.headers['cf-access-jwt-assertion']);
    }catch{return jsonError(res,401,message.id,-32001,'Owner authentication required');}
    if(!owner||typeof owner.issuer!=='string'||typeof owner.subject!=='string'||
       owner.subject.length===0){
      return jsonError(res,401,message.id,-32001,'Owner authentication required');
    }
    if(initializedNotification)return acknowledge(res);
    if(message.method==='initialize'){
      if(!keysAre(message.params,'capabilities,clientInfo,protocolVersion','_meta')||
         message.params.protocolVersion!==MCP_PROTOCOL_VERSION||
         !message.params.capabilities||typeof message.params.capabilities!=='object'||
         !message.params.clientInfo||typeof message.params.clientInfo!=='object'){
        return jsonError(res,400,message.id,-32602,'Unsupported protocol version or invalid initialize parameters');
      }
      return send(res,200,{jsonrpc:'2.0',id:message.id,result:{
        protocolVersion:MCP_PROTOCOL_VERSION,capabilities:{tools:{}},
        serverInfo:{name:'vpsc-g7-device-gateway',version:'0.0.0-dev'},
      }});
    }
    if(message.method==='tools/list'){
      if(message.params!==undefined&&(!keysAre(message.params,'','_meta,cursor')||
         message.params.cursor!==undefined&&(typeof message.params.cursor!=='string'||
           message.params.cursor.length>512))){
        return jsonError(res,400,message.id,-32602,'Invalid tool list parameters');
      }
      return send(res,200,{jsonrpc:'2.0',id:message.id,result:{tools:[{
        name:'read_file',description:'Read a file from one explicitly selected trusted device.',
        inputSchema:{type:'object',additionalProperties:false,required:['deviceId','path'],
          properties:{deviceId:{type:'string',format:'uuid'},path:{type:'string'},
            offset:{type:'integer',minimum:0,maximum:100000},
            length:{type:'integer',minimum:1,maximum:1000}}},
      }]}});
    }
    if(message.method!=='tools/call'){
      return jsonError(res,400,message.id,-32601,'Unsupported MCP method');
    }
    if(!keysAre(message.params,'arguments,name','_meta')||message.params.name!=='read_file'||
       !exactKeys(message.params.arguments,'deviceId,path')&&
       !exactKeys(message.params.arguments,'deviceId,length,offset,path')&&
       !exactKeys(message.params.arguments,'deviceId,offset,path')&&
       !exactKeys(message.params.arguments,'deviceId,length,path')){
      return jsonError(res,400,message.id,-32602,'Invalid read_file parameters');
    }
    const {deviceId,path,...paging}=message.params.arguments;
    if(typeof deviceId!=='string'||!UUID.test(deviceId)||typeof path!=='string'||
       path.length===0||path.length>4096||!ABSOLUTE_PATH.test(path)||
       path.startsWith('//')||path.startsWith('\\\\')||
       Object.hasOwn(paging,'offset')&&(!Number.isSafeInteger(paging.offset)||
         paging.offset<0||paging.offset>100_000)||
       Object.hasOwn(paging,'length')&&(!Number.isSafeInteger(paging.length)||
         paging.length<1||paging.length>1000)){
      return jsonError(res,400,message.id,-32602,'Invalid read_file parameters');
    }
    let trusted;
    try{trusted=deviceRegistry.listDevices().some(device=>device.deviceId===deviceId);}
    catch{return jsonError(res,503,message.id,-32002,'Device trust unavailable');}
    if(!trusted)return jsonError(res,403,message.id,-32003,'Device is not trusted');
    let authorized=false;
    try{authorized=await authorizeDevice(owner,deviceId)===true;}
    catch{return jsonError(res,503,message.id,-32006,'Owner-device authorization unavailable');}
    if(!authorized)return jsonError(res,403,message.id,-32007,'Owner is not authorized for this device');
    let serialized;
    try{
      const result=await router.callDevice({deviceId,name:'read_file',arguments:{path,...paging}});
      serialized=JSON.stringify(result);
      if(typeof serialized!=='string'||Buffer.byteLength(serialized,'utf8')>MAX_RESPONSE_BYTES){
        return jsonError(res,502,message.id,-32004,'Remote response invalid or too large');
      }
      return send(res,200,{jsonrpc:'2.0',id:message.id,result:JSON.parse(serialized)});
    }catch(error){
      const code=typeof error?.code==='string'&&/^[A-Z_]{1,48}$/.test(error.code)
        ?error.code:'UNAVAILABLE';
      return send(res,503,{jsonrpc:'2.0',id:message.id,error:{
        code:-32005,message:code.startsWith('AMBIGUOUS_')
          ?'Remote operation outcome unknown; do not replay'
          :'Remote device unavailable',data:{code},
      }});
    }
  };
}
