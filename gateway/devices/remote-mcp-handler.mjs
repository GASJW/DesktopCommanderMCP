// Inert G7 Gateway-to-device MCP candidate. This handler is not imported by
// gateway/server.mjs; callers must mount it only behind the owner Access
// boundary after reviewing the deployment-specific policy.
import { randomUUID } from 'node:crypto';
import { ownerIdentityDigest } from '../dashboard/owner-identity.mjs';
import { signToolGrantCapability } from './tool-grant-capability.mjs';
const MAX_REQUEST_BYTES=96*1024;
const MAX_RESPONSE_BYTES=1024*1024;
const MCP_PROTOCOL_VERSION='2025-03-26';
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const ABSOLUTE_PATH=/^(?:\/|[A-Za-z]:[\\/])[^\0]*$/;
const TOOL_SCHEMAS={
  read_file:{description:'Read a bounded text file from one explicitly selected trusted device.',
    required:['deviceId','path'],optional:['offset','length'],
    properties:{deviceId:{type:'string',format:'uuid'},path:{type:'string'},
      offset:{type:'integer',minimum:0,maximum:100000},length:{type:'integer',minimum:1,maximum:1000}}},
  list_directory:{description:'List at most 200 entries within the approved root, to depth 2.',
    required:['deviceId','path'],optional:['depth'],
    properties:{deviceId:{type:'string',format:'uuid'},path:{type:'string'},depth:{type:'integer',minimum:0,maximum:2}}},
  write_file:{description:'Create a new text file inside the approved root. Existing files are never replaced.',
    required:['deviceId','path','content','mode'],optional:[],
    properties:{deviceId:{type:'string',format:'uuid'},path:{type:'string'},content:{type:'string',maxLength:65536},
      mode:{type:'string',enum:['create']}}},
  list_processes:{description:'List only command jobs started by this agent; host processes are not enumerated.',
    required:['deviceId'],optional:[],properties:{deviceId:{type:'string',format:'uuid'}}},
  run_command:{description:'Run the fixed read-only count_lines profile on one approved file.',
    required:['deviceId','profile','path'],optional:[],
    properties:{deviceId:{type:'string',format:'uuid'},profile:{type:'string',enum:['count_lines']},path:{type:'string'}}},
};

function send(res,status,body){
  if(res.destroyed||res.writableEnded)return;
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
const ownerDigest=ownerIdentityDigest;
function validApprovalReceipt(value,deviceId,currentTrustRevision){
  return value&&typeof value==='object'&&!Array.isArray(value)&&
    Object.getPrototypeOf(value)===Object.prototype&&
    Object.keys(value).sort().join(',')===
      'deviceId,eventId,fingerprint,trustRevision,trustRevisionAfter,trustRevisionBefore'&&
    value.deviceId===deviceId&&UUID.test(value.eventId??'')&&/^[a-f0-9]{64}$/.test(value.fingerprint??'')&&
    Number.isSafeInteger(value.trustRevisionBefore)&&value.trustRevisionBefore>=0&&
    Number.isSafeInteger(value.trustRevisionAfter)&&
    value.trustRevisionAfter===value.trustRevisionBefore+1&&
    Number.isSafeInteger(value.trustRevision)&&value.trustRevision===currentTrustRevision&&
    value.trustRevisionAfter<=value.trustRevision;
}
function validToolArguments(name,value){
  const schema=TOOL_SCHEMAS[name];
  if(!schema||!value||Object.getPrototypeOf(value)!==Object.prototype)return false;
  const keys=Object.keys(value);
  if(schema.required.some(key=>!Object.hasOwn(value,key))||
     keys.some(key=>!schema.required.includes(key)&&!schema.optional.includes(key)))return false;
  if(typeof value.deviceId!=='string'||!UUID.test(value.deviceId))return false;
  if(Object.hasOwn(value,'path')&&(typeof value.path!=='string'||value.path.length===0||
     value.path.length>4096||!ABSOLUTE_PATH.test(value.path)||value.path.startsWith('//')||
     value.path.startsWith('\\\\')))return false;
  if(Object.hasOwn(value,'offset')&&(!Number.isSafeInteger(value.offset)||value.offset<0||value.offset>100000))return false;
  if(Object.hasOwn(value,'length')&&(!Number.isSafeInteger(value.length)||value.length<1||value.length>1000))return false;
  if(Object.hasOwn(value,'depth')&&(!Number.isSafeInteger(value.depth)||value.depth<0||value.depth>2))return false;
  if(Object.hasOwn(value,'content')&&(typeof value.content!=='string'||
     Buffer.byteLength(value.content,'utf8')>64*1024))return false;
  if(Object.hasOwn(value,'mode')&&value.mode!=='create')return false;
  if(Object.hasOwn(value,'profile')&&value.profile!=='count_lines')return false;
  return true;
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

export function createRemoteDeviceMcpHandler({accessVerifier,deviceRegistry,trustStore,router,
  authorizeDevice,grantStore,policySigningKey,getTrustRevision,getDeviceApprovalReceipt,onDiagnostic}={}){
  if(!accessVerifier||typeof accessVerifier.verifyPrincipal!=='function'||
     !deviceRegistry||typeof deviceRegistry.listDevices!=='function'||
     typeof deviceRegistry.isLiveSession!=='function'||
     typeof trustStore?.acquireDispatchPermit!=='function'||
     typeof trustStore?.withCurrentSession!=='function'||
     !router||typeof router.callDevice!=='function'||typeof authorizeDevice!=='function'||
     !grantStore||typeof grantStore.authorizeAndPermit!=='function'||
     typeof grantStore.withCurrentAuthorization!=='function'||!policySigningKey||
     typeof getTrustRevision!=='function'||typeof getDeviceApprovalReceipt!=='function'||
     onDiagnostic!==undefined&&typeof onDiagnostic!=='function'){
    throw new TypeError('Owner verifier, durable trust and approval receipt, router, durable tool grant store and Gateway signing key are required');
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
    if(res.destroyed)return;
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
      return send(res,200,{jsonrpc:'2.0',id:message.id,result:{tools:Object.entries(TOOL_SCHEMAS).map(([name,schema])=>({
        name,description:schema.description,
        inputSchema:{type:'object',additionalProperties:false,required:schema.required,
          properties:schema.properties},
      }))}});
    }
    if(message.method!=='tools/call'){
      return jsonError(res,400,message.id,-32601,'Unsupported MCP method');
    }
    if(!keysAre(message.params,'arguments,name','_meta')||
       typeof message.params.name!=='string'||!Object.hasOwn(TOOL_SCHEMAS,message.params.name)||
       !validToolArguments(message.params.name,message.params.arguments)){
      return jsonError(res,400,message.id,-32602,'Invalid remote tool parameters');
    }
    const name=message.params.name;
    const {deviceId,...arguments_}=message.params.arguments;
    let trustRevisionBefore;
    try{trustRevisionBefore=getTrustRevision();}
    catch{return jsonError(res,503,message.id,-32002,'Device trust unavailable');}
    if(!Number.isSafeInteger(trustRevisionBefore)||trustRevisionBefore<0){
      return jsonError(res,503,message.id,-32002,'Device trust unavailable');
    }
    let trusted;
    try{trusted=deviceRegistry.listDevices().some(device=>device.deviceId===deviceId);}
    catch{return jsonError(res,503,message.id,-32002,'Device trust unavailable');}
    if(!trusted)return jsonError(res,403,message.id,-32003,'Device is not trusted');
    const controller=new AbortController();
    const abortOnDisconnect=()=>{if(!res.writableEnded)controller.abort();};
    res.once('close',abortOnDisconnect);
    let serialized;
    const requestId=randomUUID();
    const requestStartedAt=performance.now();
    const report=(phase,outcomeCode)=>{
      if(!onDiagnostic)return;
      try{onDiagnostic(Object.freeze({requestId,deviceId,route:'/mcp',phase,outcomeCode,
        elapsedMs:Math.max(0,Math.round(performance.now()-requestStartedAt))}));}catch{}
    };
    let authorizationContext;
    let responseFenceContext;
    try{
      report('owner_dispatch','STARTED');
      const result=await router.callDevice({requestId,deviceId,name,arguments:arguments_,
        signal:controller.signal,beforeDispatch:async dispatch=>{
          if(!dispatch||dispatch.deviceId!==deviceId||dispatch.requestId!==requestId||
             !UUID.test(dispatch.sessionId??'')){
            throw Object.assign(Error('Device session authorization context unavailable'),
              {code:'SESSION_UNAVAILABLE'});
          }
          if(res.destroyed||controller.signal.aborted){
            throw Object.assign(Error('Owner request disconnected before authorization'),{code:'CANCELLED'});
          }
          let authorized;
          try{authorized=await authorizeDevice(owner,deviceId)===true;}
          catch{throw Object.assign(Error('Owner-device authorization unavailable'),{code:'OWNER_AUTH_UNAVAILABLE'});}
          if(res.destroyed||controller.signal.aborted){
            throw Object.assign(Error('Owner request disconnected before tool authorization'),{code:'CANCELLED'});
          }
          if(!authorized)throw Object.assign(Error('Owner is not authorized for this device'),
            {code:'OWNER_DEVICE_DENIED'});
          const trustRevisionAfter=getTrustRevision();
          if(trustRevisionAfter!==trustRevisionBefore){
            throw Object.assign(Error('Device trust changed during authorization'),{code:'TRUST_CHANGED'});
          }
          const approvalReceipt=getDeviceApprovalReceipt(owner,deviceId);
          if(!validApprovalReceipt(approvalReceipt,deviceId,trustRevisionAfter)){
            throw Object.assign(Error('Durable device approval receipt unavailable'),{code:'APPROVAL_UNAVAILABLE'});
          }
          const permit=await grantStore.authorizeAndPermit({ownerDigest:ownerDigest(owner),deviceId,
            fingerprint:approvalReceipt.fingerprint,tool:name,arguments:arguments_,requestId,
            approvalReceipt},{signCapability:claims=>signToolGrantCapability(claims,policySigningKey)});
          let trustPermit;
          try{
            trustPermit=trustStore.acquireDispatchPermit({deviceId,sessionId:dispatch.sessionId,
              expectedRevision:trustRevisionAfter});
          }catch(error){
            try{permit.release();}catch{}
            throw Object.assign(Error('Trust authorization changed before transport handoff'),
              {code:error?.code??'TRUST_UNAVAILABLE'});
          }
          authorizationContext={grantId:permit.grantId,ownerDigest:ownerDigest(owner),deviceId,
            fingerprint:approvalReceipt.fingerprint,tool:name,policyRevision:permit.policyRevision};
          responseFenceContext={deviceId,owner,fingerprint:approvalReceipt.fingerprint,
            trustRevision:trustRevisionAfter,approvalReceipt,sessionId:dispatch.sessionId};
          let released=false;
          return {authorization:permit.authorization,release:()=>{
            if(released)return false;
            let error;
            try{trustPermit.release();}catch(value){error=value;}
            try{permit.release();}catch(value){error??=value;}
            if(error)throw error;
            released=true;return true;
          }};
        }});
      if(res.destroyed)return;
      report('owner_dispatch','RESULT_READY');
      serialized=JSON.stringify(result);
      if(typeof serialized!=='string'||Buffer.byteLength(serialized,'utf8')>MAX_RESPONSE_BYTES){
        return jsonError(res,502,message.id,-32004,'Remote response invalid or too large');
      }
      let delivered=false;
      try{
        trustStore.withCurrentSession({deviceId:responseFenceContext.deviceId,
          sessionId:responseFenceContext.sessionId,expectedRevision:responseFenceContext.trustRevision},trustSessionProof=>
        grantStore.withCurrentAuthorization(authorizationContext,()=>{
          if(res.destroyed)return;
          const currentTrustRevision=getTrustRevision();
          const currentApprovalReceipt=getDeviceApprovalReceipt(responseFenceContext.owner,
            responseFenceContext.deviceId,trustSessionProof);
          const receiptMatches=validApprovalReceipt(currentApprovalReceipt,responseFenceContext.deviceId,
            currentTrustRevision)&&
            currentApprovalReceipt.eventId===responseFenceContext.approvalReceipt.eventId&&
            currentApprovalReceipt.fingerprint===responseFenceContext.fingerprint&&
            currentApprovalReceipt.trustRevisionBefore===responseFenceContext.approvalReceipt.trustRevisionBefore&&
            currentApprovalReceipt.trustRevisionAfter===responseFenceContext.approvalReceipt.trustRevisionAfter;
          if(currentTrustRevision!==responseFenceContext.trustRevision||!receiptMatches||
             !deviceRegistry.listDevices().some(device=>device.deviceId===responseFenceContext.deviceId)||
             !deviceRegistry.isLiveSession(responseFenceContext.deviceId,responseFenceContext.sessionId)){
            throw Object.assign(Error('Device trust, approval or session changed after dispatch'),
              {code:'DEVICE_AUTHORIZATION_CHANGED'});
          }
          send(res,200,{jsonrpc:'2.0',id:message.id,result:JSON.parse(serialized)});delivered=true;
          report('owner_response','DELIVERED');
        }));
      }catch(error){
        if(res.destroyed)return;
        const code=error?.code==='DENIED'?'AMBIGUOUS_GRANT_REVOCATION':'AMBIGUOUS_AUTHORIZATION_FENCE';
        report('owner_response',code);
        return send(res,503,{jsonrpc:'2.0',id:message.id,error:{code:-32005,
          message:'Remote result suppressed after dispatch; do not replay',data:{code}}});
      }
      if(delivered)return;
      return;
    }catch(error){
      if(res.destroyed)return;
      if(error?.code==='OWNER_DEVICE_DENIED'){
        return jsonError(res,403,message.id,-32007,'Owner is not authorized for this device');
      }
      if(error?.code==='DENIED'||error?.code==='GRANT_DENIED'||error?.code==='GRANT_SCOPE_DENIED'){
        return jsonError(res,403,message.id,-32009,'Owner is not authorized for this tool operation');
      }
      if(error?.code==='OWNER_AUTH_UNAVAILABLE'||error?.code==='TRUST_CHANGED'||
         error?.code==='APPROVAL_UNAVAILABLE'){
        return jsonError(res,503,message.id,-32002,'Device authorization evidence unavailable');
      }
      const code=typeof error?.code==='string'&&/^[A-Z_]{1,48}$/.test(error.code)
        ?error.code:'UNAVAILABLE';
      report('owner_response',code);
      return send(res,503,{jsonrpc:'2.0',id:message.id,error:{
        code:-32005,message:code.startsWith('AMBIGUOUS_')
          ?'Remote operation outcome unknown; do not replay'
          :'Remote device unavailable',data:{code},
      }});
    }finally{res.removeListener('close',abortOnDisconnect);}
  };
}
