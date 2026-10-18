import { Readable } from 'node:stream';
import { createAgentChannelTransport } from './agent-channel-transport.mjs';

const PATHS=new Set(['/agent/challenge','/agent/connect','/agent/heartbeat',
  '/agent/poll','/agent/result','/agent/cancel-ack','/agent/disconnect']);
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const FINGERPRINT=/^[a-f0-9]{64}$/;
const MAX_REQUEST=256*1024;
function reply(res,status,body){
  if(res.writableEnded||res.destroyed)return;
  res.writeHead(status,{'content-type':'application/json; charset=utf-8',
    'cache-control':'no-store','x-content-type-options':'nosniff'});
  res.end(JSON.stringify(body));
}
const reject=(res,status,error)=>reply(res,status,{error});
async function readBody(req){
  const chunks=[];let size=0;
  for await(const chunk of req){
    size+=chunk.length;
    if(size>MAX_REQUEST)throw Object.assign(Error('request too large'),{code:'TOO_LARGE'});
    chunks.push(chunk);
  }
  const raw=Buffer.concat(chunks,size);
  const text=new TextDecoder('utf-8',{fatal:true}).decode(raw);
  return {raw,text};
}

// Persistent staging composes this authenticated handler inside its TLS server.
// It requires cryptographically verified machine JWTs plus a durable I2-backed
// Client-ID/device/fingerprint binding. It never opens an HTTP listener.
export function createAuthenticatedMachineIngress({registry,router,verifyMachineToken,
  machineBindingStore,getTrustRevision=()=>0,shouldCancelOperation}={}){
  if(!registry||typeof registry.snapshotTrustedDevices!=='function'||
     typeof verifyMachineToken!=='function'||
     !machineBindingStore||typeof machineBindingStore.resolve!=='function'||
     typeof machineBindingStore.revision!=='function'||typeof getTrustRevision!=='function'){
    throw new TypeError('Persistent machine ingress requires durable binding and M2M verification');
  }
  const transport=createAgentChannelTransport({registry,router,shouldCancelOperation});
  const handle=async(req,res)=>{
    if(!PATHS.has(req.url))return reject(res,404,'Not found');
    if(req.method!=='POST')return reject(res,405,'Method not allowed');
    if(req.headers.origin||req.headers.cookie||req.headers['cf-access-client-id']||
       req.headers['cf-access-client-secret'])return reject(res,403,'Unexpected browser or service headers');
    if(!/^application\/json(?:;|$)/i.test(req.headers['content-type']??''))
      return reject(res,415,'JSON required');
    const assertion=req.headers['cf-access-jwt-assertion'];
    if(typeof assertion!=='string'||assertion.length>16*1024)return reject(res,401,'Machine JWT required');
    let principal;
    try{principal=await verifyMachineToken(assertion);}catch{}
    if(!principal||typeof principal.clientId!=='string')return reject(res,401,'Machine JWT invalid');
    let binding,revision,bindingRevision,trusted;
    try{
      binding=machineBindingStore.resolve(principal.clientId);
      revision=getTrustRevision();
      bindingRevision=machineBindingStore.revision();
      if(binding&&Number.isSafeInteger(revision)&&revision>=0&&
         Number.isSafeInteger(bindingRevision)&&bindingRevision>=0){
        trusted=registry.snapshotTrustedDevices().find(item=>item.deviceId===binding.deviceId);
      }
    }catch{
      if(binding?.deviceId)transport.invalidateDevice(binding.deviceId);
      return reject(res,503,'Machine trust or binding unavailable');
    }
    const validBinding=binding&&binding.clientId===principal.clientId&&
      UUID.test(binding.deviceId??'')&&FINGERPRINT.test(binding.fingerprint??'')&&
      Number.isSafeInteger(binding.bindingRevision)&&binding.bindingRevision>0&&
      binding.bindingRevision<=bindingRevision&&
      Number.isSafeInteger(binding.trustRevisionBefore)&&binding.trustRevisionBefore>=0&&
      Number.isSafeInteger(binding.trustRevisionAfter)&&
      binding.trustRevisionAfter===binding.trustRevisionBefore+1&&
      Number.isSafeInteger(binding.trustRevision)&&binding.trustRevision>=binding.trustRevisionAfter&&
      binding.trustRevisionAfter<=revision&&binding.trustRevision<=revision&&
      trusted?.fingerprint===binding.fingerprint;
    if(!validBinding){
      if(binding?.deviceId)transport.invalidateDevice(binding.deviceId);
      return reject(res,403,'Machine binding does not match current device trust');
    }
    let raw,text;
    try{({raw,text}=await readBody(req));}
    catch(error){return reject(res,error?.code==='TOO_LARGE'?413:400,
      error?.code==='TOO_LARGE'?'Request too large':'Invalid request body');}
    if(req.url==='/agent/challenge'||req.url==='/agent/connect'){
      let payload;
      try{payload=JSON.parse(text);}catch{return reject(res,400,'Invalid JSON');}
      if(!payload||typeof payload!=='object'||Array.isArray(payload)||
         payload.deviceId!==binding.deviceId)return reject(res,403,'Device binding mismatch');
    }else if(req.headers['x-vpsc-device-id']!==binding.deviceId){
      return reject(res,403,'Device binding mismatch');
    }
    const headers={'content-type':'application/json'};
    for(const name of ['x-vpsc-device-id','x-vpsc-session-id','x-vpsc-sequence','x-vpsc-signature']){
      if(typeof req.headers[name]==='string')headers[name]=req.headers[name];
    }
    const channelRequest=Readable.from([raw]);
    channelRequest.url=req.url;channelRequest.method=req.method;channelRequest.headers=headers;
    return transport.handle(channelRequest,res);
  };
  return Object.freeze({handle,operationState:transport.operationState,
    invalidateDevice:transport.invalidateDevice,close:transport.close});
}
