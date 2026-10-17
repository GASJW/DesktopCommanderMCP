import { createServer } from 'node:http';
import { signedAgentRequest } from '../../packages/vpsc-agent/src/frame.mjs';

const ROUTES = new Set(['/agent/challenge','/agent/connect','/agent/heartbeat',
  '/agent/poll','/agent/result','/agent/cancel-ack','/agent/disconnect']);
const MAX_REQUEST = 256 * 1024;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const DIGEST=/^[a-f0-9]{64}$/;
const reject = (res,status,message) => reply(res,status,{error:message});
function reply(res,status,body) {
  res.writeHead(status,{'content-type':'application/json','cache-control':'no-store',
    'x-content-type-options':'nosniff'});
  res.end(JSON.stringify(body));
}
function validBody(value) {
  return value && typeof value === 'object' && !Array.isArray(value);
}

// NO TLS and NO external ingress: deliberately disabled except explicit
// local test invocation. Future owner/Cloudflare policies are not represented.
export async function startLoopbackAgentPilot({
  registry,router,shouldCancelOperation,enableLoopbackPilot=false,host='127.0.0.1',port=0,
} = {}) {
  if (!enableLoopbackPilot || host !== '127.0.0.1' || port !== 0 ||
      !registry || typeof registry.acceptSignedFrame !== 'function' ||
      !router || typeof router.attachTransport !== 'function'||
      typeof router.acceptCancellation!=='function'||typeof router.rejectBeforeDelivery!=='function') {
    throw new Error('Agent pilot must be explicitly enabled, ephemeral and loopback-only');
  }
  const channels=new Map();
  const operationStates=new Map();
  function setOperationState(requestId,state){
    if(!operationStates.has(requestId)&&operationStates.size>=256){
      const evict=Array.from(operationStates).find(([,value])=>
        !['queued','delivered','cancel_requested'].includes(value.state));
      if(!evict)throw Error('Pilot operation state limit reached');
      operationStates.delete(evict[0]);
    }
    operationStates.set(requestId,state);
  }
  const server=createServer(async(req,res)=>{
    if (req.headers.origin) return reject(res,403,'Origin forbidden');
    if (!ROUTES.has(req.url)) return reject(res,404,'Not found');
    if (req.method !== 'POST') return reject(res,405,'Method not allowed');
    if (!/^application\/json(?:;|$)/i.test(req.headers['content-type']??'')) {
      return reject(res,415,'JSON required');
    }
    // Keep request bytes intact until after the size check. Decoding each
    // network chunk independently may replace a split UTF-8 codepoint, which
    // would silently change the body that is being authenticated.
    const chunks=[];
    let total=0;
    try {
      for await(const chunk of req) {
        total+=chunk.length;
        if (total>MAX_REQUEST) return reject(res,413,'Request too large');
        chunks.push(chunk);
      }
    }catch {return reject(res,400,'Invalid request');}
    let raw;
    try {raw=new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks,total));}
    catch {return reject(res,400,'Invalid UTF-8');}
    let body;
    try {body=JSON.parse(raw)}catch {return reject(res,400,'Invalid JSON');}
    if (!validBody(body)) return reject(res,400,'Invalid payload');

    if (req.url==='/agent/challenge') {
      if (typeof body.deviceId !== 'string' || !UUID.test(body.deviceId)) {
        return reject(res,400,'Invalid device');
      }
      try{return reply(res,200,registry.beginHandshake(body.deviceId));}
      catch{return reject(res,403,'Device untrusted');}
    }
    if (req.url==='/agent/connect') {
      if (typeof body.deviceId !== 'string'||!UUID.test(body.deviceId)||
          typeof body.signature !== 'string') return reject(res,400,'Invalid connection');
      try {
        const session=registry.completeHandshake(body.deviceId,body.signature);
        const old=channels.get(body.deviceId);
        if (old) {
          router.detachTransport({deviceId:body.deviceId,sessionId:old.sessionId});
          channels.delete(body.deviceId);
        }
        return reply(res,200,session);
      } catch {return reject(res,403,'Device proof rejected');}
    }

    // For all ongoing requests, possession of a session ID is INSUFFICIENT.
    // Verify a fresh signed request bound to the exact path and raw body.
    const deviceId=req.headers['x-vpsc-device-id'];
    const sessionId=req.headers['x-vpsc-session-id'];
    const sequenceString=req.headers['x-vpsc-sequence'];
    const signature=req.headers['x-vpsc-signature'];
    if (typeof sequenceString !== 'string' || !/^[1-9][0-9]{0,14}$/.test(sequenceString)) {
      return reject(res,401,'Signed agent sequence required');
    }
    const sequence=Number(sequenceString);
    let framed;
    try {
      framed=signedAgentRequest({method:req.method,pathname:req.url,
        deviceId,sessionId,sequence,bodyText:raw});
    }catch{return reject(res,401,'Signed agent envelope required');}
    if (!registry.acceptSignedFrame(deviceId,sessionId,sequence,framed,signature)) {
      return reject(res,401,'Invalid signed agent request');
    }
    const active=channels.get(deviceId);
    if (active && active.sessionId!==sessionId) {
      router.detachTransport({deviceId,sessionId:active.sessionId});
      channels.delete(deviceId);
    }
    if (req.url==='/agent/heartbeat') {
      const existing=channels.get(deviceId);
      if (!existing) {
        const queue=[],controls=[],activeRequests=new Map(),cancelEvidence=new Map();
        try {
          router.attachTransport({deviceId,sessionId,send:frame=>{
            if (queue.length>=4) throw Error('Pilot queue full');
            let delivered;
            const handoff=new Promise(resolve=>{delivered=resolve;});
            queue.push({frame,delivered});
            try{setOperationState(frame.requestId,{requestId:frame.requestId,deviceId,sessionId,state:'queued'});}
            catch(error){queue.pop();delivered();throw error;}
            return handoff;
          },cancel:requestId=>{
            const index=queue.findIndex(item=>item.frame.requestId===requestId);
            if(index>=0){
              const [queued]=queue.splice(index,1);
              queued.delivered();
              setOperationState(requestId,{requestId,deviceId,sessionId,state:'cancelled_before_delivery'});
              return true;
            }
            const frame=activeRequests.get(requestId);
            const ownerDigest=frame?.authorization?.claims?.ownerDigest;
            if(!frame||!DIGEST.test(ownerDigest??'')||controls.length>=4)return false;
            if(!controls.some(item=>item.requestId===requestId)){
              controls.push({version:1,type:'cancel',deviceId,sessionId,requestId,ownerDigest});
              cancelEvidence.set(requestId,{ownerDigest,sessionId,routerSettled:true});
              setOperationState(requestId,{requestId,deviceId,sessionId,state:'cancel_requested'});
            }
            return false;
          }});
        }catch{return reject(res,409,'Device channel conflict');}
        channels.set(deviceId,{sessionId,queue,controls,activeRequests,cancelEvidence});
      }
      return reply(res,200,{status:'alive',deviceId});
    }
    if(req.url==='/agent/disconnect'){
      if(!registry.disconnect(deviceId,sessionId))return reject(res,401,'Device session is no longer active');
      const existing=channels.get(deviceId);
      if(existing?.sessionId===sessionId){
        router.detachTransport({deviceId,sessionId});
        channels.delete(deviceId);
      }
      return reply(res,200,{disconnected:true});
    }
    const channel=channels.get(deviceId);
    if (!channel || channel.sessionId!==sessionId) {
      return reject(res,409,'Heartbeat required before routing');
    }
    if (req.url==='/agent/poll') {
      let cancel=channel.controls.shift()??null;
      if(!cancel&&channel.activeRequests.size&&shouldCancelOperation){
        for(const activeFrame of channel.activeRequests.values()){
          let allowed=false;
          try{allowed=shouldCancelOperation(Object.freeze({...activeFrame} ))===true;}catch{}
          if(!allowed){
            const ownerDigest=activeFrame.authorization?.claims?.ownerDigest;
            if(DIGEST.test(ownerDigest??'')&&channel.controls.length<4){
              cancel={version:1,type:'cancel',deviceId,sessionId,
                requestId:activeFrame.requestId,ownerDigest};
              channel.cancelEvidence.set(activeFrame.requestId,{ownerDigest,sessionId,routerSettled:false});
              setOperationState(activeFrame.requestId,{requestId:activeFrame.requestId,
                deviceId,sessionId,state:'cancel_requested'});
              break;
            }
          }
        }
      }
      if(!cancel)cancel=channel.controls.shift()??null;
      let frame=null;
      if(!cancel&&channel.activeRequests.size===0){
        const queued=channel.queue[0]??null;
        if(queued){
          let allowed=true;
          if(shouldCancelOperation){
            try{allowed=shouldCancelOperation(Object.freeze({...queued.frame}))===true;}
            catch{allowed=false;}
          }
          if(!allowed){
            // A policy or trust check that cannot be proved current is a
            // known no-dispatch denial. The router removes only this queued
            // request and releases its durable grant permit.
            router.rejectBeforeDelivery({deviceId,sessionId,requestId:queued.frame.requestId});
          }else if(channel.queue[0]===queued){
            channel.queue.shift();
            frame=queued.frame;
            channel.activeRequests.set(frame.requestId,frame);
            setOperationState(frame.requestId,{requestId:frame.requestId,deviceId,sessionId,state:'delivered'});
            queued.delivered();
          }
        }
      }
      return reply(res,200,{frame,cancel});
    }
    if(req.url==='/agent/cancel-ack'){
      if(Object.keys(body).sort().join(',')!=='ownerDigest,requestId,status'||
         !UUID.test(body.requestId??'')||!DIGEST.test(body.ownerDigest??'')||
         !['cancelled','completed','ambiguous'].includes(body.status)){
        return reject(res,400,'Invalid cancellation acknowledgement');
      }
      const activeFrame=channel.activeRequests.get(body.requestId);
      const cancellation=channel.cancelEvidence.get(body.requestId);
      if(!activeFrame||activeFrame.sessionId!==sessionId||
         activeFrame.authorization?.claims?.ownerDigest!==body.ownerDigest||
         cancellation?.ownerDigest!==body.ownerDigest||cancellation?.sessionId!==sessionId||
         operationStates.get(body.requestId)?.state!=='cancel_requested'){
        return reject(res,409,'Cancellation does not match an active request');
      }
      const accepted=router.acceptCancellation({deviceId,sessionId,requestId:body.requestId,
        ownerDigest:body.ownerDigest,status:body.status});
      channel.activeRequests.delete(body.requestId);
      channel.cancelEvidence.delete(body.requestId);
      if(!accepted&&cancellation.routerSettled){
        // The requester already received an ambiguous post-delivery result.
        // This ACK only closes the agent-side control and cannot upgrade that
        // result to success or prove rollback.
        setOperationState(body.requestId,{requestId:body.requestId,deviceId,sessionId,
          state:'ambiguous'});
        return reply(res,200,{accepted:true,status:'ambiguous'});
      }
      setOperationState(body.requestId,{requestId:body.requestId,deviceId,sessionId,
        state:accepted?body.status:'ambiguous'});
      return accepted?reply(res,200,{accepted:true,status:body.status}):
        reject(res,409,'Router no longer accepts this cancellation outcome');
    }
    if (req.url==='/agent/result') {
      if (typeof body.requestId !== 'string'||!UUID.test(body.requestId)||
          !Object.hasOwn(body,'result')) return reject(res,400,'Invalid result');
      const activeFrame=channel.activeRequests.get(body.requestId);
      if(!activeFrame||activeFrame.sessionId!==sessionId){
        return reject(res,409,'Result has no delivered operation');
      }
      const accepted=router.acceptResponse({deviceId,sessionId,
        requestId:body.requestId,result:body.result});
      if(accepted){
        channel.activeRequests.delete(body.requestId);
        setOperationState(body.requestId,{requestId:body.requestId,deviceId,sessionId,state:'completed'});
      }
      return accepted?reply(res,200,{accepted:true}):reject(res,409,'Result rejected or stale');
    }
    return reject(res,404,'Not found');
  });
  server.requestTimeout=10_000;
  await new Promise((resolve,reject)=>{
    server.once('error',reject);
    server.listen(0,'127.0.0.1',resolve);
  });
  return Object.freeze({
    url:'http://127.0.0.1:'+server.address().port,
    invalidateDevice:deviceId=>{
      const channel=channels.get(deviceId);
      if(!channel)return false;
      for(const requestId of channel.activeRequests.keys()){
        setOperationState(requestId,{requestId,deviceId,sessionId:channel.sessionId,state:'ambiguous'});
      }
      router.detachTransport({deviceId,sessionId:channel.sessionId});
      channels.delete(deviceId);
      return true;
    },
    operationState:requestId=>{
        const state=operationStates.get(requestId);
        return state?Object.freeze({...state}):null;
      },
      close:async()=>{
      for(const [deviceId,{sessionId}]of channels){
        router.detachTransport({deviceId,sessionId});
      }
      channels.clear();
      server.closeAllConnections();
      await new Promise(resolve=>server.close(resolve));
    },
  });
}
