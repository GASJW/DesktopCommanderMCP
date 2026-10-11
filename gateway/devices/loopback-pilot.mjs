import { createServer } from 'node:http';
import { signedAgentRequest } from '../../packages/vpsc-agent/src/frame.mjs';

const ROUTES = new Set(['/agent/challenge','/agent/connect','/agent/heartbeat','/agent/poll','/agent/result']);
const MAX_REQUEST = 16 * 1024;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
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
  registry,router,enableLoopbackPilot=false,host='127.0.0.1',port=0,
} = {}) {
  if (!enableLoopbackPilot || host !== '127.0.0.1' || port !== 0 ||
      !registry || typeof registry.acceptSignedFrame !== 'function' ||
      !router || typeof router.attachTransport !== 'function') {
    throw new Error('Agent pilot must be explicitly enabled, ephemeral and loopback-only');
  }
  const channels=new Map();
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
        const queue=[];
        try {
          router.attachTransport({deviceId,sessionId,send:frame=>{
            if (queue.length>=4) throw Error('Pilot queue full');
            queue.push(frame);
          }});
        }catch{return reject(res,409,'Device channel conflict');}
        channels.set(deviceId,{sessionId,queue});
      }
      return reply(res,200,{status:'alive',deviceId});
    }
    const channel=channels.get(deviceId);
    if (!channel || channel.sessionId!==sessionId) {
      return reject(res,409,'Heartbeat required before routing');
    }
    if (req.url==='/agent/poll') {
      const frame=channel.queue.shift()??null;
      return reply(res,200,{frame});
    }
    if (req.url==='/agent/result') {
      if (typeof body.requestId !== 'string'||!UUID.test(body.requestId)||
          !Object.hasOwn(body,'result')) return reject(res,400,'Invalid result');
      const accepted=router.acceptResponse({deviceId,sessionId,
        requestId:body.requestId,result:body.result});
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
