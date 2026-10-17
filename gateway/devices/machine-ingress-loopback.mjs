import { createServer } from 'node:http';
import { startLoopbackAgentPilot } from './loopback-pilot.mjs';

// Two-boundary test-only ingress: signed Cloudflare M2M identity -> device binding
// -> independent Ed25519 challenge/session/frame verification in inner pilot.
// This DOES NOT configure Cloudflare or expose TLS/public hostname.
const PATHS=new Set(['/agent/challenge','/agent/connect','/agent/heartbeat',
  '/agent/poll','/agent/result','/agent/disconnect']);
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const BODY_MAX=16*1024;
const RESULT_MAX=512*1024;
function send(res,status,json){
  res.writeHead(status,{'content-type':'application/json','cache-control':'no-store',
    'x-content-type-options':'nosniff'});
  res.end(JSON.stringify(json));
}
export async function startMachineIngressLoopback({
  registry,router,verifyMachineToken,machineBindings,
  enableTestIngress=false,host='127.0.0.1',port=0,
}={}){
  if(!enableTestIngress||host!=='127.0.0.1'||port!==0||
     !registry||!router||typeof verifyMachineToken!=='function'||
     !(machineBindings instanceof Map)||machineBindings.size<1||machineBindings.size>32||
     Array.from(machineBindings).some(([c,d])=>typeof c!=='string'||c.length<8||
       c.length>256||typeof d!=='string'||!UUID.test(d))){
    throw new TypeError('Machine ingress requires explicit loopback-only test configuration');
  }
  const bound=new Map(machineBindings);
  const inner=await startLoopbackAgentPilot({registry,router,enableLoopbackPilot:true});
  const server=createServer(async(req,res)=>{
    if(!PATHS.has(req.url))return send(res,404,{error:'Not found'});
    if(req.method!=='POST')return send(res,405,{error:'Method not allowed'});
    if(req.headers.origin)return send(res,403,{error:'Browser origin denied'});
    if(!/^application\/json(?:;|$)/i.test(req.headers['content-type']??'')){
      return send(res,415,{error:'JSON required'});
    }
    // Never accept a human Access cookie, owner email, service header, or any
    // arbitrary claimed clientId in place of a separately signed Access JWT.
    const assertion=req.headers['cf-access-jwt-assertion'];
    if(typeof assertion!=='string'||assertion.length>16*1024){
      return send(res,401,{error:'Machine JWT required'});
    }
    let principal;
    try{principal=await verifyMachineToken(assertion);}catch{return send(res,401,{error:'Machine JWT invalid'});}
    if(!principal||typeof principal.clientId!=='string'){
      return send(res,401,{error:'Machine JWT invalid'});
    }
    const deviceId=bound.get(principal.clientId);
    if(!deviceId)return send(res,403,{error:'Machine not bound to trusted device'});
    let raw;
    try{
      const chunks=[];let total=0;
      for await(const chunk of req){
        total+=chunk.length;
        if(total>BODY_MAX)return send(res,413,{error:'Request too large'});
        chunks.push(chunk);
      }
      raw=Buffer.concat(chunks,total);
    }catch{return send(res,400,{error:'Invalid request body'});}
    if(req.url==='/agent/challenge'||req.url==='/agent/connect'){
      let payload;
      try{payload=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));}
      catch{return send(res,400,{error:'Invalid JSON'});}
      if(!payload||typeof payload!=='object'||Array.isArray(payload)||
         payload.deviceId!==deviceId){
        return send(res,403,{error:'Device binding mismatch'});
      }
    }else if(req.headers['x-vpsc-device-id']!==deviceId){
      return send(res,403,{error:'Device binding mismatch'});
    }
    // Selectively forward only application-signed envelope fields, never
    // Cloudflare JWT/service secrets or user cookies to the inner listener.
    const forward={'content-type':'application/json'};
    for(const h of ['x-vpsc-device-id','x-vpsc-session-id','x-vpsc-sequence',
      'x-vpsc-signature']){
      if(typeof req.headers[h]==='string')forward[h]=req.headers[h];
    }
    try{
      const answer=await fetch(inner.url+req.url,{
        method:'POST',headers:forward,body:raw,redirect:'error',
        signal:AbortSignal.timeout(8000),
      });
      let total=0;const parts=[];
      for await(const chunk of answer.body){
        total+=chunk.length;
        if(total>RESULT_MAX)return send(res,502,{error:'Upstream response too large'});
        parts.push(chunk);
      }
      res.writeHead(answer.status,{'content-type':'application/json',
        'cache-control':'no-store','x-content-type-options':'nosniff'});
      res.end(Buffer.concat(parts,total));
    }catch{return send(res,502,{error:'Agent pilot upstream unavailable'});}
  });
  server.requestTimeout=15_000;
  try{
    await new Promise((resolve,reject)=>{
      server.once('error',reject);
      server.listen(0,'127.0.0.1',resolve);
    });
  }catch(e){await inner.close();throw e;}
  return Object.freeze({
    url:'http://127.0.0.1:'+server.address().port,
    close:async()=>{
      server.closeAllConnections();
      await new Promise(resolve=>server.close(resolve));
      await inner.close();
    }
  });
}
