import { createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { createOwnerPairingReview } from './owner-pairing-review.mjs';
import { isOwnerPrincipal, ownerPrincipalId } from './owner-identity.mjs';
export { ownerPrincipalId } from './owner-identity.mjs';

// Inert HTTP owner approval boundary: NOT imported by Gateway server.
// Requires real Cloudflare owner JWT verifier + a synchronous durable audit
// implementation (auditWrite must resolve true) before caller may mount it.
const PREFIX='/dashboard/api/g7/pairing/';
const ROUTES=new Set(['pending','approve','reject']);
const BODY_LIMIT=2048;
const TOKEN_TTL_MS=5*60*1000;
const RATE_WINDOW_MS=60*1000;
const RATE_MAX=6;
const ORIGIN=/^https:\/\/[a-z0-9.-]+$/;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function response(res,status,body,methods){
  const headers={
    'content-type':'application/json; charset=utf-8',
    'cache-control':'private, no-store, max-age=0',
    'content-security-policy':"default-src 'none'",
    'x-content-type-options':'nosniff',
    'referrer-policy':'no-referrer',
    'vary':'Cf-Access-Jwt-Assertion',
  };
  if(methods)headers.allow=methods;
  res.writeHead(status,headers);
  res.end(JSON.stringify(body));
}
function validOwner(value){
  return isOwnerPrincipal(value);
}
export function createOwnerPairingHttp({
  coordinator,accessVerifier,expectedOrigin,auditWrite,now=Date.now,
}={}){
  if(!coordinator||!accessVerifier||typeof accessVerifier.verifyPrincipal!=='function'||
    typeof expectedOrigin!=='string'||!ORIGIN.test(expectedOrigin)||
    expectedOrigin.endsWith('.local')||typeof auditWrite!=='function'||
    typeof now!=='function'){
    throw new TypeError('Signed owner verifier, approved origin and durable audit required');
  }
  const csrfSecret=randomBytes(32);
  const verified=new WeakSet();
  const review=createOwnerPairingReview({
    coordinator,ownerGate:context=>verified.has(context),
  });
  const rate=new Map();
  let poisoned=false;
  let decisionQueue=Promise.resolve();
  function csrfTag(owner,payload){
    return createHmac('sha256',csrfSecret)
      .update(owner.issuer).update('\0').update(owner.subject).update('\0')
      .update(payload).digest('base64url');
  }
  function mintCsrf(owner){
    const payload=Buffer.from(JSON.stringify({
      at:now(),nonce:randomBytes(16).toString('base64url'),
    })).toString('base64url');
    return payload+'.'+csrfTag(owner,payload);
  }
  function verifyCsrf(owner,token){
    if(typeof token!=='string'||token.length>300||token.length<45)return false;
    const parts=token.split('.');
    if(parts.length!==2||!parts[0]||!parts[1])return false;
    const [payload,tag]=parts;
    if(!/^[a-zA-Z0-9_-]+$/.test(payload)||!/^[a-zA-Z0-9_-]{43}$/.test(tag))return false;
    const expected=csrfTag(owner,payload);
    if(!timingSafeEqual(Buffer.from(tag),Buffer.from(expected)))return false;
    try{
      const info=JSON.parse(Buffer.from(payload,'base64url').toString('utf8'));
      const t=now();
      return Number.isSafeInteger(info.at) && Number.isSafeInteger(t) &&
        t>=info.at && t-info.at<=TOKEN_TTL_MS &&
        typeof info.nonce==='string' && /^[A-Za-z0-9_-]{22}$/.test(info.nonce);
    }catch{return false;}
  }
  function withinRate(owner){
    const t=now();
    const key=ownerPrincipalId(owner);
    for(const [k,v] of rate){
      if(t<v.since || t-v.since>=RATE_WINDOW_MS)rate.delete(k);
    }
    if(rate.size>256)return false;
    const v=rate.get(key);
    if(!v){rate.set(key,{since:t,count:1});return true;}
    if(v.count>=RATE_MAX)return false;
    v.count++;
    return true;
  }
  async function durableEvent(details){
    if(poisoned)throw Error('Owner audit unavailable');
    try{
      if(await auditWrite(Object.freeze({...details,event:'g7_owner_pairing',
        version:2,at:new Date(now()).toISOString()}))!==true)throw Error('Audit not committed');
    }catch{
      poisoned=true;
      throw Error('Owner audit unavailable');
    }
  }
  return async function handleOwnerPairing(req,res){
    const rawPath=req.url;
    if(typeof rawPath!=='string'||!rawPath.startsWith(PREFIX)||
       !ROUTES.has(rawPath.slice(PREFIX.length))){
      return response(res,404,{error:'Not found'});
    }
    const action=rawPath.slice(PREFIX.length);
    const expectedMethod=action==='pending'?'GET':'POST';
    if(req.method!==expectedMethod){
      return response(res,405,{error:'Method not allowed'},expectedMethod);
    }
    if(req.headers.origin&&req.headers.origin!==expectedOrigin){
      return response(res,403,{error:'Cross-origin denied'});
    }
    if(req.headers['sec-fetch-site'] && req.headers['sec-fetch-site']!=='same-origin'&&
       req.headers['sec-fetch-site']!=='none'){
      return response(res,403,{error:'Cross-site denied'});
    }
    if(poisoned)return response(res,503,{error:'Owner audit unavailable'});
    let owner;
    try{
      owner=await accessVerifier.verifyPrincipal(req.headers['cf-access-jwt-assertion']);
    }catch{return response(res,401,{error:'Owner authentication required'});}
    if(!validOwner(owner))return response(res,401,{error:'Owner authentication required'});
    const context=Object.freeze({});
    verified.add(context);
    if(action==='pending'){
      try{
        return response(res,200,{enabled:true,csrf:mintCsrf(owner),
          pending:await review.listPending(context)});
      }catch{return response(res,503,{error:'Pairing review unavailable'});}
    }
    // Browser JSON mutation requires EXACT same-origin Origin and CSRF proof.
    if(req.headers.origin!==expectedOrigin ||
       !verifyCsrf(owner,req.headers['x-vpsc-csrf'])){
      return response(res,403,{error:'CSRF authorization required'});
    }
    if(!/^application\/json(?:\s*;|$)/i.test(req.headers['content-type']??'')){
      return response(res,415,{error:'JSON required'});
    }
    if(!withinRate(owner))return response(res,429,{error:'Too many pairing decisions'});
    let payload;
    try{
      let size=0;const chunks=[];
      for await(const chunk of req){
        size+=chunk.length;
        if(size>BODY_LIMIT)return response(res,413,{error:'Payload too large'});
        chunks.push(chunk);
      }
      payload=JSON.parse(new TextDecoder('utf8',{fatal:true})
        .decode(Buffer.concat(chunks,size)));
      if(!payload||typeof payload!=='object'||Array.isArray(payload)||
         typeof payload.requestId!=='string'||!UUID.test(payload.requestId)||
         typeof payload.expectedFingerprint!=='string'||
         !/^[a-f0-9]{64}$/.test(payload.expectedFingerprint) ||
         Object.keys(payload).sort().join(',')!==
           (action==='approve'?'code,expectedFingerprint,requestId':
             'expectedFingerprint,requestId')){
        return response(res,400,{error:'Invalid pairing decision'});
      }
    }catch{return response(res,400,{error:'Invalid JSON body'});}
    const decision=decisionQueue.then(async()=>{
      let binding;
      try{
        binding=await review.inspectDecision(context,{...payload,
          requireProof:action==='approve'});
      }catch(error){
        if(error?.code==='PAIRING_DECISION_UNKNOWN'){
          poisoned=true;
          return response(res,503,{error:'Pairing outcome requires reconciliation'});
        }
        return response(res,403,{error:'Pairing decision denied'});
      }
      const event={eventId:randomUUID(),operation:action,
        ownerId:ownerPrincipalId(owner),
        requestId:binding.requestId,fingerprint:binding.fingerprint,
        trustRevisionBefore:binding.trustRevisionBefore};
      try{await durableEvent({...event,phase:'intent'});}
      catch{return response(res,503,{error:'Owner audit unavailable'});}
      let result,status=200,outcome='accepted',deviceId=null;
      try{
        result=action==='approve'
          ? await review.approve(context,{...payload,decision:{eventId:event.eventId,
            trustRevisionBefore:event.trustRevisionBefore}})
          : await review.reject(context,payload);
      }catch(error){
        if(error?.code!=='PAIRING_DECISION_DENIED'){
          poisoned=true;
          return response(res,503,{error:'Pairing outcome requires reconciliation'});
        }
        status=403;outcome='denied';result={error:'Pairing decision denied'};
      }
      let trustRevisionAfter;
      try{trustRevisionAfter=await review.currentTrustRevision(context);}
      catch{
        poisoned=true;
        return response(res,503,{error:'Pairing outcome requires reconciliation'});
      }
      if(trustRevisionAfter!==event.trustRevisionBefore+
         (status===200&&action==='approve'?1:0)){
        poisoned=true;
        return response(res,503,{error:'Pairing outcome requires reconciliation'});
      }
      if(status===200&&action==='approve'){
        if(result?.fingerprint!==event.fingerprint||!UUID.test(result?.deviceId??'')){
          poisoned=true;
          return response(res,503,{error:'Pairing outcome requires reconciliation'});
        }
        deviceId=result.deviceId;
      }
      try{
        await durableEvent({...event,phase:'outcome',outcome,deviceId,trustRevisionAfter});
      }catch{
        // The operation may already have completed: never claim failure means
        // no trust mutation; lock the control plane for manual reconciliation.
        return response(res,503,{error:'Pairing outcome requires reconciliation'});
      }
      return response(res,status,result);
    });
    // Keep the queue usable after a request-level exception while preserving
    // the individual request's rejected result for the HTTP server wrapper.
    decisionQueue=decision.then(()=>undefined,()=>undefined);
    return decision;
  };
}
