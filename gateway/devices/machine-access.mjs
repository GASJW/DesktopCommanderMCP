import { createPublicKey, verify as verifySignature } from 'node:crypto';

// G7 machine Access verifier. Separate from the owner-email verifier.
// Cloudflare Service Token application JWT: sub="" and common_name=Client ID.
// No routing, listener, Cloudflare configuration or authorization side effects.
const JWT_MAX=16*1024;
const KEY_CACHE_MS=5*60*1000;
const MAX_AGE_SECONDS=24*60*60;
const SKEW_SECONDS=30;
function parseB64Json(segment){
  if(typeof segment!=='string'||segment.length<1||segment.length>JWT_MAX||
     !/^[A-Za-z0-9_-]+$/.test(segment))throw Error('Bad JWT segment');
  const b=Buffer.from(segment,'base64url');
  if(!b.length||b.toString('base64url')!==segment)throw Error('Bad JWT encoding');
  return JSON.parse(b.toString('utf8'));
}
export function createMachineAccessVerifier({
  issuer,audience,allowedClientIds,keyProvider,now=Date.now,
}={}){
  if(typeof issuer!=='string'||!/^https:\/\/[a-z0-9-]+\.cloudflareaccess\.com$/.test(issuer)||
     typeof audience!=='string'||!/^[a-fA-F0-9]{64}$/.test(audience)||
     !Array.isArray(allowedClientIds)||!allowedClientIds.length||
     allowedClientIds.length>64||allowedClientIds.some(x=>typeof x!=='string'||
       x.length<8||x.length>256||!/^[A-Za-z0-9_.-]+$/.test(x))||
     (keyProvider!==undefined&&typeof keyProvider!=='function')||
     typeof now!=='function') throw new TypeError('Invalid G7 machine Access policy');
  const approved=new Set(allowedClientIds);
  if(approved.size!==allowedClientIds.length)throw new TypeError('Duplicate machine client identity');
  let keys=null,cachedAt=0;
  const certs=issuer+'/cdn-cgi/access/certs';
  async function getKeys(refresh=false){
    const t=now();
    if(!refresh&&keys&&t>=cachedAt&&t-cachedAt<KEY_CACHE_MS)return keys;
    let raw;
    if(keyProvider)raw=await keyProvider();
    else{
      const ctrl=new AbortController();
      const timer=setTimeout(()=>ctrl.abort(),4500);
      try{
        const res=await fetch(certs,{headers:{accept:'application/json'},
          redirect:'error',signal:ctrl.signal});
        if(!res.ok)throw Error('Access JWKS unavailable');
        raw=await res.json();
      }finally{clearTimeout(timer);}
    }
    if(!raw||!Array.isArray(raw.keys)||raw.keys.length===0||raw.keys.length>100){
      throw Error('Untrusted Access key set');
    }
    const valid=raw.keys.filter(k=>k&&k.kty==='RSA'&&(k.alg==null||k.alg==='RS256')&&
      typeof k.kid==='string'&&k.kid.length>0&&k.kid.length<256&&
      typeof k.n==='string'&&typeof k.e==='string');
    if(!valid.length)throw Error('Untrusted Access key set');
    keys=valid;
    cachedAt=t;
    return keys;
  }
  return async function verifyMachineToken(jwt){
    if(typeof jwt!=='string'||jwt.length<30||jwt.length>JWT_MAX)return null;
    const parts=jwt.split('.');
    if(parts.length!==3)return null;
    try{
      const [a,b,s]=parts;
      const header=parseB64Json(a),claims=parseB64Json(b);
      if(header?.alg!=='RS256'||typeof header.kid!=='string'||!header.kid||
         header.kid.length>=256||!claims||typeof claims!=='object')return null;
      const t=Math.floor(now()/1000);
      if(claims.type!=='app'||claims.sub!==''||
         typeof claims.common_name!=='string'||!approved.has(claims.common_name)||
         claims.iss!==issuer||
         !(claims.aud===audience||
           (Array.isArray(claims.aud)&&claims.aud.includes(audience)))||
         !Number.isInteger(claims.iat)||claims.iat>t+SKEW_SECONDS||
         !Number.isInteger(claims.exp)||claims.exp<=t-SKEW_SECONDS||
         claims.exp<claims.iat||claims.exp-claims.iat>MAX_AGE_SECONDS||
         (claims.nbf!=null&&(!Number.isInteger(claims.nbf)||
           claims.nbf>t+SKEW_SECONDS||claims.nbf>claims.exp)))return null;
      let jwks=await getKeys();
      let key=jwks.find(x=>x.kid===header.kid);
      if(!key){jwks=await getKeys(true);key=jwks.find(x=>x.kid===header.kid);}
      if(!key)return null;
      if(typeof s!=='string'||!s.length||!/^[A-Za-z0-9_-]+$/.test(s))return null;
      const sig=Buffer.from(s,'base64url');
      if(sig.toString('base64url')!==s)return null;
      const ok=verifySignature('RSA-SHA256',Buffer.from(a+'.'+b),
        createPublicKey({key,format:'jwk'}),sig);
      return ok?Object.freeze({clientId:claims.common_name}):null;
    }catch{return null;}
  };
}
