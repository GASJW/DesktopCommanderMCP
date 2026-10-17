import { timingSafeEqual } from 'node:crypto';

// An inert owner-review domain boundary, NOT an HTTP endpoint or Dashboard API.
// The Gateway must verify an owner Access JWT + CSRF before supplying the
// trusted ownerGate. No caller may supply an arbitrary owner as a substitute.
const REQUEST_ID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const FINGERPRINT=/^[a-f0-9]{64}$/;
const CODE=/^[A-F0-9]{10}$/;
const MAX_FAILURES=5;
function denied(){
  const error=new Error('Owner pairing review denied');
  error.code='PAIRING_DECISION_DENIED';
  return error;
}
function unknown(cause){
  const error=new Error('Owner pairing outcome unknown',cause?{cause}:undefined);
  error.code='PAIRING_DECISION_UNKNOWN';
  return error;
}
function normalizeCode(value){
  if(typeof value!=='string' || value.length>20)return null;
  const normalized=value.replace(/[\s-]/g,'').toUpperCase();
  return CODE.test(normalized)?normalized:null;
}
function safeEquals(a,b){
  if(!CODE.test(a)||!CODE.test(b))return false;
  return timingSafeEqual(Buffer.from(a,'ascii'),Buffer.from(b,'ascii'));
}
export function createOwnerPairingReview({coordinator,ownerGate}={}){
  if(!coordinator||!['listPending','approvePairing','rejectPairing'].every(k=>
      typeof coordinator[k]==='function')||typeof ownerGate!=='function'){
    throw new TypeError('Owner gate and pairing coordinator are required');
  }
  const failures=new Map();
  async function checkOwner(context){
    let authorized=false;
    try{authorized=await ownerGate(context)===true;}catch{authorized=false;}
    if(!authorized)throw denied();
  }
  function getPending(requestId){
    if(typeof requestId!=='string'||!REQUEST_ID.test(requestId))throw denied();
    const current=coordinator.listPending().find(p=>p.requestId===requestId);
    if(!current)throw denied();
    return current;
  }
  async function inspectDecision(context,{requestId,expectedFingerprint,requireProof=true}={}){
    await checkOwner(context);
    if(typeof requestId!=='string'||!REQUEST_ID.test(requestId))throw denied();
    const item=coordinator.inspectPairing(requestId);
    if(!item||(requireProof&&!item.proofVerified)||typeof expectedFingerprint!=='string'||
       !FINGERPRINT.test(expectedFingerprint)||item.fingerprint!==expectedFingerprint){
      throw denied();
    }
    let trustRevisionBefore;
    try{trustRevisionBefore=coordinator.trustRevision();}catch(error){throw unknown(error);}
    if(!Number.isSafeInteger(trustRevisionBefore)||trustRevisionBefore<0)throw unknown();
    return Object.freeze({requestId:item.requestId,fingerprint:item.fingerprint,
      trustRevisionBefore});
  }
  async function currentTrustRevision(context){
    await checkOwner(context);
    try{return coordinator.trustRevision();}catch(error){throw unknown(error);}
  }
  async function listPending(context){
    await checkOwner(context);
    return Object.freeze(coordinator.listPending().map(item=>Object.freeze({
      requestId:item.requestId,
      name:item.name,
      platform:item.platform,
      fingerprint:item.fingerprint,
      proofVerified:item.proofVerified,
      createdAt:item.createdAt,
      // Comparison code stays on the device display and inside the coordinator.
      // This owner API never returns displayCode or a pairing nonce.
    })));
  }
  async function approve(context,{requestId,code,expectedFingerprint,decision}={}){
    await checkOwner(context);
    const item=getPending(requestId);
    if(!item.proofVerified||typeof expectedFingerprint!=='string'||
        !FINGERPRINT.test(expectedFingerprint)){
      throw denied();
    }
    const submitted=normalizeCode(code);
    // Use the internal coordinator state; never compare with anything the
    // browser supplied except the code typed from the physical device.
    const actual=coordinator.listPending().find(x=>x.requestId===requestId);
    if(!actual||actual.fingerprint!==expectedFingerprint||
        !submitted||!safeEquals(submitted,actual.displayCode)){
      const n=(failures.get(requestId)??0)+1;
      failures.set(requestId,n);
      if(n>=MAX_FAILURES){
        coordinator.rejectPairing(requestId);
        failures.delete(requestId);
      }
      throw denied();
    }
    // No retry on a failed trust transition; owner must review observed state.
    if(decision!==undefined){
      if(!decision||typeof decision!=='object'||Array.isArray(decision)||
         Object.keys(decision).sort().join(',')!=='eventId,trustRevisionBefore'||
         !REQUEST_ID.test(decision.eventId)||
         decision.trustRevisionBefore<0||!Number.isSafeInteger(decision.trustRevisionBefore)){
        throw denied();
      }
      let observed;
      try{observed=coordinator.trustRevision();}catch(error){throw unknown(error);}
      if(observed!==decision.trustRevisionBefore)throw unknown();
    }
    let registered;
    try{registered=coordinator.approvePairing(requestId,expectedFingerprint,decision);}
    catch(error){throw unknown(error);}
    failures.delete(requestId);
    return Object.freeze({
      deviceId:registered.deviceId,
      fingerprint:registered.fingerprint,
      status:'approved_offline',
    });
  }
  async function reject(context,{requestId,expectedFingerprint}={}){
    await checkOwner(context);
    const item=getPending(requestId);
    if(expectedFingerprint!==undefined&&item.fingerprint!==expectedFingerprint)throw denied();
    failures.delete(requestId);
    const rejected=coordinator.rejectPairing(requestId);
    if(!rejected)throw denied();
    return Object.freeze({rejected});
  }
  return Object.freeze({listPending,inspectDecision,currentTrustRevision,approve,reject});
}
