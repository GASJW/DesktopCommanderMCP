import { randomUUID } from 'node:crypto';

// Isolated G7.2 prototype: no network listeners, no process execution, no owner auth.
// Transport must authenticate agents and owner/tool policy before invoking this.
const TOOL = /^[A-Za-z][A-Za-z0-9_-]{0,79}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const DIGEST=/^[a-f0-9]{64}$/;

export class DeviceRouteError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'DeviceRouteError';
    this.code = code;
  }
}
const fail = (code, message) => new DeviceRouteError(code, message);
const copy = (value, maxBytes) => {
  let serialized;
  try { serialized = JSON.stringify(value); } catch {
    throw fail('BAD_PAYLOAD', 'Unserializable payload');
  }
  if (typeof serialized !== 'string' || Buffer.byteLength(serialized, 'utf8') > maxBytes) {
    throw fail('BAD_PAYLOAD', 'Payload is missing or too large');
  }
  return JSON.parse(serialized);
};

export function createDeviceRouter({
  registry, timeoutMs = 30_000, maxPendingPerDevice = 4,
  maxRequestBytes = 128 * 1024, maxResponseBytes = 1024 * 1024,
} = {}) {
  if (!registry || typeof registry.isLiveSession !== 'function' ||
      !Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 120_000 ||
      !Number.isInteger(maxPendingPerDevice) || maxPendingPerDevice < 1 || maxPendingPerDevice > 16 ||
      !Number.isInteger(maxRequestBytes) || maxRequestBytes < 1024 || maxRequestBytes > 1024 * 1024 ||
      !Number.isInteger(maxResponseBytes) || maxResponseBytes < 1024 || maxResponseBytes > 8 * 1024 * 1024) {
    throw new TypeError('Invalid router configuration');
  }
  const active = new Map();
  let stopped = false;
  const endPending = (channel, error) => {
    for (const [id, item] of channel.pending) {
      channel.pending.delete(id);
      clearTimeout(item.timer);
      item.signal?.removeEventListener('abort',item.onAbort);
      let removed=false;
      try{removed=channel.cancel?.(id)===true;}catch{}
      item.reject(removed?fail('CANCELLED','Operation was removed before agent delivery'):error);
    }
  };
  function attachTransport({deviceId, sessionId, send, cancel} = {}) {
    if (stopped) throw fail('CLOSED', 'Router closed');
    if (typeof send !== 'function'||cancel!==undefined&&typeof cancel!=='function'||
        !registry.isLiveSession(deviceId, sessionId)) {
      throw fail('UNAUTHORIZED_DEVICE', 'Device session is not authenticated and live');
    }
    const previous = active.get(deviceId);
    if (previous && previous.sessionId === sessionId) {
      throw fail('SESSION_IN_USE', 'Session already attached');
    }
    if (previous) endPending(previous, fail('AMBIGUOUS_DISCONNECT', 'Session superseded; no replay'));
    active.set(deviceId, {sessionId, send,cancel,pending:new Map()});
    return Object.freeze({deviceId,sessionId});
  }
  async function callDevice({deviceId, name, arguments:args = {}, requestId:requestedId,
    authorization,signal,beforeDispatch} = {}) {
    if (stopped) throw fail('CLOSED', 'Router closed');
    if (typeof deviceId !== 'string' || !UUID.test(deviceId)) {
      throw fail('BAD_DEVICE', 'Explicit deviceId required');
    }
    if (typeof name !== 'string' || !TOOL.test(name)) {
      throw fail('BAD_TOOL', 'Invalid tool name');
    }
    const requestId=requestedId??randomUUID();
    if(typeof requestId!=='string'||!UUID.test(requestId)){
      throw fail('BAD_REQUEST_ID','Invalid device execution request id');
    }
    if(signal!==undefined&&(!signal||typeof signal.aborted!=='boolean'||
       typeof signal.addEventListener!=='function'||typeof signal.removeEventListener!=='function')){
      throw fail('BAD_SIGNAL','Invalid operation cancellation signal');
    }
    if(beforeDispatch!==undefined&&typeof beforeDispatch!=='function'){
      throw fail('BAD_PERMIT','Invalid pre-dispatch authorization callback');
    }
    if(signal?.aborted)throw fail('CANCELLED','Operation cancelled before device dispatch');
    if(authorization!==undefined&&(!authorization||typeof authorization!=='object'||
       Array.isArray(authorization)||Object.getPrototypeOf(authorization)!==Object.prototype||
       Object.keys(authorization).sort().join(',')!==
         'approvalEventId,approvalTrustRevisionAfter,approvalTrustRevisionBefore,fingerprint,ownerDigest,policyRevision,trustRevision'||
       !DIGEST.test(authorization.ownerDigest??'')||!Number.isSafeInteger(authorization.trustRevision)||
       authorization.trustRevision<0||!UUID.test(authorization.approvalEventId??'')||
       !DIGEST.test(authorization.fingerprint??'')||
       !Number.isSafeInteger(authorization.approvalTrustRevisionBefore)||authorization.approvalTrustRevisionBefore<0||
       !Number.isSafeInteger(authorization.approvalTrustRevisionAfter)||
       authorization.approvalTrustRevisionAfter!==authorization.approvalTrustRevisionBefore+1||
       authorization.approvalTrustRevisionAfter>authorization.trustRevision||
       typeof authorization.policyRevision!=='string'||
       authorization.policyRevision.length<1||authorization.policyRevision.length>128||
       /[\u0000-\u001f\u007f]/.test(authorization.policyRevision))){
      throw fail('BAD_AUTHORIZATION','Invalid owner authorization receipt');
    }
    if (!args || typeof args !== 'object' || Array.isArray(args) ||
        (Object.getPrototypeOf(args) !== Object.prototype && Object.getPrototypeOf(args) !== null)) {
      throw fail('BAD_PAYLOAD', 'Tool arguments must be a plain object');
    }
    const params = copy({name,arguments:args}, maxRequestBytes);
    const channel = active.get(deviceId);
    if (!channel || !registry.isLiveSession(deviceId, channel.sessionId)) {
      if (channel) {
        active.delete(deviceId);
        endPending(channel, fail('AMBIGUOUS_DISCONNECT','Session expired; no replay'));
      }
      throw fail('OFFLINE', 'Device offline');
    }
    if (channel.pending.size >= maxPendingPerDevice) throw fail('BUSY', 'Device busy');
    if(channel.pending.has(requestId))throw fail('DUPLICATE_REQUEST','Execution request is already pending');
    return new Promise((resolve,reject) => {
      const item={timer:null,resolve,reject,signal,dispatched:false,delivered:false,onAbort:null,
        authorizationOwnerDigest:authorization?.ownerDigest};
      const finish=(error)=>{
        if(!channel.pending.delete(requestId))return false;
        clearTimeout(item.timer);signal?.removeEventListener('abort',item.onAbort);
        reject(error);return true;
      };
      item.onAbort=()=>{
        if(!channel.pending.delete(requestId))return;
        clearTimeout(item.timer);signal?.removeEventListener('abort',item.onAbort);
        let removed=false;
        try{removed=channel.cancel?.(requestId)===true;}catch{}
        reject(item.dispatched&&!removed
          ?fail('AMBIGUOUS_CANCELLED','Cancellation arrived after dispatch; outcome unknown; do not replay')
          :fail('CANCELLED','Operation was cancelled before the agent received it'));
      };
      item.timer=setTimeout(()=>{
        if(!channel.pending.delete(requestId))return;
        signal?.removeEventListener('abort',item.onAbort);
        let removed=false;
        try{removed=channel.cancel?.(requestId)===true;}catch{}
        reject(item.dispatched&&!removed
          ?fail('AMBIGUOUS_TIMEOUT','Outcome unknown; do not replay')
          :fail('CANCELLED','Request expired before the agent received it'));
      },timeoutMs);
      channel.pending.set(requestId,item);
      signal?.addEventListener('abort',item.onAbort,{once:true});
      if(signal?.aborted){item.onAbort();return;}
      Promise.resolve().then(async()=>{
        let permit;
        try{
          if(stopped||active.get(deviceId)!==channel||!channel.pending.has(requestId)||
             !registry.isLiveSession(deviceId,channel.sessionId)){
            throw fail('AMBIGUOUS_DISCONNECT','Device unavailable; no replay');
          }
          if(beforeDispatch){
            permit=await beforeDispatch(Object.freeze({deviceId,sessionId:channel.sessionId,
              requestId,name,arguments:params.arguments}));
            if(!permit||typeof permit!=='object'||Array.isArray(permit)||
               Object.getPrototypeOf(permit)!==Object.prototype||
               Object.keys(permit).sort().join(',')!=='authorization,release'||
               !permit.authorization||typeof permit.authorization!=='object'||
               Array.isArray(permit.authorization)||Object.getPrototypeOf(permit.authorization)!==Object.prototype||
               typeof permit.release!=='function'){
              throw fail('BAD_PERMIT','Pre-dispatch authorization permit is invalid');
            }
          }
          if(stopped||active.get(deviceId)!==channel||!channel.pending.has(requestId)||
             signal?.aborted||!registry.isLiveSession(deviceId,channel.sessionId)){
            throw fail(signal?.aborted?'CANCELLED':'AMBIGUOUS_DISCONNECT',
              'Device unavailable before transport handoff');
          }
          const boundAuthorization=permit?.authorization??authorization;
          item.authorizationOwnerDigest=boundAuthorization?.claims?.ownerDigest??
            boundAuthorization?.ownerDigest??authorization?.ownerDigest;
          const frame=Object.freeze(copy({version:1,deviceId,sessionId:channel.sessionId,requestId,
            method:'tools/call',params,...(boundAuthorization?{authorization:boundAuthorization}:{})},maxRequestBytes));
          item.dispatched=true;
          try{
            await channel.send(frame);
            item.delivered=true;
          }finally{
            if(permit){const release=permit.release;permit=undefined;release();}
          }
        }catch(error){
          if(permit){
            try{permit.release();}catch{}
            permit=undefined;
          }
          if(item.dispatched){
            finish(fail('AMBIGUOUS_DISPATCH','Transport handoff failed; outcome unknown'));
          }else{
            finish(error&&typeof error.code==='string'?error:
              fail('AUTHORIZATION_FAILED','Operation authorization failed before dispatch'));
          }
        }
      });
    });
  }
  // acceptResponse must be called ONLY from a verified agent transport.
  function acceptResponse({deviceId, sessionId, requestId, result} = {}) {
    const channel = active.get(deviceId);
    if (stopped || !channel || channel.sessionId !== sessionId ||
        !registry.isLiveSession(deviceId, sessionId) || typeof requestId !== 'string' ||
        !UUID.test(requestId) || !channel.pending.has(requestId)) return false;
    if(!channel.pending.get(requestId)?.delivered)return false;
    let payload;
    try { payload = copy(result,maxResponseBytes); } catch {
      const item=channel.pending.get(requestId);
      channel.pending.delete(requestId);
      clearTimeout(item.timer);
      item.reject(fail('BAD_RESPONSE','Remote response invalid or too large'));
      return false;
    }
    const item=channel.pending.get(requestId);
    channel.pending.delete(requestId);
    clearTimeout(item.timer);
    item.signal?.removeEventListener('abort',item.onAbort);
    item.resolve(payload);
    return true;
  }
  // Only the authenticated transport may report the terminal state of a
  // cancellation control previously issued for this exact live request.
  function acceptCancellation({deviceId,sessionId,requestId,ownerDigest,status}={}){
    const channel=active.get(deviceId);
    if(stopped||!channel||channel.sessionId!==sessionId||
       !registry.isLiveSession(deviceId,sessionId)||!UUID.test(requestId??'')||
       !DIGEST.test(ownerDigest??'')||!['cancelled','completed','ambiguous'].includes(status))return false;
    const item=channel.pending.get(requestId);
    if(!item||!item.delivered||item.authorizationOwnerDigest!==ownerDigest)return false;
    channel.pending.delete(requestId);clearTimeout(item.timer);
    item.signal?.removeEventListener('abort',item.onAbort);
    item.reject(status==='cancelled'
      ?fail('CANCELLED','Agent confirmed cancellation before execution')
      :fail('AMBIGUOUS_CANCELLED',status==='completed'
        ?'Operation completed before cancellation; no rollback was performed'
        :'Cancellation outcome is ambiguous; do not replay'));
    return true;
  }
  // Policy invalidation while a frame is still queued is a known no-effect
  // cancellation. This is separate from post-delivery cancellation, which is
  // always ambiguous until the authenticated agent reports its outcome.
  function rejectBeforeDelivery({deviceId,sessionId,requestId}={}){
    const channel=active.get(deviceId),item=channel?.pending.get(requestId);
    if(stopped||!channel||channel.sessionId!==sessionId||!item||item.delivered||
       !registry.isLiveSession(deviceId,sessionId))return false;
    let removed=false;
    try{removed=channel.cancel?.(requestId)===true;}catch{}
    if(!removed)return false;
    channel.pending.delete(requestId);clearTimeout(item.timer);
    item.signal?.removeEventListener('abort',item.onAbort);
    item.reject(fail('AUTHORIZATION_REVOKED','Authorization changed before agent delivery'));
    return true;
  }
  function detachTransport({deviceId,sessionId} = {}) {
    const channel=active.get(deviceId);
    if (!channel || channel.sessionId !== sessionId) return false;
    active.delete(deviceId);
    endPending(channel,fail('AMBIGUOUS_DISCONNECT','Device disconnected; no replay'));
    return true;
  }
  function close() {
    if (stopped) return;
    stopped=true;
    for (const channel of active.values()) endPending(channel,fail('CLOSED','Router closed'));
    active.clear();
  }
  return Object.freeze({attachTransport,callDevice,acceptResponse,acceptCancellation,rejectBeforeDelivery,
    detachTransport,close});
}
