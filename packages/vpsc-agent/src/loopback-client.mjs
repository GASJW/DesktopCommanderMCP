import { signedAgentRequest } from './frame.mjs';

// Loopback-only fake agent, for synthetic protocol acceptance. Does not
// persist credentials or execute tools; future real agent needs TLS and
// separate Cloudflare machine authentication.
export function createLoopbackAgentClient({url,identity,deviceId,fetchFn=fetch}={}){
  let parsed;
  try{parsed=new URL(url)}catch{throw new TypeError('Invalid loopback pilot URL');}
  if(parsed.protocol!=='http:'||parsed.hostname!=='127.0.0.1'||parsed.username||
    parsed.password||parsed.pathname!=='/'||!parsed.port||parsed.search||parsed.hash||
    !identity||typeof identity.signFrame!=='function'||
    typeof identity.proveDeviceChallenge!=='function') {
    throw new TypeError('Loopback pilot only; no remote endpoints');
  }
  let sessionId=null,sequence=0;
  async function post(pathname,payload,signed=false){
    const raw=JSON.stringify(payload);
    const headers={'content-type':'application/json'};
    if(signed){
      if(!sessionId)throw Error('Device not connected');
      sequence++;
      const framed=signedAgentRequest({method:'POST',pathname,deviceId,sessionId,
        sequence,bodyText:raw});
      headers['x-vpsc-device-id']=deviceId;
      headers['x-vpsc-session-id']=sessionId;
      headers['x-vpsc-sequence']=String(sequence);
      headers['x-vpsc-signature']=identity.signFrame(framed);
    }
    const res=await fetchFn(parsed.origin+pathname,{
      method:'POST',headers,body:raw,redirect:'error',signal:AbortSignal.timeout(15_000),
    });
    const data=await res.json();
    if(!res.ok)throw Error('Pilot request rejected: '+res.status);
    return data;
  }
  async function connect(){
    const challenge=await post('/agent/challenge',{deviceId});
    if(challenge.deviceId!==deviceId)throw Error('Server challenge for wrong device');
    const signature=identity.proveDeviceChallenge(challenge);
    const session=await post('/agent/connect',{deviceId,signature});
    if(session.deviceId!==deviceId||typeof session.sessionId!=='string')throw Error('Wrong session');
    sessionId=session.sessionId;
    sequence=0;
    return {deviceId,sessionId};
  }
  async function heartbeat(){
    return post('/agent/heartbeat',{},true);
  }
  async function poll(){
    return (await post('/agent/poll',{},true)).frame;
  }
  async function pollControl(){
    const answer=await post('/agent/poll',{},true);
    if(!answer||typeof answer!=='object'||Array.isArray(answer)||
       Object.keys(answer).sort().join(',')!=='cancel,frame')throw Error('Invalid poll control response');
    return answer;
  }
  async function result(requestId,result){
    return post('/agent/result',{requestId,result},true);
  }
  async function cancelAck({requestId,ownerDigest,status}){
    return post('/agent/cancel-ack',{requestId,ownerDigest,status},true);
  }
  return Object.freeze({connect,heartbeat,poll,pollControl,result,cancelAck});
}
