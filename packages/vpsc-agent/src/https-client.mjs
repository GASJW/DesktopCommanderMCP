import { signedAgentRequest } from './frame.mjs';

// Outbound HTTPS client candidate. It does not create an inbound listener,
// install itself, run tools, persist service credentials or start automatically.
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CLIENT=/^[A-Za-z0-9_.-]{8,256}$/;
const ROUTES=new Set(['/agent/challenge','/agent/connect','/agent/heartbeat',
  '/agent/poll','/agent/result','/agent/cancel-ack','/agent/disconnect']);
const MAX_BYTES=256*1024;
const MAX_RESPONSE=512*1024;
const MAX_CLOCK_OFFSET_MS=5*60_000;
const NONCE=/^[A-Za-z0-9_-]{43}$/;
export class HttpsAgentError extends Error{
  constructor(code,message){super(message);this.name='HttpsAgentError';this.code=code;}
}
const fail=(code,message)=>new HttpsAgentError(code,message);
function exactKeys(value,keys){
  return value&&typeof value==='object'&&!Array.isArray(value)&&
    Object.getPrototypeOf(value)===Object.prototype&&
    Object.keys(value).sort().join(',')===keys;
}
function checkedOrigin(gatewayUrl,expectedHostname){
  if(typeof gatewayUrl!=='string'||typeof expectedHostname!=='string'||
     !/^[a-z0-9.-]{6,255}$/.test(expectedHostname)||
     !expectedHostname.includes('.')||expectedHostname==='localhost'){
    throw fail('CONFIG','Explicit trusted HTTPS hostname required');
  }
  let u;
  try{u=new URL(gatewayUrl);}catch{throw fail('CONFIG','Invalid HTTPS Gateway URL');}
  if(u.protocol!=='https:'||u.hostname!==expectedHostname||u.port!==''||
     u.username||u.password||u.pathname!=='/'||u.search||u.hash||
     /^\d+\.\d+\.\d+\.\d+$/.test(u.hostname)||u.hostname.endsWith('.local')){
    throw fail('CONFIG','Gateway URL must match pinned HTTPS hostname');
  }
  return u.origin;
}
export function createHttpsAgentClient({
  gatewayUrl,expectedHostname,identity,deviceId,clientId,clientSecret,
  fetchFn=fetch,timeoutMs=12_000,
}={}){
  const origin=checkedOrigin(gatewayUrl,expectedHostname);
  if(typeof deviceId!=='string'||!UUID.test(deviceId)||
     !identity||typeof identity.signFrame!=='function'||
     typeof identity.proveDeviceChallenge!=='function'||
     typeof clientId!=='string'||!CLIENT.test(clientId)||
     typeof clientSecret!=='string'||clientSecret.length<16||clientSecret.length>512||
     /[\r\n\0]/.test(clientSecret)||
     typeof fetchFn!=='function'||
     !Number.isSafeInteger(timeoutMs)||timeoutMs<1000||timeoutMs>60_000){
    throw fail('CONFIG','Invalid agent HTTPS identity or service token');
  }
  if(identity.legacyDeviceBinding){
    throw fail('CONFIG','Legacy device binding lacks durable Owner machine-binding evidence; migrate it first');
  }
  if(identity.deviceBinding&&(
     identity.deviceBinding.deviceId!==deviceId||identity.deviceBinding.clientId!==clientId||
     identity.deviceBinding.fingerprint!==identity.fingerprint)){
    throw fail('CONFIG','HTTPS client identity differs from its durable approval binding');
  }
  let sessionId=null,sequence=0,closed=false,permanentlyClosed=false;
  let gatewayClockOffsetMs=0;
  const gatewayNowMs=()=>Date.now()+gatewayClockOffsetMs;
  function ambiguousResponse(){
    // A route may have consumed a challenge, advanced a frame sequence, or
    // accepted a result before the response became unusable. Fence this client.
    closed=true;sessionId=null;sequence=0;
    throw fail('AMBIGUOUS_TRANSPORT','Agent response invalid; request outcome unknown');
  }
  async function request(route,data,authenticate=false,signal){
    if(closed)throw fail('CLOSED','Agent client closed');
    if(!ROUTES.has(route))throw fail('CONFIG','Unknown agent route');
    const body=JSON.stringify(data);
    if(typeof body!=='string'||Buffer.byteLength(body,'utf8')>MAX_BYTES){
      throw fail('BAD_PAYLOAD','Agent message exceeds approved limit');
    }
    const headers={
      'content-type':'application/json','accept':'application/json',
      'cf-access-client-id':clientId,'cf-access-client-secret':clientSecret,
    };
    if(authenticate){
      if(!sessionId)throw fail('NOT_CONNECTED','Agent session missing');
      sequence++;
      const message=signedAgentRequest({
        method:'POST',pathname:route,deviceId,sessionId,sequence,bodyText:body,
      });
      headers['x-vpsc-device-id']=deviceId;
      headers['x-vpsc-session-id']=sessionId;
      headers['x-vpsc-sequence']=String(sequence);
      headers['x-vpsc-signature']=identity.signFrame(message);
    }
    let response;
    try{
      const requestSignal=signal?AbortSignal.any([signal,AbortSignal.timeout(timeoutMs)]):AbortSignal.timeout(timeoutMs);
      response=await fetchFn(origin+route,{
        method:'POST',headers,body,redirect:'error',
        cache:'no-store',credentials:'omit',signal:requestSignal,
      });
    }catch{
      // Once the network request started, never assume the operation was not
      // delivered. No implicit replay after an uncertain outcome.
      closed=true;sessionId=null;sequence=0;
      throw fail('AMBIGUOUS_TRANSPORT','Agent transport failed; do not retry blindly');
    }
    if(!response||typeof response.status!=='number'||
       !response.headers?.get?.('content-type')?.toLowerCase().includes('application/json')){
      return ambiguousResponse();
    }
    if(!response.ok){
      if(response.status>=400&&response.status<500){
        throw fail('REJECTED','Agent ingress denied request: '+response.status);
      }
      return ambiguousResponse();
    }
    // Trust Gateway time only after the configured HTTPS fetch verifies its certificate.
    const gatewayDate=Date.parse(response.headers.get('date')??'');
    const clockOffset=Number.isFinite(gatewayDate)?gatewayDate-Date.now():NaN;
    if(Number.isFinite(clockOffset)&&Math.abs(clockOffset)<=MAX_CLOCK_OFFSET_MS){
      gatewayClockOffsetMs=clockOffset;
    }
    let total=0;const chunks=[];
    try{
      for await(const chunk of response.body){
        total+=chunk.length;
        if(total>MAX_RESPONSE)throw Error('Response exceeds limit');
        chunks.push(chunk);
      }
      const decoded=new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks,total));
      const parsed=JSON.parse(decoded);
      if(!parsed||typeof parsed!=='object'||Array.isArray(parsed)){
        throw Error('Invalid JSON response');
      }
      return parsed;
    }catch{return ambiguousResponse();}
  }
  async function connect({signal}={}){
    if(sessionId)throw fail('STATE','Already connected');
    const challenge=await request('/agent/challenge',{deviceId},false,signal);
    if(!exactKeys(challenge,'deviceId,expiresInMs,nonce')||challenge.deviceId!==deviceId||
       !NONCE.test(challenge.nonce)||!Number.isSafeInteger(challenge.expiresInMs)||
       challenge.expiresInMs<1||challenge.expiresInMs>60_000)return ambiguousResponse();
    const proof=identity.proveDeviceChallenge(challenge);
    const current=await request('/agent/connect',{deviceId,signature:proof},false,signal);
    if(!exactKeys(current,'deviceId,sessionId')||current.deviceId!==deviceId||
       typeof current.sessionId!=='string'||!UUID.test(current.sessionId))return ambiguousResponse();
    sessionId=current.sessionId;sequence=0;
    return Object.freeze({deviceId,sessionId});
  }
  async function reconnect({signal}={}){
    if(permanentlyClosed||!closed||sessionId!==null)
      throw fail('STATE','Only an ambiguous open-client session can reconnect');
    closed=false;sequence=0;
    return connect({signal});
  }
  async function heartbeat({signal}={}){
    const answer=await request('/agent/heartbeat',{},true,signal);
    if(!exactKeys(answer,'deviceId,status')||answer.deviceId!==deviceId||answer.status!=='alive'){
      return ambiguousResponse();
    }
    return answer;
  }
  async function poll({signal}={}){
    const answer=await request('/agent/poll',{},true,signal);
    if(!exactKeys(answer,'frame')&& !exactKeys(answer,'cancel,frame'))return ambiguousResponse();
    if(!(answer.frame===null||
       answer.frame&&typeof answer.frame==='object'&&!Array.isArray(answer.frame))){
      return ambiguousResponse();
    }
    return answer.frame;
  }
  async function pollControl({signal}={}){
    const answer=await request('/agent/poll',{},true,signal);
    if(!exactKeys(answer,'frame')&&!exactKeys(answer,'cancel,frame'))return ambiguousResponse();
    if(!(answer.frame===null||answer.frame&&typeof answer.frame==='object'&&!Array.isArray(answer.frame))||
       !(answer.cancel===undefined||answer.cancel===null||
         answer.cancel&&typeof answer.cancel==='object'&&!Array.isArray(answer.cancel))){
      return ambiguousResponse();
    }
    if(answer.cancel!==undefined&&answer.cancel!==null&&
       (!exactKeys(answer.cancel,'deviceId,ownerDigest,requestId,sessionId,type,version')||
        answer.cancel.version!==1||answer.cancel.type!=='cancel'||
        answer.cancel.deviceId!==deviceId||answer.cancel.sessionId!==sessionId||
        !UUID.test(answer.cancel.requestId??'')||!/^[a-f0-9]{64}$/.test(answer.cancel.ownerDigest??''))){
      return ambiguousResponse();
    }
    return Object.freeze({frame:answer.frame,cancel:answer.cancel??null});
  }
  async function disconnect(){
    if(!sessionId)return Object.freeze({disconnected:false});
    try{
      const result=await request('/agent/disconnect',{},true);
      if(!exactKeys(result,'disconnected')||result.disconnected!==true)return ambiguousResponse();
      sessionId=null;sequence=0;
      return Object.freeze({disconnected:true});
    }catch(error){
      // The disconnect may have reached the Gateway even if its response was
      // lost. Do not reuse this session or retry the uncertain request.
      sessionId=null;closed=true;
      throw error;
    }
  }
  const result=async(requestId,value,{signal}={})=>{
    if(typeof requestId!=='string'||!UUID.test(requestId)){
      throw fail('BAD_PAYLOAD','Invalid remote request id');
    }
    const answer=await request('/agent/result',{requestId,result:value},true,signal);
    if(!exactKeys(answer,'accepted')||answer.accepted!==true)return ambiguousResponse();
    return answer;
  };
  async function cancelAck({requestId,ownerDigest,status,signal}={}){
    if(typeof requestId!=='string'||!UUID.test(requestId)||
       !/^[a-f0-9]{64}$/.test(ownerDigest??'')||
       !['cancelled','completed','ambiguous'].includes(status)){
      throw fail('BAD_PAYLOAD','Invalid cancellation acknowledgement');
    }
    const answer=await request('/agent/cancel-ack',{requestId,ownerDigest,status},true,signal);
    if(!exactKeys(answer,'accepted,status')||answer.accepted!==true||
       answer.status!==status&&answer.status!=='ambiguous'){
      return ambiguousResponse();
    }
    return answer;
  }
  function close(){permanentlyClosed=true;closed=true;sessionId=null;sequence=0;}
  return Object.freeze({connect,reconnect,heartbeat,poll,pollControl,result,cancelAck,disconnect,close,gatewayNowMs});
}
