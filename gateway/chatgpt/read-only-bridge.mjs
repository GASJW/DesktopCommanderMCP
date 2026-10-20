import { createHash, createPublicKey, verify as verifySignature } from 'node:crypto';
import { ownerIdentityDigest } from '../dashboard/owner-identity.mjs';
import { createRemoteDeviceMcpHandler } from '../devices/remote-mcp-handler.mjs';

export const CHATGPT_MCP_ROUTE='/chatgpt/mcp';
export const CHATGPT_RESOURCE_METADATA_PATH='/.well-known/oauth-protected-resource';
const SCOPE='g7.read';
const CLOCK_SKEW_SECONDS=30;
const MAX_ACCESS_TOKEN_SECONDS=3600;
const PRIVATE_JWK_MEMBERS=new Set(['d','p','q','dp','dq','qi','oth']);

function exact(value,keys){
  return value&&typeof value==='object'&&!Array.isArray(value)&&
    Object.getPrototypeOf(value)===Object.prototype&&Object.keys(value).sort().join(',')===keys;
}

function httpsUrl(value){
  if(typeof value!=='string'||value.length>2048)return false;
  try{
    const url=new URL(value);
    return url.protocol==='https:'&&!url.username&&!url.password&&!url.search&&!url.hash;
  }catch{return false;}
}

export function validateChatGptBridgeConfig(config,owner){
  if(!exact(config,'clientIds,issuer,jwks,principalMapping,resource,resourceMetadataUrl')||
     !httpsUrl(config.issuer)||!httpsUrl(config.resource)||!httpsUrl(config.resourceMetadataUrl)||
     new URL(config.resourceMetadataUrl).pathname!==CHATGPT_RESOURCE_METADATA_PATH||
     !exact(config.principalMapping,'ownerIssuer,ownerSubject,subject')||
     config.principalMapping.ownerIssuer!==owner?.issuer||
     config.principalMapping.ownerSubject!==owner?.subject||
     typeof config.principalMapping.subject!=='string'||!config.principalMapping.subject||
     config.principalMapping.subject.length>1024||/[\0\r\n]/.test(config.principalMapping.subject)||
     !Array.isArray(config.clientIds)||config.clientIds.length<1||config.clientIds.length>16||
     config.clientIds.some(id=>typeof id!=='string'||id.length<1||id.length>256||/[\s\0]/.test(id))||
     new Set(config.clientIds).size!==config.clientIds.length||
     !Array.isArray(config.jwks)||config.jwks.length<1||config.jwks.length>32){
    throw new Error('Invalid ChatGPT read-only bridge OAuth configuration');
  }
  const keys=new Map();
  for(const jwk of config.jwks){
    if(!jwk||jwk.kty!=='RSA'||jwk.alg!=='RS256'||jwk.use&&jwk.use!=='sig'||
       typeof jwk.kid!=='string'||!jwk.kid||jwk.kid.length>256||/[\0\r\n]/.test(jwk.kid)||
       typeof jwk.n!=='string'||jwk.n.length>4096||typeof jwk.e!=='string'||jwk.e.length>32||
       [...PRIVATE_JWK_MEMBERS].some(member=>Object.hasOwn(jwk,member))||keys.has(jwk.kid)){
      throw new Error('ChatGPT bridge JWKS must contain unique public RS256 keys');
    }
    let publicKey;
    try{publicKey=createPublicKey({key:jwk,format:'jwk'});}catch{
      throw new Error('Invalid ChatGPT bridge public key');
    }
    if(publicKey.asymmetricKeyType!=='rsa'||
       (publicKey.asymmetricKeyDetails?.modulusLength??0)<2048){
      throw new Error('ChatGPT bridge RSA keys must be at least 2048 bits');
    }
    keys.set(jwk.kid,publicKey);
  }
  return {keys,clientIds:new Set(config.clientIds)};
}

function decodeJson(segment){
  if(typeof segment!=='string'||!segment||!/^[A-Za-z0-9_-]+$/.test(segment)||segment.length>16384)
    throw new Error('Invalid JWT segment');
  const bytes=Buffer.from(segment,'base64url');
  if(bytes.toString('base64url')!==segment)throw new Error('Invalid JWT encoding');
  return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
}

function audienceMatches(aud,resource){
  return aud===resource||Array.isArray(aud)&&aud.includes(resource)&&aud.every(value=>typeof value==='string');
}

function tokenClientMatches(payload,clientIds){
  const clientId=payload.client_id??payload.azp;
  return typeof clientId==='string'&&clientIds.has(clientId)&&
    (payload.client_id===undefined||payload.client_id===clientId)&&
    (payload.azp===undefined||payload.azp===clientId);
}

function validAccessToken(token,config,{keys,clientIds}){
  if(typeof token!=='string'||token.length<30||token.length>16*1024)return null;
  const segments=token.split('.');
  if(segments.length!==3)return null;
  try{
    const [encodedHeader,encodedPayload,encodedSignature]=segments;
    const header=decodeJson(encodedHeader),payload=decodeJson(encodedPayload);
    if(!header||Object.getPrototypeOf(header)!==Object.prototype||
       Object.keys(header).some(name=>!['alg','kid','typ'].includes(name))||
       header.alg!=='RS256'||typeof header.kid!=='string'||
       !['at+jwt','jwt'].includes(String(header.typ??'').toLowerCase())||
       !payload||Object.getPrototypeOf(payload)!==Object.prototype)return null;
    const key=keys.get(header.kid);
    if(!key)return null;
    const now=Math.floor(Date.now()/1000);
    if(payload.iss!==config.issuer||!audienceMatches(payload.aud,config.resource)||
       typeof payload.sub!=='string'||payload.sub!==config.principalMapping.subject||
       !Number.isSafeInteger(payload.exp)||payload.exp<=now||
       !Number.isSafeInteger(payload.iat)||payload.iat>now+CLOCK_SKEW_SECONDS||
       payload.exp<=payload.iat||payload.exp-payload.iat>MAX_ACCESS_TOKEN_SECONDS||
       payload.nbf!==undefined&&(!Number.isSafeInteger(payload.nbf)||payload.nbf>now+CLOCK_SKEW_SECONDS)||
       typeof payload.scope!=='string'||!payload.scope.split(/\s+/).includes(SCOPE)||
       !tokenClientMatches(payload,clientIds))return null;
    const signature=Buffer.from(encodedSignature,'base64url');
    if(!signature.length||signature.toString('base64url')!==encodedSignature||
       !verifySignature('RSA-SHA256',Buffer.from(`${encodedHeader}.${encodedPayload}`),key,signature))return null;
    return Object.freeze({issuer:config.principalMapping.ownerIssuer,
      subject:config.principalMapping.ownerSubject});
  }catch{return null;}
}

function bearerToken(req){
  const value=req.headers.authorization;
  if(typeof value!=='string')return null;
  const match=/^Bearer ([^\s,]+)$/i.exec(value);
  return match?.[1]??null;
}

function canonicalJson(value){
  if(Array.isArray(value))return `[${value.map(canonicalJson).join(',')}]`;
  if(value&&typeof value==='object')return `{${Object.keys(value).sort()
    .map(key=>`${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}

// shortcut: identical RPC ID/payload within one conversation is ambiguous; use a fresh ID for every new invocation.
function stableRequestId({owner,message,deviceId,name,arguments:args}){
  const session=message.params?._meta?.['openai/session'];
  if(typeof session!=='string'||session.length===0||Buffer.byteLength(session,'utf8')>1024||
     /[\u0000-\u001f\u007f]/.test(session))throw new Error('ChatGPT conversation identity unavailable');
  const digest=createHash('sha256').update('VPSC-I8A-REQUEST-v2\n').update(canonicalJson([
    ownerIdentityDigest(owner),session,message.id,deviceId,name,args,
  ])).digest('hex').slice(0,32).split('');
  digest[12]='4';
  digest[16]=(parseInt(digest[16],16)&3|8).toString(16);
  const hex=digest.join('');
  return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
}

function authChallenge(config){
  return `Bearer resource_metadata="${config.resourceMetadataUrl}", scope="${SCOPE}", error="invalid_token", error_description="A valid G7 Owner authorization is required"`;
}

function sendJson(res,status,body,headers={}){
  if(res.destroyed||res.writableEnded)return;
  res.writeHead(status,{'content-type':'application/json; charset=utf-8','cache-control':'no-store',
    'x-content-type-options':'nosniff',...headers});
  res.end(JSON.stringify(body));
}

export function createChatGptReadOnlyBridge({oauth,owner,...gateway}={}){
  const {keys,clientIds}=validateChatGptBridgeConfig(oauth,owner);
  const resolveOwner=async req=>validAccessToken(bearerToken(req),oauth,{keys,clientIds});
  const challenge=authChallenge(oauth);
  const mcpHandler=createRemoteDeviceMcpHandler({...gateway,resolveOwner,
    route:CHATGPT_MCP_ROUTE,allowedTools:['read_file'],
    supportedProtocolVersions:['2025-11-25','2025-06-18','2025-03-26'],
    requireStreamableAccept:true,validateProtocolVersionHeader:true,
    unauthenticatedMethods:['initialize','tools/list','notifications/initialized'],
    toolMetadata:{read_file:{securitySchemes:[{type:'oauth2',scopes:[SCOPE]}],
      annotations:{readOnlyHint:true,destructiveHint:false,openWorldHint:false}}},
    requestIdFactory:stableRequestId,
    onAuthenticationRequired(_req,res,message){
      if(message.method==='tools/call'){
        sendJson(res,200,{jsonrpc:'2.0',id:message.id,result:{isError:true,
          content:[{type:'text',text:'Owner authorization is required.'}],
          _meta:{'mcp/www_authenticate':[challenge]}}});
      }else sendJson(res,401,{jsonrpc:'2.0',id:message.id??null,
        error:{code:-32001,message:'Owner authentication required'}},{'www-authenticate':challenge});
      return true;
    },
  });
  const metadata=Object.freeze({resource:oauth.resource,authorization_servers:[oauth.issuer],
    scopes_supported:[SCOPE],bearer_methods_supported:['header']});
  return async function handleChatGptReadOnlyBridge(req,res){
    if(req.url===CHATGPT_RESOURCE_METADATA_PATH){
      if(req.method!=='GET')return sendJson(res,405,{error:'Method not allowed'});
      if(req.headers.origin)return sendJson(res,403,{error:'Browser origin denied'});
      return sendJson(res,200,metadata);
    }
    return mcpHandler(req,res);
  };
}
