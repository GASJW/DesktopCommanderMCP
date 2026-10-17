import path from 'node:path';
import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';

const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const DIGEST=/^[a-f0-9]{64}$/;
const TOOLS=new Set(['read_file','list_directory','write_file','list_processes','run_command']);
const CLAIM_KEYS=['approvalEventId','approvalTrustRevisionAfter','approvalTrustRevisionBefore',
  'argumentsDigest','constraints','decisionId','deviceId','expiresAt','fingerprint','grantId','issuedAt',
  'ownerDigest','policyRevision','requestId','scope','tool','trustRevision','version'];

const fail=message=>Object.assign(new Error(message),{code:'INVALID_GRANT_CAPABILITY'});
const sameKeys=(value,expected)=>value&&typeof value==='object'&&!Array.isArray(value)&&
  Object.getPrototypeOf(value)===Object.prototype&&
  Object.keys(value).sort().join(',')===[...expected].sort().join(',');

export function canonicalJson(value){
  if(value===null||typeof value==='string'||typeof value==='boolean')return JSON.stringify(value);
  if(typeof value==='number'&&Number.isFinite(value))return JSON.stringify(value);
  if(Array.isArray(value))return '['+value.map(canonicalJson).join(',')+']';
  if(value&&typeof value==='object'&&Object.getPrototypeOf(value)===Object.prototype){
    return '{'+Object.keys(value).sort().map(key=>JSON.stringify(key)+':'+canonicalJson(value[key])).join(',')+'}';
  }
  throw fail('Capability data is not canonical JSON');
}
export function toolArgumentsDigest(tool,arguments_){
  return createHash('sha256').update(canonicalJson({tool,arguments:arguments_})).digest('hex');
}

function validScopeAndConstraints(tool,scope,constraints){
  if(tool==='list_processes')return sameKeys(scope,[])&&
    sameKeys(constraints,['maxJobs'])&&Number.isSafeInteger(constraints.maxJobs)&&
    constraints.maxJobs>=1&&constraints.maxJobs<=32;
  const hasRoot=scope&&typeof scope.root==='string'&&path.isAbsolute(scope.root)&&
    path.normalize(scope.root)===scope.root&&!scope.root.includes('\0')&&scope.root.length<=4096;
  if(!hasRoot)return false;
  if(tool==='read_file')return sameKeys(scope,['root'])&&
    sameKeys(constraints,['maxBytes','maxLength','maxOffset'])&&
    Number.isSafeInteger(constraints.maxBytes)&&constraints.maxBytes>=1&&
    constraints.maxBytes<=64*1024&&Number.isSafeInteger(constraints.maxLength)&&
    constraints.maxLength>=1&&constraints.maxLength<=1000&&
    Number.isSafeInteger(constraints.maxOffset)&&constraints.maxOffset>=0&&constraints.maxOffset<=100000;
  if(tool==='list_directory')return sameKeys(scope,['root'])&&
    sameKeys(constraints,['maxDepth','maxEntries'])&&Number.isSafeInteger(constraints.maxDepth)&&
    constraints.maxDepth>=0&&constraints.maxDepth<=2&&Number.isSafeInteger(constraints.maxEntries)&&
    constraints.maxEntries>=1&&constraints.maxEntries<=200;
  if(tool==='write_file')return sameKeys(scope,['root'])&&
    sameKeys(constraints,['maxBytes'])&&Number.isSafeInteger(constraints.maxBytes)&&
    constraints.maxBytes>=1&&constraints.maxBytes<=64*1024;
  if(tool==='run_command')return sameKeys(scope,['profile','root'])&&scope.profile==='count_lines'&&
    sameKeys(constraints,['maxOutputBytes','maxRuntimeMs','profile'])&&constraints.profile==='count_lines'&&
    Number.isSafeInteger(constraints.maxOutputBytes)&&constraints.maxOutputBytes>=1024&&
    constraints.maxOutputBytes<=16*1024&&Number.isSafeInteger(constraints.maxRuntimeMs)&&
    constraints.maxRuntimeMs>=100&&constraints.maxRuntimeMs<=10_000;
  return false;
}

function validClaims(claims){
  return sameKeys(claims,CLAIM_KEYS)&&claims.version===1&&UUID.test(claims.grantId??'')&&
    UUID.test(claims.decisionId??'')&&UUID.test(claims.requestId??'')&&
    UUID.test(claims.deviceId??'')&&UUID.test(claims.approvalEventId??'')&&
    DIGEST.test(claims.ownerDigest??'')&&DIGEST.test(claims.fingerprint??'')&&
    DIGEST.test(claims.argumentsDigest??'')&&TOOLS.has(claims.tool)&&
    Number.isSafeInteger(claims.policyRevision)&&claims.policyRevision>=1&&
    Number.isSafeInteger(claims.approvalTrustRevisionBefore)&&claims.approvalTrustRevisionBefore>=0&&
    Number.isSafeInteger(claims.approvalTrustRevisionAfter)&&
    claims.approvalTrustRevisionAfter===claims.approvalTrustRevisionBefore+1&&
    Number.isSafeInteger(claims.trustRevision)&&claims.trustRevision>=claims.approvalTrustRevisionAfter&&
    Number.isSafeInteger(claims.issuedAt)&&Number.isSafeInteger(claims.expiresAt)&&
    claims.expiresAt>claims.issuedAt&&claims.expiresAt-claims.issuedAt<=60_000&&
    validScopeAndConstraints(claims.tool,claims.scope,claims.constraints);
}

function privateKeyObject(key){
  try{const result=key?.type==='private'?key:createPrivateKey(key);
    if(result.asymmetricKeyType!=='ed25519')throw Error();return result;
  }catch{throw fail('An Ed25519 Gateway policy signing key is required');}
}
function publicKeyObject(key){
  try{const result=key?.type==='public'?key:createPublicKey(key);
    if(result.asymmetricKeyType!=='ed25519')throw Error();return result;
  }catch{throw fail('A pinned Ed25519 Gateway policy public key is required');}
}

export function signToolGrantCapability(claims,privateKey){
  if(!validClaims(claims))throw fail('Capability claims are invalid');
  const payload=Buffer.from(canonicalJson(claims));
  const signature=sign(null,payload,privateKeyObject(privateKey)).toString('base64url');
  return Object.freeze({version:1,claims:Object.freeze({...claims}),signature});
}

function inside(root,target,{allowRoot=false}={}){
  const relative=path.relative(root,target);
  return (allowRoot&&relative==='')||relative!==''&&relative!=='..'&&
    !relative.startsWith('..'+path.sep)&&!path.isAbsolute(relative);
}
function pathAllowed(root,filename,{allowRoot=false}={}){
  if(typeof filename!=='string'||!path.isAbsolute(filename)||filename.length>4096||filename.includes('\0'))return false;
  const absolute=path.resolve(filename);
  return inside(root,absolute,{allowRoot});
}
function argumentsWithinGrant(claims,args){
  if(!args||Object.getPrototypeOf(args)!==Object.prototype)return false;
  const {tool,scope,constraints}=claims;
  if(tool==='list_processes')return Object.keys(args).length===0;
  if(!pathAllowed(scope.root,args.path,{allowRoot:tool==='list_directory'||tool==='write_file'}))return false;
  if(tool==='read_file')return (args.length??1000)<=constraints.maxLength&&
    (args.offset??0)<=constraints.maxOffset;
  if(tool==='list_directory')return (args.depth===undefined?2:Number.isSafeInteger(args.depth)&&
    args.depth<=constraints.maxDepth);
  if(tool==='write_file')return args.mode==='create'&&typeof args.content==='string'&&
    Buffer.byteLength(args.content,'utf8')<=constraints.maxBytes;
  if(tool==='run_command')return args.profile===scope.profile;
  return false;
}

export function verifyToolGrantCapability(value,publicKey,{now=Date.now(),deviceId,requestId,
  fingerprint,tool,arguments:arguments_,allowedRoot}={}){
  if(!sameKeys(value,['claims','signature','version'])||value.version!==1||
     typeof value.signature!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(value.signature)||
     !validClaims(value.claims))throw fail('Capability envelope or claims are invalid');
  let validSignature=false;
  try{validSignature=verify(null,Buffer.from(canonicalJson(value.claims)),publicKeyObject(publicKey),
    Buffer.from(value.signature,'base64url'));}catch{}
  const claims=value.claims;
  if(!validSignature||!Number.isSafeInteger(now)||claims.issuedAt>now+5000||claims.expiresAt<=now){
    throw fail('Capability signature is invalid or the authorization is expired');
  }
  if(deviceId!==undefined&&claims.deviceId!==deviceId||requestId!==undefined&&claims.requestId!==requestId||
     fingerprint!==undefined&&claims.fingerprint!==fingerprint||tool!==undefined&&claims.tool!==tool||
     arguments_!==undefined&&claims.argumentsDigest!==toolArgumentsDigest(claims.tool,arguments_)){
    throw fail('Capability does not bind this device, request or operation');
  }
  if(!argumentsWithinGrant(claims,arguments_))throw fail('Operation arguments are outside the granted scope or constraints');
  if(typeof allowedRoot!=='string'||!path.isAbsolute(allowedRoot)||
     path.normalize(allowedRoot)!==allowedRoot||claims.tool!=='list_processes'&&
     !inside(path.resolve(allowedRoot),path.resolve(claims.scope.root),{allowRoot:true})){
    throw fail('Capability scope is outside the agent approved root');
  }
  return Object.freeze({...claims,scope:Object.freeze({...claims.scope}),
    constraints:Object.freeze({...claims.constraints})});
}
