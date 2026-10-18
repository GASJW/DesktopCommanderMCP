import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { Readable } from 'node:stream';
import { createMachineAccessVerifier } from '../devices/machine-access.mjs';
import { createAuthenticatedMachineIngress } from '../devices/persistent-machine-ingress.mjs';

const ISSUER='https://g7-machine-staging.cloudflareaccess.com';
const AUDIENCE='b'.repeat(64);
const CLIENT='g7-staging-agent.synthetic';
const DEVICE='123e4567-e89b-42d3-a456-426614174000';
const FINGERPRINT='a'.repeat(64);
const {privateKey,publicKey}=generateKeyPairSync('rsa',{modulusLength:2048});
const jwk={...publicKey.export({format:'jwk'}),kid:'staging-machine',alg:'RS256'};
const verifier=createMachineAccessVerifier({issuer:ISSUER,audience:AUDIENCE,
  allowedClientIds:[CLIENT],keyProvider:async()=>({keys:[jwk]})});
function machineJwt(clientId=CLIENT){
  const now=Math.floor(Date.now()/1000);
  const header=Buffer.from(JSON.stringify({alg:'RS256',kid:jwk.kid})).toString('base64url');
  const claims=Buffer.from(JSON.stringify({type:'app',sub:'',common_name:clientId,
    iss:ISSUER,aud:AUDIENCE,iat:now,exp:now+60})).toString('base64url');
  return `${header}.${claims}.${sign('RSA-SHA256',Buffer.from(`${header}.${claims}`),privateKey).toString('base64url')}`;
}
function fixture({bindingFingerprint=FINGERPRINT,trustedFingerprint=FINGERPRINT,revision=1}={}){
  const registry={
    snapshotTrustedDevices:()=>[{deviceId:DEVICE,fingerprint:trustedFingerprint}],
    beginHandshake:deviceId=>({deviceId,nonce:'fresh-single-use-challenge'}),
    acceptSignedFrame:()=>false,
  };
  const router={attachTransport(){},detachTransport(){},acceptCancellation(){return false;},
    rejectBeforeDelivery(){return false;}};
  const machineBindingStore={revision:()=>revision,
    resolve:clientId=>clientId===CLIENT?{clientId,deviceId:DEVICE,fingerprint:bindingFingerprint,
      bindingRevision:1,trustRevisionBefore:0,trustRevision:1,trustRevisionAfter:1}:null};
  const ingress=createAuthenticatedMachineIngress({registry,router,verifyMachineToken:verifier,
    machineBindingStore,getTrustRevision:()=>revision});
  return {ingress,registry,router};
}
async function request(ingress,{token=machineJwt(),deviceId=DEVICE}={}){
  const req=Readable.from([Buffer.from(JSON.stringify({deviceId}))]);
  req.url='/agent/challenge';req.method='POST';
  req.headers={'content-type':'application/json','cf-access-jwt-assertion':token};
  const res={status:null,headers:null,body:null,writableEnded:false,destroyed:false,
    writeHead(status,headers){this.status=status;this.headers=headers;},
    end(body){this.body=String(body);this.writableEnded=true;}};
  await ingress.handle(req,res);
  return {...res,json:JSON.parse(res.body)};
}

test('persistent machine ingress uses a direct handler and has no test listener URL',async()=>{
  const {ingress}=fixture();
  try{
    assert.equal(typeof ingress.handle,'function');
    assert.equal(Object.hasOwn(ingress,'url'),false);
    assert.equal(Object.hasOwn(ingress,'port'),false);
    const response=await request(ingress);
    assert.equal(response.status,200);
    assert.equal(response.json.nonce,'fresh-single-use-challenge');
  }finally{await ingress.close();}
});

test('persistent ingress requires a cryptographically valid M2M JWT',async()=>{
  const {ingress}=fixture();
  try{
    const response=await request(ingress,{token:'clientId='+CLIENT});
    assert.equal(response.status,401);
  }finally{await ingress.close();}
});

test('persistent ingress denies a durable Client-ID binding with a different fingerprint',async()=>{
  const {ingress}=fixture({bindingFingerprint:'c'.repeat(64),trustedFingerprint:FINGERPRINT});
  try{
    const response=await request(ingress);
    assert.equal(response.status,403);
    assert.match(response.json.error,/binding|trust/i);
  }finally{await ingress.close();}
});

test('persistent ingress refuses a map-only test binding',()=>{
  const {registry,router}=fixtureParts();
  assert.throws(()=>createAuthenticatedMachineIngress({registry,router,verifyMachineToken:verifier,
    machineBindingStore:new Map([[CLIENT,DEVICE]]),getTrustRevision:()=>1}),/durable/i);
});
function fixtureParts(){
  const registry={snapshotTrustedDevices:()=>[],beginHandshake(){},acceptSignedFrame(){}};
  const router={attachTransport(){},detachTransport(){},acceptCancellation(){},rejectBeforeDelivery(){}};
  return {registry,router};
}
