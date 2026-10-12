import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync,sign } from 'node:crypto';
import { createMachineAccessVerifier } from '../devices/machine-access.mjs';

const issuer='https://vpsc.cloudflareaccess.com';
const audience='a'.repeat(64), nowMs=1_800_000_000_000;
const nowSec=Math.floor(nowMs/1000);
const clientId='agent-one.example.access';
const alternative='agent-two.example.access';
function makeKeys(){
  const {publicKey,privateKey}=generateKeyPairSync('rsa',{modulusLength:2048});
  return {privateKey,jwk:{...publicKey.export({format:'jwk'}),kid:'test-kid',alg:'RS256'}};
}
function token(k,claim={},head={}){
  const header={alg:'RS256',kid:'test-kid',typ:'JWT',...head};
  const claims={type:'app',sub:'',common_name:clientId,iss:issuer,aud:audience,
    iat:nowSec-10,exp:nowSec+3600,...claim};
  const a=Buffer.from(JSON.stringify(header)).toString('base64url');
  const b=Buffer.from(JSON.stringify(claims)).toString('base64url');
  const c=sign('RSA-SHA256',Buffer.from(a+'.'+b),k.privateKey).toString('base64url');
  return [a,b,c].join('.');
}
function fixture(extra={}){
  const keys=makeKeys();
  let reads=0;
  const verify=createMachineAccessVerifier({issuer,audience,now:()=>nowMs,
    allowedClientIds:[clientId],keyProvider:async()=>{reads++;return {keys:[keys.jwk]};},
    ...extra,
  });
  return {keys,verify,reads:()=>reads};
}
test('valid RS256 Cloudflare Service Token JWT yields approved Client ID',async()=>{
  const {keys,verify}=fixture();
  assert.deepEqual(await verify(token(keys)),{clientId});
});
test('separate user identity and Access app JWT cannot authenticate as service',async()=>{
  const {keys,verify}=fixture();
  for(const override of [{sub:'person-123'},{type:'org'},{sub:'',common_name:'not-approved'},
    {sub:'person-123',email:'owner@example.com'},{common_name:alternative}]){
    assert.equal(await verify(token(keys,override)),null);
  }
});
test('wrong audience issuer, expiration and excessively long lifetime fail closed',async()=>{
  const {keys,verify}=fixture();
  for(const override of [
    {aud:'b'.repeat(64)},{iss:'https://evil.cloudflareaccess.com'},
    {exp:nowSec-40},{iat:nowSec+60},{iat:nowSec-1,exp:nowSec+100_000},
    {nbf:nowSec+60},{nbf:nowSec+4000,exp:nowSec+3600},
    {exp:'fake'}, {iat:null}
  ]) assert.equal(await verify(token(keys,override)),null);
});
test('wrong client token scope cannot access another device',async()=>{
  const {keys,verify}=fixture();
  assert.equal(await verify(token(keys,{common_name:alternative})),null);
  const multi=fixture({allowedClientIds:[alternative,clientId]});
  assert.deepEqual(await multi.verify(token(multi.keys,{common_name:alternative})),
    {clientId:alternative});
});
test('tampered JWT header, body and signature are rejected',async()=>{
  const {keys,verify}=fixture();
  const valid=token(keys);
  const [h,p,s]=valid.split('.');
  const changed=Buffer.from(JSON.stringify({type:'app',sub:'',common_name:alternative,iss:issuer,
    aud:audience,iat:nowSec,exp:nowSec+100})).toString('base64url');
  assert.equal(await verify([h,changed,s].join('.')),null);
  assert.equal(await verify([h,p,s.slice(1)+'A'].join('.')),null);
  assert.equal(await verify(token(keys,{}, {alg:'none'})),null);
  assert.equal(await verify(token(keys,{}, {alg:'HS256'})),null);
  assert.equal(await verify(token(keys,{}, {kid:'unknown'})),null);
});
test('bad or malformed JWT never throws or returns a principal',async()=>{
  const {verify}=fixture();
  for(const v of [null,undefined,'','abc','a.b.c','x'.repeat(17000),
    'e30.e30.e30','foo.bar.baz',{},true,'@@.@@.@@']){
    assert.equal(await verify(v),null);
  }
});
test('wrong RSA signing key cannot impersonate allowed machine',async()=>{
  const {verify}=fixture();
  const other=makeKeys();
  assert.equal(await verify(token(other)),null);
});
test('invalid policy and duplicate client identifiers fail closed',()=>{
  const k=makeKeys();
  for(const override of [{allowedClientIds:[]},{allowedClientIds:[clientId,clientId]},
    {allowedClientIds:['x']},{issuer:'http://vpsc.cloudflareaccess.com'},
    {audience:'invalid'},{keyProvider:3}]){
    assert.throws(()=>createMachineAccessVerifier({issuer,audience,
      allowedClientIds:[clientId],keyProvider:async()=>({keys:[k.jwk]}),
      ...override}),/policy|Duplicate/);
  }
});
test('untrusted or unavailable key provider results deny access',async()=>{
  const keys=makeKeys();
  const verify=createMachineAccessVerifier({
    issuer,audience,allowedClientIds:[clientId],now:()=>nowMs,
    keyProvider:async()=>({keys:[]})
  });
  assert.equal(await verify(token(keys)),null);
  const fails=createMachineAccessVerifier({
    issuer,audience,allowedClientIds:[clientId],now:()=>nowMs,
    keyProvider:async()=>{throw Error('network down')}
  });
  assert.equal(await fails(token(keys)),null);
});
test('signing key cache refreshes unknown KID with same trusted issuer',async()=>{
  const keys=makeKeys();
  const jwk1={...keys.jwk,kid:'first'};
  let count=0;
  const verify=createMachineAccessVerifier({issuer,audience,allowedClientIds:[clientId],
    now:()=>nowMs,keyProvider:async()=>{count++;return {keys:[count===1?jwk1:keys.jwk]};}});
  assert.deepEqual(await verify(token(keys)),{clientId});
  assert.equal(count,2);
});
test('JWK that is not RSA or has unsafe algorithm is not accepted',async()=>{
  const keys=makeKeys();
  const verify=createMachineAccessVerifier({issuer,audience,allowedClientIds:[clientId],
    now:()=>nowMs,keyProvider:async()=>({keys:[{...keys.jwk,alg:'HS256'}]})});
  assert.equal(await verify(token(keys)),null);
});
