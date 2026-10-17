import { createHash } from 'node:crypto';

function validOwner(value){
  return value&&typeof value.issuer==='string'&&
    /^https:\/\/[a-z0-9-]+\.cloudflareaccess\.com$/.test(value.issuer)&&
    typeof value.subject==='string'&&value.subject.length>0&&value.subject.length<=1024;
}
const sha256=value=>createHash('sha256').update(value).digest('hex');

// Persist only stable, non-reversible owner references in policy records.
export function ownerPrincipalId(owner){
  if(!validOwner(owner))throw new TypeError('Verified owner principal required');
  return sha256(owner.issuer+'\0'+owner.subject).slice(0,24);
}
export function ownerIdentityDigest(owner){
  if(!validOwner(owner))throw new TypeError('Verified owner principal required');
  return sha256('VPSC-I4-OWNER-v1\n'+JSON.stringify([owner.issuer,owner.subject]));
}
export function isOwnerPrincipal(owner){return validOwner(owner);}
