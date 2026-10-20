import { createHash } from 'node:crypto';
import { auth0OwnerIdentityDigest, auth0OwnerPrincipalId, isAuth0OwnerPrincipal }
  from '../owner/auth0-owner-auth.mjs';

export const STAGING_OWNER_ISSUER='https://g7-owner-staging.cloudflareaccess.com';

function validOwner(value){
  return value&&typeof value.issuer==='string'&&
    /^https:\/\/[a-z0-9-]+\.cloudflareaccess\.com$/.test(value.issuer)&&
    typeof value.subject==='string'&&value.subject.length>0&&value.subject.length<=1024;
}
const sha256=value=>createHash('sha256').update(value).digest('hex');

// Persist only stable, non-reversible owner references in policy records.
export function ownerPrincipalId(owner){
  if(isAuth0OwnerPrincipal(owner))return auth0OwnerPrincipalId(owner);
  if(!validOwner(owner))throw new TypeError('Verified owner principal required');
  return sha256(owner.issuer+'\0'+owner.subject).slice(0,24);
}
export function ownerIdentityDigest(owner){
  if(isAuth0OwnerPrincipal(owner))return auth0OwnerIdentityDigest(owner);
  if(!validOwner(owner))throw new TypeError('Verified owner principal required');
  return sha256('VPSC-I4-OWNER-v1\n'+JSON.stringify([owner.issuer,owner.subject]));
}
export function isOwnerPrincipal(owner){return validOwner(owner)||isAuth0OwnerPrincipal(owner);}
export function isSyntheticStagingOwner(owner){return owner?.issuer===STAGING_OWNER_ISSUER;}
