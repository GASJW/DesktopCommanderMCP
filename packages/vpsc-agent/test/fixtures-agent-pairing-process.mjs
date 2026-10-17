import { createInterface } from 'node:readline';
import { loadOrCreateDeviceIdentity } from '../src/identity-store.mjs';

const identity=loadOrCreateDeviceIdentity({directory:process.env.VPSC_TEST_IDENTITY_DIR});
process.stdout.write(JSON.stringify({kind:'identity',publicKeyPem:identity.publicKeyPem,
  fingerprint:identity.fingerprint})+'\n');
for await(const line of createInterface({input:process.stdin,crlfDelay:Infinity})){
  let message;
  try{message=JSON.parse(line);}catch{continue;}
  if(message?.kind!=='prove')continue;
  try{
    const proof=identity.prove(message.challenge);
    process.stdout.write(JSON.stringify({kind:'proof',proof})+'\n');
  }catch{
    process.stdout.write(JSON.stringify({kind:'proof-error'})+'\n');
  }
}
