import { loadOrCreateDeviceIdentity } from '../src/identity-store.mjs';
const identity=loadOrCreateDeviceIdentity({directory:process.env.VPSC_TEST_IDENTITY_DIR});
process.stdout.write(JSON.stringify({fingerprint:identity.fingerprint,
  deviceBinding:identity.deviceBinding})+'\n');
