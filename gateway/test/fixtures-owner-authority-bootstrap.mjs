import { createAuth0OwnerVerifier } from '../owner/auth0-owner-auth.mjs';
import { createDurableOwnerAuthority } from '../owner/durable-owner-authority.mjs';

const fixture = JSON.parse(process.env.G7_I8F_BOOTSTRAP_FIXTURE);
const verifier = createAuth0OwnerVerifier(fixture.verifierConfig, { now: () => fixture.now });
const authority = createDurableOwnerAuthority({ directory: fixture.directory,
  realmId: fixture.realmId, issuer: fixture.verifierConfig.issuer, verifier,
  approvalJwks: fixture.approvalJwks, now: () => fixture.now });
try {
  const state = authority.bootstrap({ accessToken: fixture.accessToken, approval: fixture.approval });
  process.stdout.write(JSON.stringify({ status: state.status, revision: state.revision }) + '\n');
} catch (error) {
  process.stderr.write(JSON.stringify({ code: error?.code ?? 'BOOTSTRAP_FAILED' }) + '\n');
  process.exitCode = 2;
}
