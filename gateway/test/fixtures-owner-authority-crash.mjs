import { createAuth0OwnerVerifier } from '../owner/auth0-owner-auth.mjs';
import { createDurableOwnerAuthority } from '../owner/durable-owner-authority.mjs';

const fixture = JSON.parse(process.env.G7_I8F_CRASH_FIXTURE);
const verifier = createAuth0OwnerVerifier(fixture.verifierConfig, { now: () => fixture.now });
const authority = createDurableOwnerAuthority({ ...fixture.authorityConfig,
  directory: fixture.directory, realmId: fixture.realmId, issuer: fixture.verifierConfig.issuer,
  verifier, now: () => fixture.now,
  testHooks: { afterDurableWrite(stage) {
    if (stage === fixture.stage) process.exit(73);
  } },
});
authority.bootstrap({ accessToken: fixture.accessToken, approval: fixture.approval });
process.exit(74);
