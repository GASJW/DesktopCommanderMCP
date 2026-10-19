# G7 I7 Windows agent patch 1

This patch is additive to the frozen I7 RC1 source. It does not replace or modify the I7 RC1 artifact or the active Gateway release.

The Windows capability verifier maps the Gateway's canonical POSIX grant scope onto the configured Windows drive root and rejects mixed path namespaces and escapes. The HTTPS agent estimates Gateway time from the Date header of successful responses received through its TLS-verified transport. It accepts offsets up to five minutes; missing or larger offsets do not relax capability signature, scope, or expiry checks, so an unsynchronized clock fails closed.

## Rollout

Keep the active I7 Gateway, trust, bindings, grants, audit, and Linux agent in place. Read the active Gateway policy public key through the authorized staging procedure and set only policyPublicKeyPem in the private Windows agent.json. Keep the existing Windows M2M secret, DPAPI-protected identity, Owner binding receipt, and execution ledger. Start the Windows worker manually through the loopback SSH tunnel; do not create a Windows service or scheduled task.

## Recovery

If the Windows worker fails, stop or restart only that worker. Preserve its DPAPI identity, Owner binding receipt, and ledger. Check analyzeI4ExecutionRecovery before resubmitting any operation after an ambiguous transport result. Do not roll the Gateway back to I5F after the Windows binding exists; the additive Windows device requires the multi-device I7 Gateway.