# Where the identity pieces live

Each row names the files that hold one piece of the identity records. The TypeScript package `node/probity-records-verify` carries the same contract where a twin is listed.

| Piece | Module | Python | TypeScript twin |
|---|---|---|---|
| Four-principal block, basic and strict profiles, token check against pinned JWKS | identity | `packages/probity-records/src/probity_records/identity.py` | `node/probity-records-verify/src/verify.ts` |
| Canonical identity string: grammar, render, parse, profile checks and shared vectors | identity | `packages/probity-records/src/probity_records/canonical_identity.py`<br>`packages/probity-records/src/probity_records/canonical_identity_vectors.py`<br>`packages/probity-records/docs/canonical-identity.md` | `node/probity-records-verify/src/identity.ts` |
| Holder confirmation key (cnf) and the stateless DPoP and mutual-TLS proof checks | identity | `packages/probity-records/src/probity_records/possession.py` | `node/probity-records-verify/src/verify.ts` |
| Record signer and key custody (KMS, Vault, delegated session keys) | identity | `packages/probity-records/src/probity_records/core.py`<br>`packages/probity-records/src/probity_records/signing.py` | - |
| Canonical JSON (RFC 8785) under every identity digest | identity | `packages/probity-records/src/probity_records/core.py` | - |
| Principals, act-chain, grant-chain and stamp digests over the one canonicaliser | identity | `packages/probity-records/src/probity_records/digests.py` | - |
| Verified identities of a request: the trust-bundle format and the pure function from presented credentials to canonical identities | identity | `packages/probity-records/src/probity_records/verified_identities.py`<br>`packages/probity-records/src/probity_records/verified_identities_vectors.py`<br>`packages/probity-records/docs/verified-identities.md` | `node/probity-records-verify/src/verified.ts` |
| Agent stamp format and its stateless verifier | broker | `packages/probity-records/src/probity_records/stamp.py` | `node/probity-records-verify/src/verified.ts` |
| Capability grant, delegation chain, attenuation and argument constraints | authority | `packages/probity-records/src/probity_records/grants.py`<br>`packages/probity-records/src/probity_records/constraints.py`<br>`packages/probity-records/src/probity_records/celexpr.py` | `node/probity-records-verify/src/verify.ts` |
| The one signed revocation list: kinds agent, build, grant, key, permit, sponsor and stream | authority | `packages/probity-records/src/probity_records/revocation.py` | `node/probity-records-verify/src/revocation.ts` |
| M-of-N approvals bound to the request hash, and the vote recount | authority | `packages/probity-records/src/probity_records/quorum.py`<br>`packages/probity-records/src/probity_records/oidc_approval.py` | `node/probity-records-verify/src/verify.ts` |
| Verify routes for the payment-mandate and status-receipt corpora | evaluation | `packages/agent-evidence-verify/src/agent_evidence_verify/adapters/payment_mandate.py`<br>`packages/agent-evidence-verify/src/agent_evidence_verify/adapters/status_receipt_binding.py`<br>`packages/agent-evidence-verify/src/agent_evidence_verify/evmsig.py` | - |

<!-- Every path in this table is checked against the tree by tests/test_identity_homes.py. -->
