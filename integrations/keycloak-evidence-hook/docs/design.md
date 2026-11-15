# Design: signed receipts for Keycloak token grants

## The problem

An agent platform that brokers identity through Keycloak lets a gateway exchange a user's token for one scoped to a tool, mint service tokens with client credentials, and obtain user-approved tokens over CIBA. After an incident, the question is always the same: which client obtained which token, for which user, with what audience and scope, and from which presented token. Keycloak's event store answers it only for someone who trusts the server's database, and it can be edited or expire. A relying party that received a token has no record of its own that it can check against the issuer.

## What the hook records

On each successful `TOKEN_EXCHANGE`, `CLIENT_LOGIN` (client credentials) and `AUTHREQID_TO_TOKEN` (CIBA) event, the listener writes one in-toto Statement in a DSSE envelope:

| member | source | note |
| --- | --- | --- |
| `subject[0].digest.sha256` | SHA-256 of the issued access token's `jti` | the token itself never reaches the listener |
| `issuer` | realm issuer URL | |
| `grantType` | the event type, mapped to its grant type URN | |
| `eventId`, `issuedAt` | the Keycloak event | `issuedAt` in UTC to whole seconds |
| `actor.clientId`, `actor.authMethod` | the requesting client | |
| `subject.userId` | the user the token names | the service-account user for client credentials |
| `subjectToken.sha256`, `subjectToken.issuedTo` | the presented `subject_token`, hashed when read | token exchange only |
| `actorTokenSha256` | the presented `actor_token`, hashed when read | null when none |
| `audience`, `scope` | the issued token's audience and scope | sorted, duplicate-free |
| `refreshTokenIdSha256` | SHA-256 of the refresh token id | null when none |
| `recorder` | listener id, version, key id | key id is the SHA-256 of the raw public key |
| `chain` | stream, index, SHA-256 of the previous line | see below |

The rule is strict: no token value, no secret and no raw token identifier is written. A listener sees the request form, so it hashes `subject_token` and `actor_token` the moment it reads them. The issued token's bytes are not visible to an event listener (Keycloak encodes them after the event details are set), so the receipt names the issued token by the digest of its `jti`. A relying party holding the token computes the same digest from the `jti` claim.

## Key custody

The realm operator supplies a dedicated Ed25519 key pair as two PEM files. The listener refuses to start when either file is missing, unreadable, or the pair does not match, so a realm never runs believing it records grants while it cannot sign them.

The recorder key is deliberately not the realm's token-signing key. A token-signing key is rotated on the realm's schedule and published in its JWKS for a different purpose; reusing it would let anyone who can obtain a token signature confuse the two roles, and would tie the evidence's lifetime to token rotation. Keep the private key outside the Keycloak database (a mounted secret or an HSM-backed file), publish the public key or its key id where verifiers pin it, and rotate by starting a new stream under a new key.

## The hash chain

Each receipt names its stream (one per node), its index and the SHA-256 of the previous line's bytes. The listener appends with a flush to disk and resumes the chain from the file's last line after a restart. A verifier given the whole file checks every signature and every link, so a removed, reordered, edited or foreign line breaks the check. The chain cannot show a truncated tail or a removed head: to cover those, a consumer retains the head digest it last saw (the verifier reports `head_sha256`) or has an independent party co-sign checkpoints.

## Failure behaviour

A failed write is logged at ERROR with the event id and counted; it does not change the token response. Keycloak calls listeners after the response is built and catches their exceptions, so an event listener cannot refuse a grant. A deployment that must refuse a grant it cannot record needs the same record written from a token-exchange or client-policy hook that runs before the response; the record format does not change.

## What a receipt does not prove

A valid receipt shows that the holder of the recorder key recorded this grant with these values. It does not show that the realm's policy allowed the grant, that every grant was recorded, or who holds the key. Those are separate checks: the policy against the realm's configuration, completeness against the retained head and the node count, custody against the operator's key records.

## Verifying

`agent-evidence-verify` judges one receipt with the `token_grant_receipt/v1` claim type. The consumer pins the recorder public key and the values it expects; the decision is `supported` when every value matches, `contradicted` with the first mismatch as its reason, and `not_established` when the key does not verify the receipt or the supplied log's chain is broken. The [end-to-end run](../e2e/RUN-LOG.md) shows each decision against receipts a real Keycloak wrote.

## Next

- ID-JAG (`draft-ietf-oauth-identity-assertion-authz-grant`): once Keycloak emits an event for the identity assertion grant, it maps to one more `grantType` with the assertion's digest in place of `subjectToken`.
- Pre-response recording, for deployments that must refuse a grant they cannot record.
- A conformance corpus for the predicate in agent-evidence-vectors, so other identity providers can emit the same record and be checked by the same suite.
