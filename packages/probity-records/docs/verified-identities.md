# Verified identities of a request

`probity_records.verified_identities` answers one question for a service that receives requests from agents: who is this? It takes the credentials a request presented, the trust bundle the service pins and the time, and it returns the canonical identities of the request ([canonical-identity.md](https://github.com/probityai/probity/blob/main/packages/probity-records/docs/canonical-identity.md)) with the transport identity beside them. It returns no allow or deny. An access list, a policy engine or a log reads the same answer.

```python
from probity_records.verified_identities import RequestFacts, verified_identities

identities = verified_identities(
    {"user": user_token, "agent": agent_token},
    bundle,                      # the pinned trust bundle, a parsed JSON document
    "2026-11-23T12:00:00+00:00",
    transport,                   # the mutual-TLS peer the TLS layer verified, or None
    request=RequestFacts(method="POST", url="https://billing.example.com/mcp/refund", content=body,
                         dpop=dpop_header),
)
```

`verify_request` takes the same arguments and also returns what a service that keeps state spends once: the possession proof and the stamp's `jti`.

## The trust bundle

```json
{
  "version": 1,
  "environment": "prod",
  "tenant": "acme",
  "audience": "https://billing.example.com/mcp",
  "profile": "strict",
  "issuers": {
    "https://idp.example.com/realms/agents": {
      "keys": [{"kty": "OKP", "crv": "Ed25519", "x": "...", "kid": "idp-1"}],
      "pins": [{"thumbprint": "<RFC 7638 thumbprint>", "roles": ["user", "agent"], "tenants": ["acme"]}]
    },
    "gateway.example.com/t/acme": {
      "keys": [{"kty": "OKP", "crv": "Ed25519", "x": "..."}],
      "pins": [{"thumbprint": "<RFC 7638 thumbprint>", "roles": ["stamp"], "tenants": ["acme"]}]
    }
  }
}
```

Every member is required and no other member is allowed. Each pin names one listed key by its RFC 7638 thumbprint and says which roles (`user`, `agent`, `sponsor`, `stamp`) it may sign for and in which tenants. A key signs a credential only for a role and a tenant its pin names, so a key pinned for user tokens never makes an agent. A token issuer is an `https` URL and its keys carry `kid`. A stamp key is an Ed25519 key pinned for `stamp` alone. A private member, an RSA key shorter than 2048 bits, a key listed twice or a pin that names no listed key is refused as `trust_bundle_malformed`.

## Credentials

A request presents one of two things:

- **Identity-provider tokens**, when an agent calls the service directly: `user` (an RFC 9068 access token, `typ` `at+jwt`, or an identity assertion grant, `oauth-id-jag+jwt`), `agent` (the agent client's own access token) and `sponsor` (an ID token, for an agent acting for no user).
- **The agent stamp** (`stamp`), when the call comes through a gateway that verified the principals and forwards the stamp instead of their tokens. A stamp is never presented beside tokens (`identity_sources_mixed`).

## Checks, in order

For each token:

1. A compact JWS of base64url JSON objects with no repeated member (`token_malformed`).
2. No header member that names a key: `jku`, `jwk`, `x5u`, `x5c` (`token_header_names_a_key`). No `crit`: this verifier implements no extension (`token_critical_unsupported`).
3. `iss` is a pinned issuer (`principal_issuer_untrusted`); `kid` selects exactly one of its keys (`token_kid_unknown`); that key is pinned for this role in the bundle's tenant (`principal_key_not_pinned`).
4. `typ` is the role's type (`token_type_mismatch`).
5. The signature verifies under the pinned key with the algorithm the key's type takes: EdDSA, ES256 or RS256 (`token_signature_unverified`). `alg` `none` never verifies.
6. `sub` and the client (`client_id`, or `azp` for an ID token) are non-empty strings; `iat` and `exp` are integers with `exp` after `iat` (`token_malformed`).
7. `aud` names the bundle's audience (`token_wrong_audience`).
8. `iat` is not after the time (`principal_not_yet_valid`), `nbf` is not after it (`token_not_yet_valid`), and the time is before `exp` (`principal_expired`).

Then for the request:

- A user's token with no agent token is kind `unknown`: the absence of an agent never means a human acted. A user's token that names an agent in `act` while no agent token is presented is refused (`principal_credential_missing`).
- The user's `act` claim names the presented agent first (`principal_act_names_another_agent`); the user's token was issued to the agent's client (`principal_user_token_not_issued_to_agent`). A sponsor answers for an agent (`principals_need_agent`).
- Every token bound to a key (RFC 7800 `cnf`) is bound to the same key (`possession_not_the_grant_key`) and is proven held for this request by `possession.check_possession`: a DPoP proof for this method, this URL and these body bytes, whose `ath` binds the agent's token, or the confirmed client certificate. A token and proof captured on one route and replayed on another fails `dpop_htu_mismatch`. The proof is returned so a service that keeps state spends it once.

For a stamp (`stamp.verify_stamp_token`): the header is exactly `alg` `EdDSA`, `typ` `probity-agent-stamp+jwt` and `kid` (`stamp_header_invalid`); `iss` is a pinned issuer (`stamp_wrong_issuer`) and `kid` is the SHA-256 of a raw Ed25519 key pinned for `stamp` there (`stamp_key_mismatch`, `principal_key_not_pinned`); the signature verifies (`stamp_forged`); the claims are exactly `iss`, `aud`, `iat`, `exp`, `jti`, `request_sha256` and `stamp` (`stamp_malformed`); `aud` is the bundle's audience (`stamp_wrong_audience`); `request_sha256` is the SHA-256 of the body received, null for no body (`stamp_request_mismatch`); the lifetime is at most 300 seconds (`stamp_lifetime_too_long`) and the time is inside it (`stamp_not_yet_valid`, `stamp_expired`). The `stamp` claim is exactly `user`, `agent`, `principals`, `act`, `grants` and `identity`; it names an agent other than the user (`stamp_downgraded`); and `identity` is a canonical identity string naming the same user, agent, act digest and grant digest (`stamp_identity_mismatch`). The request identity is that string, so a service behind the gateway reads exactly the identity a service called directly reads.

Last, every ref of the request identity and of the transport identity is in the bundle's environment (`identity_environment_mismatch`), so a staging identity is never read in production, and the bundle's profile is applied: `strict` refuses kind `unknown` (`identity_actor_unknown`).

## The identity

For tokens: kind `agent`; the user ref is the user token's `iss` and `sub`; the chain is the agents of the user token's `act` claim, root first, ending with the presented agent; `act` is `digests.act_chain_digest` of the claim; the sponsor ref comes from the sponsor token. Every ref is scoped by the bundle's environment and named by its issuer.

## Vectors

`vectors/shared/verified_identities.json` holds 53 cases, generated by `verified_identities_vectors.py` with fixed keys and deterministic signatures. The TypeScript verifier (`node/probity-records-verify/src/verified.ts`) reports the same identities or the same refusal code for each.
