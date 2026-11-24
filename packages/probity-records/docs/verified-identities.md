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

`verify_request` takes the same arguments and also returns what a service that keeps state spends once: the possession proof, and the stamp's `nonce` until its `expires`. A DPoP proof (`possession.DpopProof`) is spent under `possession.proof_key(jkt, jti)` until its `replay_exp`, which is `iat` plus the freshness skew plus `possession.REPLAY_GRACE`, the last second at which the same proof could still pass; a certificate proof (`possession.CertificateProof`) names the confirmed thumbprint and has nothing to spend. The TypeScript `verifyRequest` returns the same values (`proof.jkt`, `proof.jti`, `proof.iat`, `proof.replayExp`, and `proofKey`), so a receiver in either language spends the same key for the same window.

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
- **The agent stamp**, when the call comes through a gateway that verified the principals and forwards the stamp instead of their tokens. The stamp is an HTTP message signature (RFC 9421) over the request, so it is read from the request's header lines (`RequestFacts.headers`, one `(name, value)` pair per line received), not from a token role. A stamp is never presented beside tokens (`identity_sources_mixed`).

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

For a stamp (`stamp.verify_stamp`), in this order:

1. The four fields `Probity-Principals`, `Content-Digest`, `Signature-Input` and `Signature` are each given once, in any case (`stamp_repeated`), and all four are present once any is (`stamp_malformed`). A `Signature` with no `probity` member belongs to another signer and is not a stamp.
2. Each is an RFC 8941 dictionary, read by `agent_evidence_verify.structured_fields` (`stamp_malformed`).
3. The `probity` signature input covers exactly `("@method" "@target-uri" "@authority" "content-digest" "probity-principals")`, in that order, and has exactly the parameters `created`, `expires` (Integers), `nonce`, `keyid` (Strings, the nonce at most 128 bytes), `alg="ed25519"` and `tag="probity-principals/v1"` (`stamp_header_invalid`).
4. `keyid`, the lowercase hex SHA-256 of a raw Ed25519 key, names exactly one key the bundle lists (`stamp_key_mismatch`), and that key is pinned for `stamp` in the bundle's tenant (`principal_key_not_pinned`). The key id only picks among listed keys: a stamp never brings its own key.
5. `Content-Digest` is exactly one `sha-256` Byte Sequence (`stamp_malformed`) and it is the digest of the body received (`stamp_request_mismatch`).
6. The Ed25519 signature verifies over the RFC 9421 signature base built from the request the service received: its method, its own external URL and that URL's authority (`stamp_forged`). A stamp signed for another method, route, host or port therefore fails here.
7. `expires` is after `created` (`stamp_malformed`) and at most 300 seconds later (`stamp_lifetime_too_long`); `created` is not after the time (`stamp_not_yet_valid`); the time is before `expires` (`stamp_expired`).
8. `Probity-Principals` is exactly the String members `id`, `client` and `principals`, in that order, with `principals` a `sha256:` identity digest (`stamp_malformed`); `id` is a canonical identity string (`stamp_identity_mismatch`) of kind `agent` (`stamp_downgraded`) naming the user it acts for (`stamp_no_user`) and an agent that is not that user (`stamp_downgraded`).

The verifier remembers nothing. A service that keeps state spends `(nonce, expires)` in its own single-use store after these checks pass, so a captured stamp cannot be replayed even on the same request.

A gateway signs with `stamp.sign_stamp`:

```
Probity-Principals: id="aid1!agent;user=...;chain=...;act=sha256:...", client="agent-refunds", principals="sha256:..."
Content-Digest: sha-256=:<base64 SHA-256 of the body>:
Signature-Input: probity=("@method" "@target-uri" "@authority" "content-digest" "probity-principals");created=1795435190;expires=1795435250;nonce="...";keyid="<hex SHA-256 of the raw key>";alg="ed25519";tag="probity-principals/v1"
Signature: probity=:<Ed25519 signature>:
```

The user, the agent chain, the `act` digest and the `grants` digest are read from `id`, so the stamp carries each once and they cannot disagree.

Last, every ref of the request identity and of the transport identity is in the bundle's environment (`identity_environment_mismatch`), so a staging identity is never read in production, and the bundle's profile is applied: `strict` refuses kind `unknown` (`identity_actor_unknown`).

## The identity

For tokens: kind `agent`; the user ref is the user token's `iss` and `sub`; the chain is the agents of the user token's `act` claim, root first, ending with the presented agent; `act` is `digests.act_chain_digest` of the claim; the sponsor ref comes from the sponsor token. Every ref is scoped by the bundle's environment and named by its issuer.

## Vectors

`vectors/shared/verified_identities.json` holds 80 cases, written by `scripts/gen_shared_vectors.py` from `verified_identities_vectors.py` with fixed keys and deterministic signatures. The TypeScript verifier (`node/probity-records-verify/src/verified.ts`) reports the same identities, the same proof and stamp spend values, or the same refusal code for each. An accepted case's `proof` is `possession.possession_record` of the proof and, for DPoP, its single-use `key` and the `expires` a store must remember it until: `{"method": "dpop", "iat", "jkt", "jti", "key", "expires"}` or `{"method": "mtls", "x5t#S256"}`. VI16 holds the window at the oldest accepted `iat`, and VI17 holds the key to the UTF-8 bytes of a `jti` that is not ASCII.
