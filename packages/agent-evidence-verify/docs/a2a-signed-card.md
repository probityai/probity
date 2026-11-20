# Signed Agent Cards

`a2a_signed_card/v1` answers one question about one A2A Agent Card: which keys of the card's own
DID signed the card's bytes, and does the consumer's key authority let those keys speak for that
DID? It never says the agent does what the card says, and it fetches nothing.

A card reader that takes the key from the card's own `jku`, or from whatever key set arrived with
the card, accepts a card a stranger signed with a key of their own and served beside it. The
discovery record is mistaken for authority. This reader names the card's DID, scopes every `kid` to
it, and asks the consumer's [key authority](key-authority.md) about every signing key.

## Signed bytes

Each entry of the card's `signatures` list is a JWS in flattened form (`protected`, `signature`,
optional unprotected `header`) over `ASCII(protected) || "." || BASE64URL(JCS(card - signatures))`
(A2A specification sections 8.4.1 to 8.4.3, RFC 7515, RFC 8785). Algorithms: ES256 (raw `r || s`)
and EdDSA (Ed25519). The card is judged as served: removing protocol default values needs the
card's Protocol Buffers schema, which the JSON does not carry, so a card whose signer removed a
default that the server wrote back reads `signature_invalid`.

## Assessment

```json
{
  "claim_type": "a2a_signed_card/v1",
  "card": "card.json",
  "card_did": "did:web:agent.example",
  "keys": "jwks.json",
  "at": "2026-11-17T12:00:00Z",
  "key_authority": {"kind": "pin", "keys": [{"public_key_sha256": "...", "kid": "did:web:agent.example#ed25519"}]}
}
```

`card` names the card bytes as fetched. `card_did` is the DID the consumer holds for the card's
owner, for a did:web the host the card was fetched from. `keys` names the JWK Set the reader
resolved (from `jku` or a key store); without it, a `did-web` authority's pinned DID document
supplies the key. `at` is the check time a `registry` authority needs.

## Checks

The first refusal decides, and its code is the reason.

| Code | Refused when |
|---|---|
| `card_invalid` | the card is not I-JSON (a duplicate member, a lone surrogate) or not an object |
| `card_unsigned` | no `signatures`, or an empty list |
| `signatures_malformed` | `signatures` is not a list of `protected`, `signature` and an optional `header` object (`null` included) |
| `header_malformed` | a protected header or signature is not strict unpadded base64url, or the header is not an I-JSON object |
| `header_names_not_disjoint` | the unprotected header repeats a protected name (RFC 7515 section 7.2.1) |
| `kid_missing` | the protected header names no `kid` |
| `alg_unsupported` | `alg` is neither ES256 nor EdDSA (`none` included) |
| `jws_crit_unsupported` | the protected header carries `crit` |
| `jws_b64_unsupported` | the protected header carries `b64` |
| `kid_not_under_card_did` | a `kid` is not `card_did#fragment`: a bare `key-1`, or a key of another DID |
| `jwks_malformed` | the key set is not a JWK Set |
| `jwks_kid_ambiguous` | two keys in the key set share the `kid` |
| `key_malformed` | the key is not a public JWK: a private member such as `d`, a coordinate of the wrong length, or an Ed25519 point that is non-canonical or of small order |
| `key_not_for_signing` | the key's `use` is not `sig`, or its `key_ops` omit `verify` (RFC 7517 sections 4.2 and 4.3) |
| `alg_key_mismatch` | the key is not of the type `alg` names, or its JWK `alg` names another algorithm |
| `signature_invalid` | a signature does not verify over the card minus `signatures` |
| `conformance_extension_malformed` | the conformance extension's `params` are not exactly `corpus`, `corpus_version`, `verifier`, `verifier_version` with exact versions |

A key the key set does not hold for the `kid`, with no `did-web` authority to supply one, is
`not_established` with `key_unavailable`, decided only after every signature whose key is present
has verified: a forged signature beside one whose key was withheld is `contradicted`. A key in the
JWS header itself (`jwk`, `x5c`) is never used.

An Ed25519 key of small order (the identity point, say) is refused, not trusted to the signature
library: under the identity point the signature `R = identity, S = 0` verifies every message in
OpenSSL, so a card "signed" under it binds no one. The vector `small-order-key` carries that
signature under a key the consumer pins.

## The conformance extension

A card can list `https://w3id.org/agent-evidence/vocab/v1/conformance_extension` in
`capabilities.extensions`, with `params` naming the corpus its records are judged by and the
verifier that judges them, each at an exact version. The term is defined in
agent-evidence-vocabulary (`evaluation_claim.conformance_extension`). The extension sits inside the
card's signed bytes, so removing it breaks the card's signature; the vector `extension-stripped`
shows it. The reader reports the parameters in its check on a supported card.

A version is one exact release: a normalized PEP 440 public version (`0.7.0`, `1.0rc1`,
`0.7.0.post1`, `2.0.dev3`) or a SemVer 2.0.0 version without build metadata (`1.0.0-rc.1`). Leading
zeros, spellings PEP 440 normalizes away (`1.0-rc1`, `1.0.0alpha`), an epoch, a local label, build
metadata and any operator or wildcard (`>=0.37`, `^1.2`, `1.2.*`) are refused.

```json
{"uri": "https://w3id.org/agent-evidence/vocab/v1/conformance_extension",
 "params": {"corpus": "agent-evidence-vectors", "corpus_version": "0.37.0",
            "verifier": "agent-evidence-verify", "verifier_version": "0.7.0"}}
```

## Decisions

Every signature verifying and every signing key authorised is `supported` with
`card_signature_authorized`. A key the authority refuses is `contradicted` with the authority's
reason (`key_not_pinned`, `key_not_in_did_document`, `key_not_in_assertion_method` and the rest).
No authority, or authority evidence that is missing, is `not_established`. The rule is fail
closed: every signature covers the same bytes, so a signer that rotated keys drops the signature
under the retired key. The decision carries the key-set fingerprint the verdict trusted.

## Vectors

`tests/data/a2a-signed-card` holds 39 cases written by
`scripts/gen-signed-card-and-receipt-vectors.py` from fixed test keys: valid EdDSA, ES256 and
did:web cards, tampered, signatures-included, wrong-kid and stranger-key cards, and one case per
refusal code, among them withheld keys beside forged and valid signatures, keys marked for
encryption, a private key, a small-order key and a DID document whose methods are not a list.
Regenerate with `--check` to confirm the bytes.
