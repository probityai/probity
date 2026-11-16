# Key authority

A valid signature proves that someone holding a key signed the bytes. It does not prove that the key
may speak for the record. A verifier that stops at the signature accepts a record signed by a key the
record supplies for itself, a key named in a DID document but not listed for assertions, a key revoked
before the record was made, or a key bound to another subject.

`agent_evidence_verify.key_authority.authorize` answers the second question under an authority the
consumer names in its policy, never one the record names. Adapters that judge a signature call it
after the signature check, and a verdict agrees only when the key is authorised.

| Kind | Policy object | Authorised when |
|---|---|---|
| `pin` | `{"kind": "pin", "keys": [{"public_key_sha256": "<hex>", "kid": "<optional>"}]}` | the SHA-256 of the key bytes is pinned, under the pinned key id when the pin names one |
| `did-web` | `{"kind": "did-web", "did": "did:web:...", "document": "<artifact>", "document_sha256": "<hex>"}` | the pinned DID document lists a method carrying the key under `assertionMethod`, and the record's key id is that method |
| `registry` | `{"kind": "registry", "bindings": [{"subject", "public_key_sha256", "not_before", "not_after", "revoked_at"}]}` | a binding of the record's subject covers the record's time and was not revoked at or before it |
| `kt-inclusion` | `{"kind": "kt-inclusion", "tree_size": n, "root_sha256": "<hex>"}` | an RFC 6962 inclusion proof the case supplies reaches the pinned root for the leaf `RFC 8785({"key_sha256", "subject"})` |

Outcomes:

| Outcome | Adapter decision | Examples of the reason |
|---|---|---|
| `authorized` | the adapter's own verdict stands | `key_pinned`, `key_in_assertion_method`, `key_bound_at_time`, `key_in_log` |
| `unauthorized` | `contradicted` | `key_not_pinned`, `key_id_mismatch`, `key_not_in_assertion_method`, `did_document_not_pinned`, `key_revoked`, `key_outside_validity`, `key_not_bound_to_subject`, `key_not_in_log` |
| `unknown` | `not_established` | `no_key_authority_in_policy`, `did_document_unavailable`, `record_subject_unknown`, `inclusion_proof_unavailable` |

Every outcome adds a `key_authority` check that carries `key_set_sha256`: the SHA-256 over the sorted
digests of the keys the authority trusted, one per line. Two verdicts with the same fingerprint trusted
the same keys.

Keys are compared as raw bytes: the Ed25519 public key, or the uncompressed EC point `0x04 || x || y`.
A JWK (`OKP` Ed25519 and Ed448, `EC` P-256 and P-384) and a base58btc multibase Ed25519 key are read
into that form; a JWK that carries a private member is refused.

`proof_of_control/v1` is the first adapter that requires it. A DNSSEC chain authority is not built yet.
