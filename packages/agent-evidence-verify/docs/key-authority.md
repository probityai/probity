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
| `pin` | `{"kind": "pin", "keys": [{"public_key_sha256": "<hex>", "kid": "<optional>"}]}` | the SHA-256 of the key bytes is pinned; when every pin of that key names a key id, the record names one of them |
| `did-web` | `{"kind": "did-web", "did": "did:web:...", "document": "<artifact>", "document_sha256": "<hex>"}` | the pinned DID document lists a signing method carrying the key under `assertionMethod`, and, when the record names a key id, it is that method's id (absolute, or `#fragment` of this DID) |
| `registry` | `{"kind": "registry", "bindings": [{"subject", "public_key_sha256", "not_before", "not_after", "revoked_at"}]}` | a binding of the record's subject and key covers the record's time, and no binding of that subject and key was revoked at or before it |
| `kt-inclusion` | `{"kind": "kt-inclusion", "tree_size": n, "root_sha256": "<hex>", "inclusion_proof": "<artifact>"}` | an RFC 6962 inclusion proof the case supplies reaches the pinned root for the leaf `RFC 8785({"key_sha256", "subject"})` |
| `dnssec-chain` | `{"kind": "dnssec-chain", "trust_anchor": {"zone": ".", "ds": ["<DS>"]}, "name": "<owner>", "chain": "<artifact>"}` | the TXT RRset at `name` validates under DNSSEC from the pinned trust anchor at the record's instant, and one of its records reads `key-sha256=<hex>` for the key; when the record's subject is a DNS name, `name` is inside it |

Outcomes:

| Outcome | Adapter decision | Examples of the reason |
|---|---|---|
| `authorized` | the adapter's own verdict stands | `key_pinned`, `key_in_assertion_method`, `key_bound_at_time`, `key_in_log`, `key_in_dnssec_record` |
| `unauthorized` | `contradicted` | `key_not_pinned`, `key_id_mismatch`, `record_subject_not_did`, `key_not_in_assertion_method`, `key_not_for_signing`, `did_document_not_pinned`, `did_document_malformed`, `inclusion_proof_malformed`, `key_revoked`, `key_outside_validity`, `key_not_bound_to_subject`, `key_not_in_log`, `key_not_in_dnssec_record`, `key_record_outside_subject`, `dnssec_<reason>` for a chain that fails |
| `unknown` | `not_established` | `no_key_authority_in_policy`, `did_document_unavailable`, `record_subject_unknown`, `inclusion_proof_unavailable`, `dnssec_chain_unavailable`, `dnssec_<reason>` for a chain missing a record |

Rules a second reader of the same policy and evidence must apply the same way:

- A DID document in which two verification methods share an id, after a relative `#fragment` is resolved against
  the DID, is malformed, whether the methods sit under `verificationMethod` or are embedded under a relationship
  (DID Core 1.0 section 5.2). A reader that kept the first copy and one that kept the last would trust different
  keys. `verificationMethod` and each relationship must be lists.
- A verification method that carries more than one verification material property (`publicKeyJwk` and
  `publicKeyMultibase`, say) makes the document malformed (DID Core 1.0 section 5.2.1): one reader would trust
  the JWK and another the multibase key.
- A JWK whose `use` is not `sig`, or whose `key_ops` does not list `verify`, does not sign (RFC 7517 sections 4.2
  and 4.3).
- A DID's key speaks for that DID only: a record whose own subject is another identifier is
  `record_subject_not_did`. A record that names no subject is judged on the key alone.
- Each kind reads only the members its row names. Any other member (a `kid` on `did-web`, a `revocations` list
  beside `bindings`) is the consumer's case error, never ignored: an ignored restriction widens what is trusted.
  A pin's `kid` and a binding's `subject` are strings.
- Revocation ends a key for its subject: a second, unrevoked binding of the same subject and key does not bring
  it back.
- Instants are RFC 3339 `date-time` exactly: `T` and `Z` in either case, `Z` or a numeric offset. ISO 8601 week
  and ordinal dates, the basic format, a comma fraction and a space separator are refused. A leap second (`:60`)
  is read only when, with the offset applied, it falls in the last minute of a UTC day (RFC 3339 section 5.7);
  it orders after every instant of that day's last ordinary second and before the next day.
- Instants are compared exactly: a bound keeps every fraction digit it carries, and a token's `iat` is read as
  the number it is, an integer or the exact value of a double. Rounding either side to a microsecond would let a
  record a fraction of a microsecond before `not_before` through, or refuse one just inside `not_after`.
- An inclusion proof's `index` and `tree_size` are JSON integers; `true` and `2.0` are malformed. Inclusion shows
  the binding was logged, not that no later entry revoked it.

Every outcome adds a `key_authority` check that carries `key_set_sha256`: the SHA-256 over the sorted
digests of the keys the authority trusted, one per line. Two verdicts with the same fingerprint trusted
the same keys.

Keys are compared as raw bytes: the Ed25519 public key, or the uncompressed EC point `0x04 || x || y`.
A JWK (`OKP` Ed25519 and Ed448, `EC` P-256 and P-384) and a base58btc multibase Ed25519 key are read
into that form; a JWK that carries a private member is refused.

`proof_of_control/v1` is the first adapter that requires it. It asks once per signed statement (the token, or
every record of a chain) with that statement's `iss` as the subject and its `iat` as the instant, and the least
favourable answer decides. `document` (did-web), `inclusion_proof` (kt-inclusion) and `chain` (dnssec-chain) name
case artifacts; the decision's scope records the binding of each one it read. `dns_aid_sig/v1` and
`declared_versus_acted/v1` ask it with the record's zone as the subject (`did:web:<zone>` for did-web). The
DNSSEC rules are those of [dns-aid.md](dns-aid.md#dnssec_rrsetv1).
