# Co-signed receipts

`co_signed_receipt/v1` answers one question about one tool-call receipt: which parties signed its
bytes, and may their keys speak for them? Two signatures bind two parties to one record. They do
not show the record true, and they do not show the parties independent: one operator can hold both
keys.

## The record and its signed bytes

A receipt names a format version, the agent (`agentDid`) and an optional caller (`callerDid`), the
tool, hashes of the task and of the result, the outcome (`success`, and a `failureType` that is
empty exactly on success), the latency in milliseconds and a timestamp, with hex Ed25519
signatures: `signature` by the agent, `callerSignature` by the caller. Both parties sign the same
bytes: RFC 8785 of the receipt with `signature` and `callerSignature` removed, every other member as
written and an absent member absent.

## Assessment

```json
{
  "claim_type": "co_signed_receipt/v1",
  "receipt": "receipt.json",
  "keys": "keys.json",
  "key_authority": {"kind": "pin", "keys": [{"public_key_sha256": "..."}]},
  "cosigner_key_authority": {"kind": "pin", "keys": [{"public_key_sha256": "..."}]}
}
```

`keys` names a JSON object mapping each DID to its public Ed25519 JWK, the keys the reader
resolved; the receipt never supplies its own key. `key_authority` decides the agent's key with
`agentDid` as the subject, `cosigner_key_authority` the caller's with `callerDid`, each at the
receipt's `timestamp`.

## Member rules

The member rules run before any signature, because a valid signature over a malformed record is the
case a signature check alone admits. They are the `co-signed-receipt` rule set of
agent-evidence-admission, with its codes and order, and a parity test runs that rule set's corpus:
`version-unknown`, `member-missing`, `hash-not-lowercase-hex64`, `member-malformed`,
`signature-not-lowercase-hex128`, `cosigner-missing`, `cosignature-missing`, `cosigner-is-signer`,
`failure-type-inconsistent`, `latency-out-of-range`, `instant-malformed`. A receipt that is not
I-JSON is refused under the strict reader's code (`duplicate-member` and the rest); one that is not
an object is `receipt-shape-malformed`.

## Signatures and authority

| Code | Decision | When |
|---|---|---|
| `key_unavailable` | `not_established` | the key set holds no key for a party, and every party whose key it holds signed (a forged signature beside a withheld key is `contradicted`) |
| `key_malformed` | `contradicted` | a party's key is not an Ed25519 public JWK: a private member, a JWK `alg` other than `EdDSA`, or a non-canonical or small-order point, under which one signature verifies every message |
| `key_not_for_signing` | `contradicted` | a party's key is marked `use` other than `sig`, or its `key_ops` omit `verify` |
| `cosigner-is-signer` | `contradicted` | the same key for both parties |
| `signature-invalid` | `contradicted` | the agent's signature does not verify |
| `cosignature-invalid` | `contradicted` | a present `callerSignature` does not verify |
| `receipt_signers_authorized` | `supported` | every signature verifies and every key is authorised |

A key an authority refuses is `contradicted` with the authority's reason; no authority is
`not_established`. The decision reports `evidence_attribution` (agent-evidence-vocabulary) once it
is decided: `co_signed` or `single_signed` when every signature verifies and every key is
authorised, `unattributed_evidence` when a present signature does not verify or an authority
refuses a key (a signature under a key that may not speak for its party binds no party), and no
value while key authority is undecided.

## Vectors

`tests/data/co-signed-receipt` holds 19 receipts written by
`scripts/gen-signed-card-and-receipt-vectors.py` from fixed test keys, among them eight broken
receipts, each refused: an uppercase hash, an absent task hash (signed without it, and signed as
`null`), an unknown format version, a co-signature that does not verify, a negative latency, a
129-character signature that a lenient hex decoder truncates to a valid one, and an omitted
`failureType`. Three more answer the adversary's reading: an agent key marked for encryption, the
identity point as the agent's key (whose one signature verifies every receipt), and a forged agent
signature beside a withheld caller key, which is `contradicted`, not `not_established`.
