# Record bundle (`probity-record-bundle/v1`)

A record bundle carries one decision record and everything needed to grade it offline, with only the public witness
keys a verifier pins: the cosigned checkpoint, the log's keys, the leaf and its RFC 9162 inclusion proof, the record
and its source key, and, for a record that answers one stage of one permit, the receipt map commitment and the map
proof (`receipt-map.md`). The verifier is `probity_records.bundle.verify_bundle`.

## What a public bundle carries

Decision, 24 Nov 2026: a public bundle carries the evaluator's control-decision statement, predicate
`https://probityai.github.io/agent-evidence-vectors/predicate/v1/control-decision`, signed as one DSSE envelope
(`payloadType` `application/vnd.in-toto+json`) under the source's Ed25519 key. It is the one decision predicate with a
public reader, so every check in a public bundle is one a stranger can repeat from published text.

A gateway record (`urn:probity:gateway-decision:v1` and `v2`) and a custodian event (`urn:probity:custodian-event:v1`)
are private enforcement formats. The public verifier refuses a bundle whose source kind it holds no reader for
(`bundle_record_kind_unsupported`). A party that holds a private reader passes it (`readers={"gateway": ...}`), and the
grading, the inclusion and map proofs and the claims check are the same code for every kind.

## Shape

```json
{"format": "probity-record-bundle/v1",
 "checkpoint": "<c2sp.org/tlog-checkpoint signed note with cosignatures>",
 "log": {"vkey": "<Ed25519 vkey named after the origin>", "pqVkey": "<ML-DSA-44 vkey> | null"},
 "leaf": {"index": 0, "bytes": "<base64 leaf>", "inclusion": ["<base64 32 bytes>", "..."]},
 "record": {"bytes": "<base64 envelope>", "source": {"id": "...", "kind": "evaluator", "publicKey": "<64 hex>"},
            "counterparty": "<optional target id>"},
 "map": null | {"commitment": {"index": 1, "bytes": "...", "inclusion": ["..."]}, "proof": {"...": "receipt-map.md"}},
 "claims": {"grade": "I", "pq": "PQ-covered (independence)"}}
```

The leaf is the canonical JSON of `probity-decision-log-leaf/v2`: `format`, `tenant`, `source`, `kind`, `sequence`,
`previous`, `record` (the SHA-256 of the payload), `receipt` (`{issuer, permit, stage}` or null) and `admittedAtMs`.
The verifier rebuilds it from the verified record and refuses one that differs (`bundle_record_mismatch`).

## Grades

| Grade | When |
|---|---|
| S | fewer pinned external operators cosigned freshly than the quorum: "locally tamper-evident, awaiting external witness" |
| W | externally witnessed; content attested only by the party it describes, a receipt without a map proof, or a claimed counterparty under a key the verifier did not bind ("tenant-declared counterparty") |
| I | a receipt under a key the verifier bound to the counterparty, externally witnessed, with a map proof that its (issuer, permit id, stage) holds exactly this record |

Assurance is "staging-grade" unless production-list operators alone meet the quorum. Post-quantum status: "PQ-covered
(independence)" needs the log's own ML-DSA-44 line under the key the VERIFIER pins for the origin and a fresh ML-DSA-44
cosignature from a counted witness; "PQ-covered (integrity)" the pinned log line alone; otherwise "PQ-pending". The
witnessed time is when the quorum was met (the quorum-th earliest counted cosignature, one per operator). A claim above
what the verifier computes is refused (`bundle_claim_overstated`).

## Refusal codes

`bundle_malformed`, `bundle_checkpoint_refused`, `bundle_trust_invalid`, `bundle_log_key_invalid`,
`bundle_leaf_not_included`, `bundle_leaf_malformed`, `bundle_record_kind_unsupported`, `bundle_record_invalid`,
`bundle_record_mismatch`, `bundle_map_invalid`, `bundle_map_contradiction`, `bundle_claim_overstated`, each in
`refusal_codes.json` under the check `record.bundle`.
