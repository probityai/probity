# Telemetry evidence: `evidence_digest/v1` and `event_log_completeness/v1`

Telemetry records often carry a digest of each piece of evidence, and session logs often link each event to the
one before it. A check that only recomputes digests passes five records it should refuse:

| Break | What a digest-only check sees | What these claim types return |
|---|---|---|
| The consumer reads an inline copy; the digest binds a second copy that nobody reads, and only the inline copy was edited | every digest matches | `contradicted` / `consumed_copy_bound` |
| Every digest reference is removed | 0 mismatches, read as a pass | `contradicted` / `coverage` ("0 of N consumed items carry a digest") |
| A body is written with a repeated member (`{"route":"A","route":"B"}`) | a last-wins parser hashes one meaning, a first-wins reader acts on another | `contradicted` / `no_duplicate_member` |
| The digest set is signed by a key it carries for itself | the signature verifies | `contradicted` / `signer_pinned` (the key authority check says `key_not_pinned`) |
| The consumer names no item at all | 0 of 0 | `not_established` / `empty_denominator` |

## `evidence_digest/v1`

```json
{
  "claim_type": "evidence_digest/v1",
  "manifest": "manifest.json",
  "consumed": {"e001": "e001.json", "e002": "e002.json"},
  "authority": {"kind": "pin", "keys": [{"public_key_sha256": "<hex>"}]},
  "require_signature": true
}
```

`consumed` maps each item id to the case artifact holding the exact copy the consumer reads. The manifest is
strict I-JSON:

```json
{"schema_version": "evidence-digest-manifest/v1",
 "refs": [{"id": "e001", "hash_alg": "sha-256", "canonicalization": "rfc8785", "digest": "<hex>"}],
 "signature": {"alg": "Ed25519", "public_key": "<base64url>", "value": "<base64url>"}}
```

`hash_alg` is `sha-256`, `sha-384` or `sha-512`. `canonicalization` is `rfc8785` (the consumed copy is parsed as
strict I-JSON and hashed in RFC 8785 form), `cbor-deterministic` (the consumed copy must already be the RFC 8949
section 4.2.1 core deterministic encoding; a non-shortest argument or unsorted map is refused) or `raw` (the bytes
as read). A reference that declares no form is `not_established` / `undeclared_canonical_form`. The signature is
Ed25519 over `evidence-digest-manifest/v1 || 0x00 || RFC 8785 (manifest without signature)`. A `signature` member
whose value is `null` is refused (`record_shape`): it is neither a signature nor its absence.

Checks, in order; the first failure is the reason: `record_shape` (a repeated member is `no_duplicate_member`),
`signature`, `key_authority` and `signer_pinned`, `no_duplicate_reference`, `coverage`, `canonical_form`,
`consumed_copy_bound`. Not established: `records_unavailable`, `signer_not_established` (a signed manifest and no
authority in the policy), `unsigned_manifest` (when `require_signature`), `empty_denominator`,
`undeclared_canonical_form`, `consumed_copy_unavailable`. Supported: `digests_bind_consumed_copy`.

## `event_log_completeness/v1`

```json
{
  "claim_type": "event_log_completeness/v1",
  "records": "events.jsonl",
  "first_prev": "<sha256 the consumer pinned for the first link>",
  "coverage": {"session": "s1", "first_seq": 1},
  "head": "head.json",
  "authority": {"kind": "pin", "keys": [{"public_key_sha256": "<hex>"}]}
}
```

One event per line, each an I-JSON object with `seq` and `prev`; `prev` is SHA-256 over the RFC 8785 bytes of
the event before it. The head is in the `probity-witness-ledger-head-v0` format the observer writes
(`format`, `count`, `head`, `keyid`, `signature`), signed with Ed25519 over
`probity-witness-ledger-head-v0 || 0x00 || RFC 8785 {format, count, head}`. The key the head carries is checked
under the consumer's authority, never trusted because it is there.

Checks, in order: `record_shape` (`no_duplicate_member`), `coverage_boundary`, `signature`, `key_authority` and
`signer_pinned`, `no_duplicate_event`, `sequence`, `chain_order`, `head_anchor`. Each of six edits fails with a
named reason: a dropped event and two swapped events fail `sequence`; a flipped status, a rewritten link and an
edited body fail `chain_order`; a cut tail fails `head_anchor`; a log rewritten, relinked and re-signed with
another key fails `signer_pinned`. Not established: `empty_denominator` (no events), `head_not_anchored` (no head
retained: a cut tail cannot be seen), `head_unavailable`, `records_unavailable`, `signer_not_established`.
Supported: `event_log_complete`.

The verdict does not show that the producer recorded every event that happened, or anything about events outside
the coverage boundary.
