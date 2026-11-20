# Read OCSF decision records

`agent-evidence-verify ocsf-decision` reads a stream of OCSF API Activity decision records (`class_uid`
6003) of the kind the Praxis Policy Engine's `ocsf-audit` sink writes: the ruling on the base event,
the engine's decision facts under `unmapped."aid.*"`, and, with chaining on, `attestation_list[0]`
carrying a SHA-256 `fingerprint` over the record's RFC 8785 bytes, a `prev_event` link and an ECDSA
P-256 DSSE signature at `unmapped.signature_b64`. The format is specified as AID-EMIT-1. The reader was
written from that text and the sink's published samples, which the tests read unchanged
(`tests/data/ocsf-decision/`, pinned in `SOURCE.json`).

```sh
agent-evidence-verify ocsf-decision records.ndjson --trust-policy jwks.json
agent-evidence-verify ocsf-decision records.ndjson --trust-policy jwks.json --heads heads.json --profile strict
```

It prints one JSON report and the verdict of the profile asked for. Exit 0 when the profile accepts,
1 when it refuses, 2 when a record cannot be read (then no verdict).

## Every check is its own dimension

Each dimension has a `status` of `verified`, `failed`, `not_checked`, `unavailable` or `not_supported`,
with findings. Record dimensions are reported per record under `records` and rolled up at the top.

| Dimension | What it checks |
|---|---|
| `structural_validity` | strict JSON; a member named twice at any depth, including one spelled with an escape, is not read, because a last-wins verifier and a first-wins consumer read two records from one seal |
| `decision_consistency` | `action_id`, `action`, `disposition_id` and `disposition` are one of the four rulings, and the verdict, steps, `deny_ignored` flag and `status_code` agree with it |
| `fingerprint` | SHA-256 of the bytes the published rule covers, integers written exactly |
| `signature` | the DSSE signature, tried against every key of the relying party's own JWKS; the record's key id never chooses the key |
| `key_binding` | the key that verified belongs to the signed `authority_uid`, was valid at the record's `time`, matches the unsigned key id if one is present, and is the only key of that authority valid then; with two live keys it is `unavailable`, because the key id rides outside the signed bytes |
| `trust_policy` | the relying party's JWKS: P-256 keys, each with a `kid` and the `authority_uid` it belongs to; a key listed twice refuses |
| `record_uniqueness` | one uid with different content refuses; the same record delivered twice is noted |
| `chain_links`, `chain_gaps`, `chain_head` | links among supplied records (fingerprint, type, seq, forks, more than one opening), predecessors named but not supplied, and whether the chain's opening is supplied |
| `stream_sequence`, `stream_head` | `stream_seq` dense per `(epoch, stream_id)` with `emission_seq` in order; a smaller seq under a larger epoch is a restart; the stream opens at 0 |
| `tail` | the end of each chain or stream against a head the relying party holds from a source the emitter does not control; without one it is `not_checked`, because deleting the last records leaves records that still verify |
| `evidence_scope`, `content_digests` | never established: the format does not say which read capabilities the sink held, and `aid.content` digests are not recomputed |

## Two profiles

`baseline` refuses a report in which any record or stream dimension failed, and leaves every
`not_checked` and `unavailable` as reported. This is the format's own reading.

`strict` also requires, each as its own dimension under `strict`:

| Strict dimension | Refuses |
|---|---|
| `signature_required` | an unsigned record; the format's default `signing: none` gives a checksum anyone with write access recomputes |
| `key_named_by_signed_bytes` | a record whose signing key the signed bytes and the relying party's key set do not name |
| `tail_anchored` | a chain or stream with no independent head |
| `opening_supplied` | a chain whose genesis, or a stream whose `stream_seq` 0, is not supplied |
| `numbers_interoperable` | an integer a double-based reader reads as another number, so its fingerprint differs there |

Heads (`--heads`) are a JSON list of `{"chain_uid", "uid", "fingerprint"}` and
`{"epoch", "stream_id", "stream_seq"}` objects.

## Corpus mode

`agent-evidence-verify corpus DIR` answers a corpus whose manifest names the suite `ocsf-decision/v1`:
each member is a JSON object with `records` (the exact text, one record per line), and optionally
`trust_policy`, `relying_party` (`{"heads": [...]}`) and `profile`. The `vectors-ocsf-decision` corpus
of agent-evidence-vectors is written in this form.
