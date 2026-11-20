# Read a decision record's action-binding attachment

`agent-evidence-verify decision-record` reads one attachment whose document carries
`"profile": "dps-action-binding"` and `"profile_version": "0.3.0"`: the exact bytes of every action
specification under its SHA-256, and the stages of one reviewed action (proposal, review, outcome,
standing approval and its revocation, authorised change, request, recheck, attempt, result), beside
the decision record named by its `decision_id`. The reader was written from the format's published
text, schemas and test data.

```sh
agent-evidence-verify decision-record attachment.json --record record.json --trust-policy policy.json
agent-evidence-verify decision-record attachment.json --relying-party sources.json --profile strict
```

It prints one JSON report and the verdict of the profile asked for. Exit 0 with a verdict; exit 2
when an input cannot be read, and then no verdict.

## Every check is its own dimension

Each dimension has a `status` of `verified`, `failed`, `not_checked`, `unavailable` or
`not_supported`, with findings. No dimension stands for another and the report never merges them:

| Dimension | What it checks |
|---|---|
| `structural_validity` | the document against the published schema, member by member; a member named twice is not read |
| `specification_digests`, `specification_statements` | each specification's bytes against its digest, and its summary against its bytes |
| `record_statements` | the stages' statements about the decision record's `drafting_authority`, `review_log` and `affirmation_record`; `not_checked` without the record |
| `action_binding` | shown, approved, requested and attempted digests agree; one outcome per review; request limits; changes; standing-approval bounds |
| `stage_order`, `authorisation_recheck`, `observed_results`, `rationale_provenance` | order and times as the issuer states them, rechecks before attempts, one result per attempt, rationale timing |
| `issuer_signature` | the organisation seal copy, with the key taken only from the relying party's trust policy, its certificate and its key state; a key superseded or compromised before it is read signs at a stated earlier time only as `unavailable`, unless an independent timestamp earlier than the retirement covers the seal |
| `time_assurance` | the issuer's times against an independent timestamp the relying party verified: `failed` when the issuer dates the attachment after it, `verified` within a day before it, `not_checked` further before it, since a timestamp shows only that the bytes existed no later than its time |
| `identity_assurance`, `authority_assurance`, `legal_signature` | never established by the attachment |

Every base64 value the attachment carries (specification and bounds bytes, the seal's signature) is
read only in its canonical spelling: a text whose unused trailing bits are set is another writing of
the same bytes, and fails `structural_validity`.

## Two profiles

`baseline` refuses a report whose structure, any binding dimension, the issuer signature or
`time_assurance` failed, and otherwise accepts
it with every `not_checked` and `unavailable` left as reported. This is the format's own reading.

`strict` adds seven dimensions under `strict`, and accepts only when the issuer signature, every
binding dimension and every strict dimension is `verified`:

| Strict dimension | Refuses |
|---|---|
| `approver_independence` | an approval given by the proposer, the requester or the executor |
| `single_effect_per_request` | one request observed to succeed twice; a retry after an indeterminate attempt stays `not_checked` until the target says how many effects it saw |
| `identity_independent`, `authority_independent` | a person or an authority the relying party's own sources do not confirm; an identity entry confirms only when it names its source, and a grant held by a person whose identity is not confirmed does not verify |
| `time_independent` | issuer times that disagree with the relying party's independent observations, so consistent backdating shows |
| `latest_attachment` | an older attachment of the decision, when the relying party holds a later one |
| `signature_required` | an unsigned attachment, including one whose signature was removed |

The relying party's sources (`--relying-party`) are a JSON object with any of `identities`
(`{actor: {"status": "verified", "source": ref}}`), `authority_grants` (`[{"actor_ref", "authority_ref"}]`),
`independent_times` (`{"tolerance_seconds": n, "observed": {stage_id: time}}`), `latest`
(`{decision_id: attachment_digest}`), `target_effects` (`{request_id: count}`) and
`independent_timestamp` (`{"source_ref", "subject_sha256", "existed_no_later_than"}`: the relying
party's own reading of a timestamp token whose message imprint is the SHA-256 of the attachment's
bytes or of its seal's signature bytes; this reader does not parse the token itself).

## Corpus mode

`agent-evidence-verify corpus DIR` answers a corpus whose manifest names the suite
`decision-record/v1`: each member is a JSON object with `attachment` (the exact text), and optionally
`record`, `trust_policy`, `relying_party`, `timestamps_beside` and `profile`. The `vectors-decision-record`
corpus of agent-evidence-vectors is written in this form.

The tests read every published binding case of the format (`tests/data/decision-record/`, pinned by
SHA-256 in `SOURCE.json`) and compare each dimension with the case's expected value.
