# Adapters

## Operand lineage

`operand_lineage/v1` recomputes ordered binary arithmetic over exact decimal
strings. A consumer policy pins separate source and execution artifacts,
declares constants, and names the final step. Every declared constant and
step must contribute to that figure. A missing artifact or a consumer witness
pin mismatch yields `not_established`; missing references also yield
`not_established`. A file that differs from its declared length or SHA-256
refuses with exit 2 and no verdict. Unsafe file reads also refuse.
Mismatched known operands or results yield `contradicted`.
Nonterminating division needs a rounding rule and yields `not_established`.
Malformed input exits 2 without a verdict.

`supported` means the supplied trace is internally consistent with the
selected source bytes. The policy's authority label does not authenticate
who observed execution, establish source completeness, or show that the
chosen operation answered the intended question. A real execution claim
needs an independently captured trace and its own binding policy.

## Authority anchor

`authority_anchor/v1` compares a consumer-selected JSON field with an expected
identity in a pinned HTTP capture. It checks the request target, status, and
capture window. A different bound identity is `contradicted`; an absent,
unparseable, wrong-target, or stale bound capture is `not_established`.
Unsafe reads and declared artifact binding mismatches refuse without a verdict.

The consumer must pin a capture obtained outside the observed artifact and
establish its provenance. The verifier does not contact the authority or
authenticate the transport or capture clock. An AVE class stamp naming
`external_authority` describes a possible vantage; it is not evidence that a
particular finding made that probe. The example uses invented identities.

## Event absence

`event_absence/v1` checks a claim that no event of a selected type occurred
for one invocation and interval. A bound event in that interval contradicts
the claim even if coverage is incomplete. An empty record supports it only
when a separate capability record declares field visibility and the
observation record declares complete coverage for that claim and scope. The
same rule applies when the event field is absent or present but empty.

Missing visibility or coverage is `not_established`. Malformed records fail
without a verdict. Both records are pinned by the consumer policy. Matching
identifiers and digests do not authenticate the producer or prove that its
coverage statement is true; the consumer must establish those facts separately.

An observation with `coverage: incomplete` must name its gaps as `start` and
`end` intervals inside its scope. Use `coverage: unknown` when no gap can be
located. A bare `incomplete` flag is malformed, not a property verdict.

## Broker-recorded file completion

[`brokered_file_write/v1`](brokered-file-write.md) checks a separately selected
typed `completion_recorded` assertion against authenticated Observer v0 file
records. Missing terminal evidence has an explicit state. Process failure,
recorded completion and later retained file bytes remain separate. The check
does not establish arbitrary effects or independent custody.

## Done-receipt checks

[`protected_paths/v1`, `acceptance_observed/v1`, `tool_claim_match/v1`, `completion_claim/v1` and `done_receipt/v2`](done-receipt.md)
check a coding agent's completion claim against a sealed contract and records made
outside the agent. `protected_paths/v1` is the event-absence rule above, applied to
file mutation.

## Adversarial execution evidence statements

`adversarial_execution_evidence/v1` judges one in-toto statement whose predicate type is
`https://in-toto.io/attestation/adversarial-execution-evidence/v0.7`. The assessment names the
statement artifact and may pin `substrate_observation_keys`, raw Ed25519 public keys as 64 lowercase
hex digits. The adapter recomputes the predicate's gates from the statement's own bytes: `supported`
means the statement is valid and its carried result equals the recomputed result; `contradicted`
means a gate refused it. The `execution_evidence` check carries the verdict, the failure codes in
detection order, and for a valid statement the result and each row's tier (`attested` only when every
covering record verifies under a pinned key). [examples/execution-evidence](../examples/execution-evidence)
uses a conformance-corpus statement and the corpus's published test key, which carries no trust
outside the corpus.
