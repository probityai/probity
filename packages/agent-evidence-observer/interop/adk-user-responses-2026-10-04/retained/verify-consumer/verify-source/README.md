# probity-verify

An offline verifier that decides whether a claim holds against evidence bytes the consumer pinned, with adapters for source passages, operand lineage, authority captures and bounded absence claims.

It's for auditors, incident reviewers and relying parties who receive a claim about an AI system and need a decision they can replay, not a report they have to trust.

## Quick start

There is no package release yet, so pin a commit. Python 3.10 or newer and [uv](https://docs.astral.sh/uv/):

```sh
git clone https://github.com/probityai/probity-verify && cd probity-verify
git checkout d3c0213ff3697c19535b6bcb63e29e74182807b5
uv run probity-verify examples/source-coverage/case.json \
  --policy examples/source-coverage/policy-june.json
```

It prints a decision packet that opens:

```text
Probity decision packet v1
Case: "source-coverage-demo"
Claim: source_text_coverage/v1
Decision: contradicted
Reason: selected_span_missing_from_record
Policy SHA-256: dfda1551714f92702169d1411af6b0bfeee54732f934ce71265534af775fa388
```

A selected passage is in the source capture but missing from the stored report. The packet goes on to list every artifact binding and check. `uv run pytest` runs the test suite.

## Status

Version 0.1.0, unreleased. Four adapters ship: `source_text_coverage/v1`, `operand_lineage/v1`, `authority_anchor/v1` and `event_absence/v1`. Each decision is `supported`, `contradicted` or `not_established`. The verifier checks supplied bytes only: it does not fetch URLs or authenticate the authority a policy names.

## Documentation

| page | read it for |
| --- | --- |
| <a name="run"></a><a name="inputs-and-decisions"></a>[Running the verifier](https://github.com/probityai/probity-verify/blob/main/docs/running.md) | every example command, the case and policy inputs, and what each decision means |
| <a name="share-a-replayable-decision"></a><a name="index-decisions-and-disputes"></a>[Replayable decisions and the index](https://github.com/probityai/probity-verify/blob/main/docs/bundles-and-index.md) | ZIP bundles, replay, and the local index of decisions, challenges and supersessions |
| <a name="operand-lineage"></a><a name="authority-anchor"></a><a name="event-absence"></a>[Adapters](https://github.com/probityai/probity-verify/blob/main/docs/adapters.md) | what operand lineage, authority anchor and event absence check, and what they leave to the consumer |
| [Adapter plan](https://github.com/probityai/probity-verify/blob/main/docs/architecture.md) | the architecture and the adapters planned next |
| [Source coverage vectors](https://github.com/probityai/probity-verify/blob/main/vectors-source-coverage/README.md) and [operand-lineage vectors](https://github.com/probityai/probity-verify/blob/main/vectors-operand-lineage/README.md) | conformance cases with pinned bytes and expected decisions |

## License

Apache-2.0.
