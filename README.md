# probity-verify

An offline verifier that decides whether a claim holds against evidence bytes the consumer pinned, with adapters for source passages, operand lineage, authority captures, bounded absence and spend journals.

It's for auditors, incident reviewers and relying parties who receive a claim about an AI system and need a decision they can replay, not a report they have to trust.

## Quick start

PyPI publishes `probity-verify==0.1.0`. Python 3.10 or newer and [uv](https://docs.astral.sh/uv/) are needed. This source quick start retains its historical code and input snapshot; the [installed-package recipe](https://github.com/probityai/probity-verify/blob/main/docs/install.md) pins the released wheel separately:

```sh
git clone https://github.com/probityai/probity-verify && cd probity-verify
git checkout 588db582c50558f3e2a928be89ffc135188afcdb
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

## Use the decision in a check

All valid decisions exit 0, including `contradicted` and `not_established`. Exit 2 reports invalid input without a verdict. Require support for this claim by reading `decision`:

```sh
uv run probity-verify examples/source-coverage/case.json \
  --policy examples/source-coverage/policy-june.json --json > decision.json &&
uv run python - <<'PY'
import json

with open("decision.json") as stream:
    result = json.load(stream)
print(result["decision"], result["reason"])
raise SystemExit(0 if result["decision"] == "supported" else 1)
PY
```

This guard prints `contradicted selected_span_missing_from_record` and exits 1. `supported` means the stated claim passes the pinned policy's checks. Your application still owns authorization.

## Status

PyPI version 0.1.0 supplies the current verifier. Source version 0.1.1 adds packaged sample inputs; see [release instructions](https://github.com/probityai/probity-verify/blob/main/docs/RELEASING.md) for checked artifacts. Seven adapters ship: `brokered_file_write/v1`, `source_text_coverage/v1`, `operand_lineage/v1`, `authority_anchor/v1`, `event_absence/v1`, `event_absence/v2` and `spend_reservation/v1`. Each decision is `supported`, `contradicted` or `not_established`. The verifier checks supplied bytes only: it does not fetch URLs or authenticate the authority a policy names.

## Documentation

| page | read it for |
| --- | --- |
| [Install a pinned version](https://github.com/probityai/probity-verify/blob/main/docs/install.md) | install outside the source checkout and replay three sample decisions |
| [Choose a claim check](https://github.com/probityai/probity-verify/blob/main/docs/recipes.md) | select a task from checked recipes and retrieve exact commands and input digests |
| [Select a consumer adapter](https://github.com/probityai/probity-verify/blob/main/docs/adapter-api.md) | supply exact adapter versions through adjudication, bundle creation and replay |
| [Check a customer offer](https://github.com/probityai/probity-verify/blob/main/docs/customer-support-action.md) | compare a draft with raw company records and an exact manager approval |
| <a name="run"></a><a name="inputs-and-decisions"></a>[Running the verifier](https://github.com/probityai/probity-verify/blob/main/docs/running.md) | every example command, the case and policy inputs, and what each decision means |
| <a name="share-a-replayable-decision"></a><a name="index-decisions-and-disputes"></a>[Replayable decisions and the index](https://github.com/probityai/probity-verify/blob/main/docs/bundles-and-index.md) | ZIP bundles, replay, and the local index of decisions, challenges and supersessions |
| <a name="operand-lineage"></a><a name="authority-anchor"></a><a name="event-absence"></a>[Adapters](https://github.com/probityai/probity-verify/blob/main/docs/adapters.md) | what operand lineage, authority anchor and event absence check, and what they leave to the consumer |
| [Spend reservations](https://github.com/probityai/probity-verify/blob/main/docs/spend-reservation.md) | replay a pinned budget journal, refuse dispatch without an affordable reservation, and keep pending calls charged |
| [Observation vantage](https://github.com/probityai/probity-verify/blob/main/docs/observation-vantage.md) | select the producer and observation scope, replay bounded absence, and operate a witness with separate keys and retained heads |
| [Adapter plan](https://github.com/probityai/probity-verify/blob/main/docs/architecture.md) | the architecture and the adapters planned next |
| [A2A server and client](https://github.com/probityai/probity-verify/blob/main/docs/a2a.md) | send raw case bytes to an operator-configured verifier, or read a pinned Lab record |
| [Source coverage vectors](https://github.com/probityai/probity-verify/blob/main/vectors-source-coverage/README.md) and [operand-lineage vectors](https://github.com/probityai/probity-verify/blob/main/vectors-operand-lineage/README.md) | conformance cases with pinned bytes and expected decisions |

## License

Apache-2.0.
