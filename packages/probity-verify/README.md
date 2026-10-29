# probity-verify

[![PyPI](https://img.shields.io/pypi/v/probity-verify.svg)](https://pypi.org/project/probity-verify/)
[![Downloads (PePy)](https://static.pepy.tech/badge/probity-verify)](https://pepy.tech/projects/probity-verify)

An offline verifier that decides whether a claim holds against evidence bytes the consumer pinned, with adapters for source passages, operand lineage, authority captures, bounded absence and spend journals.

It's for auditors, incident reviewers and relying parties who receive a claim about an AI system and need a decision they can replay, not a report they have to trust.

Install the released package: `pip install probity-verify==0.2.3`.

## Quick start

Check a sample claim with the released package. You need Python 3.11 or newer and [uv](https://docs.astral.sh/uv/); there is nothing to clone, and a cold run takes about seven seconds. Version 0.2.3 ships the sample case and policies inside the wheel:

```sh
samples="$(uvx --from probity-verify==0.2.3 python -c 'import importlib.resources as r; print(r.files("probity_verify") / "samples")')"
uvx probity-verify==0.2.3 "$samples/case.json" --policy "$samples/policy-june.json"
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

A selected passage is in the source capture but missing from the stored report. The packet goes on to list every artifact binding and check. Swap in `policy-april.json` for `not_established`, or `case-complete.json` with `policy-complete.json` for `supported`. To run from a pinned source checkout instead, see [Install a pinned version](https://github.com/probityai/probity/blob/main/packages/probity-verify/docs/install.md#run-the-source-quick-start).

## Use the decision in a check

All valid decisions exit 0, including `contradicted` and `not_established`. Exit 2 reports invalid input without a verdict. Require support for this claim by reading `decision`:

```sh
uvx probity-verify==0.2.3 "$samples/case.json" \
  --policy "$samples/policy-june.json" --json > decision.json &&
python3 - <<'PY'
import json

with open("decision.json") as stream:
    result = json.load(stream)
print(result["decision"], result["reason"])
raise SystemExit(0 if result["decision"] == "supported" else 1)
PY
```

This guard prints `contradicted selected_span_missing_from_record` and exits 1. `supported` means the stated claim passes the pinned policy's checks. Your application still owns authorization.

## Status

Version 0.2.3 is on PyPI and ships the sample inputs used above. See [release instructions](https://github.com/probityai/probity/blob/main/packages/probity-verify/docs/RELEASING.md) for checked artifacts and the [changelog](https://github.com/probityai/probity/blob/main/packages/probity-verify/CHANGELOG.md) for what each release changed. Thirteen adapters ship in 0.2.3: `brokered_file_write/v1`, `source_text_coverage/v1`, `operand_lineage/v1`, `authority_anchor/v1`, `event_absence/v1`, `event_absence/v2`, `spend_reservation/v1`, the done-receipt checks for coding agents `protected_paths/v1`, `acceptance_observed/v1`, `tool_claim_match/v1`, `completion_claim/v1` and `probe_observed/v1`, and `done_receipt/v2`, which derives a done receipt's two verdicts again from them: whether the work is done and whether the agent gamed the process. Each decision is `supported`, `contradicted` or `not_established`. The verifier checks supplied bytes only: it does not fetch URLs or authenticate the authority a policy names.

## Documentation

| page | read it for |
| --- | --- |
| [Start a project](https://github.com/new?template_name=evidence-starter&template_owner=probityai) | a template that checks an observer-recorded write with this verifier, pinned and in CI |
| [Install a pinned version](https://github.com/probityai/probity/blob/main/packages/probity-verify/docs/install.md) | install outside the source checkout and replay three sample decisions |
| [Choose a claim check](https://github.com/probityai/probity/blob/main/packages/probity-verify/docs/recipes.md) | select a task from checked recipes and retrieve exact commands and input digests |
| [Select a consumer adapter](https://github.com/probityai/probity/blob/main/packages/probity-verify/docs/adapter-api.md) | supply exact adapter versions through adjudication, bundle creation and replay |
| [Check a customer offer](https://github.com/probityai/probity/blob/main/packages/probity-verify/docs/customer-support-action.md) | compare a draft with raw company records and an exact manager approval |
| <a name="run"></a><a name="inputs-and-decisions"></a>[Running the verifier](https://github.com/probityai/probity/blob/main/packages/probity-verify/docs/running.md) | every example command, the case and policy inputs, and what each decision means |
| <a name="share-a-replayable-decision"></a><a name="index-decisions-and-disputes"></a>[Replayable decisions and the index](https://github.com/probityai/probity/blob/main/packages/probity-verify/docs/bundles-and-index.md) | ZIP bundles, replay, and the local index of decisions, challenges and supersessions |
| <a name="operand-lineage"></a><a name="authority-anchor"></a><a name="event-absence"></a>[Adapters](https://github.com/probityai/probity/blob/main/packages/probity-verify/docs/adapters.md) | what operand lineage, authority anchor and event absence check, and what they leave to the consumer |
| [Done-receipt checks](https://github.com/probityai/probity/blob/main/packages/probity-verify/docs/done-receipt.md) | check a coding agent's "done" against protected paths, an outside acceptance grade and its claimed command runs, with vantage and witness scope on every verdict |
| [Spend reservations](https://github.com/probityai/probity/blob/main/packages/probity-verify/docs/spend-reservation.md) | replay a pinned budget journal, refuse dispatch without an affordable reservation, and keep pending calls charged |
| [Observation vantage](https://github.com/probityai/probity/blob/main/packages/probity-verify/docs/observation-vantage.md) | select the producer and observation scope, replay bounded absence, and operate a witness with separate keys and retained heads |
| [Adapter plan](https://github.com/probityai/probity/blob/main/packages/probity-verify/docs/architecture.md) | the architecture and the adapters planned next |
| [A2A server and client](https://github.com/probityai/probity/blob/main/packages/probity-verify/docs/a2a.md) | send raw case bytes to an operator-configured verifier, or read a pinned Lab record |
| [Source coverage](https://github.com/probityai/probity/blob/main/packages/probity-verify/vectors-source-coverage/README.md), [operand-lineage](https://github.com/probityai/probity/blob/main/packages/probity-verify/vectors-operand-lineage/README.md) and [done-check vectors](https://github.com/probityai/probity/blob/main/packages/probity-verify/vectors-done-checks/README.md) | conformance cases with pinned bytes and expected decisions |

## License

Apache-2.0.
