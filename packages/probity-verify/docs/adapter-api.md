# Select an adapter for one consumer

Use the Python API to supply an additional claim adapter for one call:

```python
from probity_verify import adjudicate
from your_application.checks import check_selected_claim

decision = adjudicate(
    case,
    consumer_policy,
    artifact_root,
    adapters={"company_claim/v1": check_selected_claim},
)
```

The policy selects the exact `claim_type` in its case assessment. An adapter
for `company_claim/v1` cannot handle a request for `company_claim/v2` unless the
consumer supplies that version separately. The kernel does not infer aliases,
import plugins, or select code from a case or policy.

The keyword-only `adapters` argument must be a mapping from names to callables.
Names use `name/vN`: an ASCII letter followed by ASCII letters, digits,
underscores, dots or hyphens, then `/v` and a positive decimal version. A leading
zero is invalid. Each callback accepts `(case, policy, artifact_root)`.

The kernel snapshots the existing registry and the supplied mapping before it
reads the claim selection. It rejects collisions with registered claim types
and reserved built-in names. It does not change either mapping. A selection
affects only that call. The legacy `probity_verify.core.ADAPTERS` dictionary
remains available for existing callers; changes to that dictionary affect
later snapshots.

An adapter returns `schema_version: probity-decision/v1`, matching `case_id`
and `claim_type`, a `decision`, a `reason`, a `scope` object and a `checks` list.
Decisions are `supported`, `contradicted` or `not_established`. The kernel checks
the common envelope and adds the SHA-256 binding to the consumer policy.
The adapter must validate its own evidence contract, required checks and policy
rules. A policy hash does not prove that the adapter applied those rules.

The callback receives deep copies of the case and policy. The kernel captures
their JSON bytes and the policy digest before the callback. A callback that
changes either control value raises `CaseError`, even if it returns a valid
decision envelope. The caller's case and policy remain intact. This check
covers control values, including artifact selectors, rather than changes to
external files or other process state.

Malformed selections and invalid envelopes raise `CaseError` without a
decision. Missing evidence can produce `not_established` only when the selected
adapter defines that valid evidence state.

## Carry the selection through a bundle

Supply the same explicit mapping when you create and replay a bundle:

```python
from pathlib import Path
from probity_verify.bundle import create_bundle, replay_bundle

selected = {"company_claim/v1": check_selected_claim}
bundle_path = Path("decision.zip")
create_bundle(case_path, policy_path, bundle_path, adapters=selected)
replayed = replay_bundle(bundle_path, adapters=selected)
```

The bundle carries the case, policy, artifact bytes and decision. It does not
carry executable adapter code. The recipient selects and pins that code
separately. A bundle with an additional claim type cannot replay without the
matching explicit adapter selection.

Callbacks are trusted Python code. This API does not authenticate callbacks,
establish evidence provenance or isolate code. Select them in application code,
outside producer-supplied records. CLI and bundle entry points do not inherit a
call's adapter mapping automatically. The CLI does not load additional adapters
from record fields, archive members or module names.
