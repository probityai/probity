# Replayable decisions and the decision index

## Share a replayable decision

```sh
uv run probity-bundle create examples/source-coverage/case.json \
  --policy examples/source-coverage/policy-june.json --output decision.zip
uv run probity-bundle replay decision.zip
```

The ZIP contains the case, consumer policy, bound artifact bytes, and decision.
Replay checks the bindings, recomputes the decision, and rejects unsafe archive
members. Only fully bound cases can be bundled. Identical inputs produce
identical ZIP bytes. The ZIP is unsigned; its holder can replace the policy,
artifacts, and decision together. A recipient must establish the policy and
witness provenance separately.

Malformed input exits 2. A valid decision exits 0. The packet includes the
policy digest, artifact bindings, checks, reason, and scope.

For a consumer-specific claim, pass the same explicit adapter mapping to
`create_bundle(..., adapters=selected)` and `replay_bundle(..., adapters=selected)`.
Creation snapshots that mapping for its decision and self-replay. A bundle
cannot import or select code from its own records. The generic CLI handles
built-in claims. See [adapter selection](adapter-api.md) and the
[customer offer example](customer-support-action.md).

## Index decisions and disputes

Keep replayable decisions and disputes in a local index:

```sh
uv run probity-bundle create examples/source-coverage/case.json \
  --policy examples/source-coverage/policy-june.json --output june.zip
uv run probity-bundle create examples/source-coverage/case.json \
  --policy examples/source-coverage/policy-april.json --output april.zip
uv run probity-index add decisions.db june.zip
uv run probity-index add decisions.db april.zip
uv run probity-index verify decisions.db
```

Each add prints an event ID. Use those IDs to record a dispute or replacement:

```sh
uv run probity-index challenge decisions.db \
  --target ID --counter ID --basis "Why this decision is disputed"
uv run probity-index supersede decisions.db \
  --target OLD --replacement NEW --basis "Why the new decision replaces it"
```

Verification replays every bundle and checks the references. A challenge does
not change a verdict. A supersession records the operator's stated reason;
matching case IDs do not prove that two policies express the same claim.
The SQLite file is unsigned and its operator can replace its history.
It does not authenticate witnesses or challengers.

See the [adapter plan](architecture.md) and
[AIID field note](../examples/source-coverage/AIID-FIELD-NOTE.md).
The executable fixtures contain invented text.

The [source coverage vectors](../vectors-source-coverage/README.md) test six
boundary cases with pinned fixture bytes, expected decisions, and reasons.
Run them with `uv run --extra test pytest vectors-source-coverage/tests`.
For `source_text_coverage/v1`, the CLI accepts either the existing
`probity-case/v1` and `probity-policy/v1` pair or the neutral
`source-coverage-case/v1` and `source-coverage-policy/v1` pair. Mixed pairs fail.

The [operand-lineage vectors](../vectors-operand-lineage/README.md) test ten
arithmetic and evidence-boundary cases against an external CLI.
