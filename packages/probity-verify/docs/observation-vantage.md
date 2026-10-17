# Observation vantage

`event_absence/v2` adds consumer-selected producer and vantage pins to bounded event absence. The consumer names the observed party, invocation, event type, time interval and exact evidence hashes in a policy outside the supplied case.

```sh
git checkout 0f29bfa2ad160496eccb643e67921937837d3636
uv run probity-verify examples/event-absence-v2/covered/case.json \
  --policy examples/event-absence-v2/covered/policy.json
uv run python examples/event-absence-v2/generate.py --check
```

The retained examples are authored synthetic records from [a489590a](https://github.com/probityai/probity-verify/commit/a489590aa537b46f54caddb552b4f6d1464c2565). The generator reproduces all 12 original JSON files byte for byte; its manifest records their hashes.

| example | decision | reason |
| --- | --- | --- |
| `covered` | `supported` | the selected separate producer reports complete visibility and no matching event |
| `observed-write` | `contradicted` | a matching write is present, despite a named coverage gap |
| `self-reported-write` | `not_established` | the consumer selected a self-reported observation |

The observation record must match the consumer's producer, vantage, invocation and interval. A record cannot upgrade a `self_reported` policy pin. Missing bindings, capability visibility or complete coverage leave absence unestablished. Passing packets report both the vantage check and the event check as met.

`independent` here is a selected vantage label. Verify compares supplied bytes and labels. The consumer establishes the operator's identity, capture coverage and custody through its own authentication and review process.

## Run the installed witness

The [Observer operator profile at 0770e031](https://github.com/probityai/agent-evidence-observer/tree/0770e0311903d2f658dba04644805e3449a4f622/interop/witness-operator-2026-10-03) provides a separate installed operator, producer and reader. Its [configuration guide](https://github.com/probityai/agent-evidence-observer/blob/0770e0311903d2f658dba04644805e3449a4f622/interop/witness-operator-2026-10-03/PROFILE.md) covers key generation, the selected client UID, a private store and a retained head outside that store.

On a Linux host with Python 3.12, uv and permission to run the finite UID controls:

```sh
git clone https://github.com/probityai/agent-evidence-observer
cd agent-evidence-observer
git checkout 0770e0311903d2f658dba04644805e3449a4f622
bash interop/witness-operator-2026-10-03/verify_install.sh \
  "$PWD/witness-evidence"
```

The host selects the public keys, source hashes, case population and prior heads in `native/host-policy.json`, outside `native/packet`. The installed reader authenticates signed histories, receipts and terminal effect packets before reporting process state, committed effects and publication decisions separately.

| finite control | expected result |
| --- | --- |
| permit | one committed write, signed terminal, release |
| failure after the write | one committed write, signed terminal, withhold |
| unavailable before admission | no write, no registered interval, withhold |
| unavailable after the write | one retained target effect, missing terminal, withhold |
| lost acknowledgment | retry reuses the persisted begin receipt, withhold |
| rollback, fork, missing ledger, wrong key or peer | refuse without changing durable state |

Retain the original ledger, signed heads, selected host policy, wheel bytes and source pins. Recheck a restored store against the retained head before resuming it. An unsigned summary stays separate from the signed evidence it summarizes.

The [current native run](https://github.com/probityai/agent-evidence-observer/actions/runs/37213667494) is author-operated PEER work with a separate producer UID. An outside operator's acceptance, keys and custody remain pending. Keep this population separate from the synthetic Verify examples and select `self_reported` for author-operated custody.
