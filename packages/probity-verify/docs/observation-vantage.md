# Observation vantage

`event_absence/v2` adds consumer-selected producer and vantage pins to bounded event absence. The consumer names the observed party, invocation, event type, time interval and exact evidence hashes in a policy outside the supplied case.

```sh
git checkout 0f29bfa2ad160496eccb643e67921937837d3636
uv run probity-verify examples/event-absence-v2/covered/case.json \
  --policy examples/event-absence-v2/covered/policy.json
uv run python examples/event-absence-v2/generate.py --check
```

The retained examples are authored synthetic records from [a489590a](https://github.com/probityai/probity/commit/a489590aa537b46f54caddb552b4f6d1464c2565). The generator reproduces all 12 original JSON files byte for byte; its manifest records their hashes.

| example | decision | reason |
| --- | --- | --- |
| `covered` | `supported` | the selected separate producer reports complete visibility and no matching event |
| `observed-write` | `contradicted` | a matching write is present, despite a named coverage gap |
| `self-reported-write` | `not_established` | the consumer selected a self-reported observation |

The observation record must match the consumer's producer, vantage, invocation and interval. A record cannot upgrade a `self_reported` policy pin. Missing bindings, capability visibility or complete coverage leave absence unestablished. Passing packets report both the vantage check and the event check as met.

`independent` here is a selected vantage label. Verify compares supplied bytes and labels. The consumer establishes the operator's identity, capture coverage and custody through its own authentication and review process.

## Check the retained witness run

The installed witness run, with its separate operator, producer and reader, is run by the operator's runtime. Its retained capture lives in [witness-operator-2026-10-03/retained](https://github.com/probityai/probity/tree/main/packages/agent-evidence-observer/interop/witness-operator-2026-10-03/retained), with a [configuration guide](https://github.com/probityai/probity/blob/main/packages/agent-evidence-observer/interop/witness-operator-2026-10-03/PROFILE.md) covering key generation, the selected client UID, a private store and a retained head outside that store.

On a Linux host with Python 3.12, uv and the public Observer reader installed, replay the retained capture:

```sh
git clone https://github.com/probityai/probity
cd probity/packages/agent-evidence-observer
python interop/witness-operator-2026-10-03/verify_retained.py
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

The retained native run is author-operated PEER work with a separate producer UID. An outside operator's acceptance, keys and custody remain pending. Keep this population separate from the synthetic Verify examples and select `self_reported` for author-operated custody.
