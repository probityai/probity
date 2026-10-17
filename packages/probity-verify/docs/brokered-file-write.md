# Check broker-recorded file completion

Use `brokered_file_write/v1` to check a typed report against a selected Observer
v0 file-write history. The report's exact boolean `completion_recorded` asserts
whether that history records one request, path and content digest. It does not
assert arbitrary physical execution or successful workflow completion.

Install Verify from the [pinned source recipe](install.md). Run a synthetic wire
example from the checkout root:

```sh
probity-verify examples/brokered-file-write/recorded/case.json \
  --policy examples/brokered-file-write/recorded/policy.json --json
```

The [false-negative case](../examples/brokered-file-write/false-negative/case.json)
contradicts a report that denies the recorded completion. The
[missing-terminal case](../examples/brokered-file-write/missing-terminal/case.json)
keeps uncertainty despite retained target bytes. The generator's private seeds
are public test-only material. These three examples are synthetic wire controls.
They do not establish native workload execution or independent operation.

## Select original evidence

Keep the existing `probity-case/v1` container. Its artifacts bind relative paths,
exact lengths and SHA-256. Keep a separate `probity-policy/v1` consumer policy.
The assessment needs exactly `claim_type`, `report`, `broker_witness`, `context`
and `retained_target`. Each selector has exactly `artifact` and `sha256`.

The report artifact has exactly `schema_version: brokered-file-write-report/v1`,
`interval_id`, `request_id`, `path`, `content_sha256` and `completion_recorded`.
The last field must be an actual JSON boolean. A prose report needs an explicitly
selected typed assertion and separately retained original prose. Verify does not
infer that conversion.

The consumer context pins `interval_id`, `request_id`, `path`, `authority_scope`
and `intended_content_sha256`. Intended content stays separate from claimed and
recorded content. The broker witness pins distinct `observer_key` and
`witness_key`, literal `witness_scope: PEER`, and an explicit `record` state.
Keys come from the consumer's trust decision, not candidate record key IDs.

| State | Required record fields | Result boundary |
| --- | --- | --- |
| `sealed` | `state`, `packet`, `history`, `ledger`, `head` | Compare a fully authenticated bounded history with the assertion. |
| `missing_terminal` | `state`, `history`, `ledger`, `head` | Check supplied originals and retain `not_established`. |

For native checkpoint-only sealed packets, `ledger` and `head` are both null.
For packets with `ledgerReceipt`, select both original artifacts. Verify checks
receipt authentication, roles, counts, hashes, opening/terminal joins and log
inclusion. A selected signed ledger head binds a retained prefix. This does not
establish latest-head freshness, global uniqueness or complete outside custody.

The supported native authority has exactly `intervalId`, `scope` and
`operation: write-file`. This version admits the original minimal authority
profile. Measured-authority, HTTP/SQLite, Inspect and DSSE profiles need their own
explicit contracts. They are refused here.

Native records and the typed report use ASCII JSON bytes. The report can use
ASCII whitespace. Verify decodes that declared domain before JSON parsing and
refuses UTF-16, UTF-32 and byte order marks. Consumer control JSON uses UTF-8.
It does not infer another wire encoding.

Verify uses a direct `cryptography` dependency for Ed25519. It independently
checks the original restricted ASCII JSON bytes, domain-separated signatures,
prior commitment, authority digest, history chain, write intents, request/path/
content/root joins, opening and terminal checkpoints, and literal claim writes.
The `authorizationBinding` extension must match its signed native claim and
exact completed request. Its `grantDigest` remains a signed reference. This check
does not establish issuer permission or pre-effect witnessed grant timing.

## Keep conclusions separate

An authenticated matching completion supports true and contradicts false.
A complete sealed gap-free selected history without that completion supports
false and contradicts true. These conclusions apply to the recorded broker
population. A known gap prevents a negative conclusion. Missing required files
or a witnessed terminal yield `not_established`. A typed missing-terminal state
can contain a pending intent without inventing its result.

Malformed data, unsafe reads, bad signatures and inconsistent authenticated
history refuse with exit 2 and no verdict. A missing terminal is a valid evidence
state, not a catch-all for invalid records.

`retained_target` is either null or an artifact selector with `captured_at` in UTC
seconds. The decision reports its selected byte digest separately. Changed later
target bytes do not disprove an earlier recorded completion. A surviving file
alone does not prove recorded completion. Neither a packet nor a file changes
the worker's actual process exit or proves workflow success.

Records have a 1 MiB byte budget, at most 512 history/ledger entries, depth 32 and
32,768 structural nodes. Consumer control files also have bounded JSON parsing
and use the [secure artifact read boundary](running.md#artifact-read-boundary).
These limits are explicit refusals. No alternate format or portability alias is
inferred. `execution_observation/v1` remains a separate broader proposal.

## Preserve and check a capture

Retain the original packet, JSONL history, ledger/head when selected, and any
target readback before authoring report assertions or consumer policies. Preserve
actual worker streams and process status separately. Retain the Verify source
revision, wheel, installed dependency versions and complete decision streams.
The policy digest in every decision binds the exact consumer selection.

Run `uv run python examples/brokered-file-write/generate.py --check` to check the
synthetic examples. Run `uv run pytest` and both original conformance corpora
after an adapter change. The [recipe index](recipes.json) binds current source and
inputs. A passing authored check does not establish outside adoption, an
independent operator, a paying customer or a registered research result.


## Run actual local crash controls

Install Observer in a separate producer environment from an immutable public
source revision. Install the Verify wheel in a consumer environment with its
own direct dependencies. Run the controller from this checkout:

```sh
python3 scripts/check-brokered-file-write.py \
  --producer-python /path/to/producer/bin/python \
  --verifier /path/to/consumer/bin/probity-verify \
  --output /path/to/new-capture-directory
```

The controller retains three real producer exits. Normal completion exits zero.
A hard exit after the sealed packet exits 74 and retains a recorded completion.
A hard exit after the write but before the terminal checkpoint exits 74 and
keeps `not_established`. Both true and false typed reports run through the
installed CLI. The producer generates local ephemeral keys and retains public
selections before the broker call. It alone imports Observer. The controller
and Verify consumer do not import Observer.

The optional `--original-capture` selects the exact retained public witness ZIP
with SHA-256 `2b4f04dcc0c0d5e7c1a4a68288fd92457676db50da3da631a348ba0d4940605e`.
Its source and consumed file digests are checked before replay. Original process
records remain separate from new assertions and decisions. The original
`failed-after` exit 7 and HTTP crash captures remain distinct historical cases.
These controls prove the stated local behavior, not independent operation.


The maintained [native CI job](../.github/workflows/brokered-file-write.yml)
uses the same controller and an immutable public Observer source revision. Its
artifact keeps original evidence, actual worker/reader streams, source, wheels
and dependency records. `manifest.json` declares paths, lengths and SHA-256
relative to its own parent. Resolve every process stream from its process
record's parent. CI status and the actual artifact contents must both be checked
before accepting a retained run. A source file read at invocation binds that
file, not authenticated executing-byte provenance.
