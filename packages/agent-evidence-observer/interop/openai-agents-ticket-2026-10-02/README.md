# OpenAI Agents SDK trace and protected ticket reference

This installable reference uses OpenAI Agents SDK **0.23.1**: actual `Runner`,
`ModelResponse`, `function_tool`, native agent/task/turn/function/generation spans,
and an application-owned `TracingProcessor`. A scripted native `Model` supplies
fixed synthetic calls. No provider API request, credential or model inference is
used. The protected HTTP/SQLite ticket service and the packet it produced are run by
the operator's runtime; this directory keeps that packet under [retained](retained)
(runtime sources withheld by digest, listed in `retained/WITHHELD-SOURCES.json`)
and the readers that verify it with public code only: `python verify_retained.py`.

The complete six-case plan freezes before execution. Permit commits revision 1;
revocation and changed arguments are refused with unchanged revision 0; a tool
failure before HTTP leaves revision 0. A tool failure after committed HTTP and
`MaxTurnsExceeded` after a committed tool both retain revision 1, while task status
stays **error** or **incomplete**. Task completion is distinct from dispatch
permission and authenticated effect completion. All nine scripted model calls,
six tool invocations and 36 native span lifecycles must remain represented.

## Install and replay the retained packet

Python 3.13 is tested. Runtime dependencies and the SDK are selected by hashes in
`requirements.lock`. The wheel is built from this directory and checked against
the selected source bytes.

```sh
python -m venv .plugin-env
.plugin-env/bin/python -m pip install --require-hashes -r requirements.lock
.plugin-env/bin/python -m pip install --no-deps ../..
.plugin-env/bin/python -m pip wheel --no-deps --no-build-isolation . --wheel-dir selected-wheels
.plugin-env/bin/python verify_wheels.py selected-wheels --selection source-selection.json
.plugin-env/bin/python -m pip install --no-deps selected-wheels/*.whl
.plugin-env/bin/python -m pip check
.plugin-env/bin/python verify_retained.py
```

The retained packet contains public grants, signed receipts, original HTTP bytes,
installed sources/license, the before-run plan, original SDK callback exports,
task errors, and bounded wall/process CPU counters. A 90-second serial execution
budget permits six attempts and at most nine model calls. SDK usage is zero by
construction; these counters measure integration execution, not language model
tokens or quality.

## Register the processor

For an application, install the plugin extra and register **before any trace or
agent run**. Compatibility is bounded to SDK 0.23.1 and this tested reference.

```python
from agents import set_trace_processors
from probity_openai.processor import LocalTraceProcessor

collector = LocalTraceProcessor()  # payload capture is off by default
set_trace_processors([collector])  # replaces the default OpenAI exporter
# Run your application's actual Agents SDK workflow here.
collector.force_flush()
collector.shutdown()              # idempotent; closes further capture
capture = collector.snapshot()
```

The export destination is the application-owned in-memory snapshot. There is no
network exporter, background queue or callback logging. Callbacks are serialized
with a lock. `force_flush` marks synchronous capture completion; `shutdown` flushes
and closes. Metadata mode retains identifiers, parent relationships, native times
and span types only. It omits workflow/model/operation names, inputs, outputs,
custom data, errors and user metadata. `capture_payloads=True` retains detached
native exports and can include sensitive inputs, outputs or errors. Only finite,
public synthetic fixtures opt in in this reference. It does not sanitize another
processor, previous buffers, framework logs or other application channels.

Replacing processors is essential: `add_trace_processor` would preserve the
default OpenAI exporter. Serialization and closed-processor failures increment a
fixed counter without retaining error payloads. The SDK can continue executing
when a processor fails; publication must refuse that incomplete capture. This
profile's reader requires zero capture failures, explicit flush and shutdown,
complete trace/span parentage and chronology, and every declared attempt.

## Install the separate reader and select host policy

```sh
python -m venv .reader-env
.reader-env/bin/python -m pip install --require-hashes -r requirements-reader.lock
.reader-env/bin/python -m pip install --no-deps selected-wheels/*.whl
.reader-env/bin/python -m pip check
.reader-env/bin/python -c "import importlib.util; assert importlib.util.find_spec('agents') is None and importlib.util.find_spec('openai') is None"
.reader-env/bin/probity-openai-read retained/fresh-run/packet --pins-file /path/to/host-selected-policy.json --withheld-sources retained/WITHHELD-SOURCES.json
```

The reader requires a separately supplied pins file: exact plan, source-manifest
and artifact-manifest SHA-256 values, profile and UTC consumer reference time.
The retained packet carries a demonstration pins file. Copying it is author-operated
replay, not an independent host selection. A host must select its own policy and
reader wheel hashes outside the candidate packet, run the reader as a gate, and
publish only on verified status and the full six-attempt population. An upgrade
selects new adapter source bytes and wheel hashes, builds into a new directory,
then replays retained packets before changing the host's selection. The protected
Observer baseline stays separately pinned; this reference creates no release tag.

The reader imports neither SDK nor OpenAI client and makes no network request.
It authenticates signed native effects separately from SDK trace records. Trace
records and source hashes remain same-operator provenance; they do not prove
independent effect custody. The profile's admission decision applies to this
bounded synthetic integration population, not arbitrary application traces.

## Reproduce compatibility and refusal controls

```sh
.plugin-env/bin/python -m pytest tests -q
.plugin-env/bin/ruff check --select E,F,I,C901 --config 'lint.mccabe.max-complexity=5' src tests verify_wheels.py verify_retained.py
```

The tests run the installed real SDK, check opt-in/default capture and callback
failures, retain failure after committed effects and incomplete tasks, and reject
omitted model/tool/span records, reordered/misparented traces, changed native
read-back, wrong scope/budgets, boolean numeric substitutions and unclosed capture
**after** artifact digest reselection. CI rebuilds source-proven standard wheels
and reproduces the retained packet report with a separate SDK-free reader. Original artifacts expire after 90 days;
retained capsules and exact run IDs must be recorded separately.

## Ownership and outside use

Probity maintains this reference through
[Observer issues](https://github.com/probityai/agent-evidence-observer/issues).
Compatibility changes require source selections, native runs and semantic refusal
checks. No outside acceptance, recurring host use or independent custody is
established by this author-operated reference.

The SDK's [current contribution policy](https://github.com/openai/openai-agents-python/blob/81f0ccf20c6e24063b9da36fa37f2bdb6a43d8d3/CONTRIBUTING.md)
restricts upstream PRs to collaborators. Tracing listing eligibility additionally
requires a released installable integration and independently verifiable continued
SDK use by an unaffiliated project, with an issue before any listing change. This
owned implementation is executable; directory inclusion remains a separate goal.

The first retained Ubuntu run is
[37053806564](https://github.com/probityai/agent-evidence-observer/actions/runs/37053806564),
from implementation head `faa22f16b459f10f53705a2d377754135db63e2b`.
Its original 367-entry artifact had SHA-256
`6f90d31bc08599b97641d6e6215a937b4b3ba5962953ce718e24c9ec904f53d2`; the retained copy
[native-fixture-37053806564.zip](retained/native-fixture-37053806564.zip) (356 entries,
SHA-256 `fa1c613c0ae74a2ef6d86c44b6b9dced7000ddf2981c114c5ad6e4439b4f0cc2`) omits the
runtime sources listed in `retained/WITHHELD-SOURCES.json`.
[recorded-run.json](recorded-run.json) separates the reviewed head, actual PR
merge execution source, independently selected target baseline, source-byte
matches, complete task/effect results and author-copied demonstration pins.
The SDK-free replay reproduces the original reader and report bytes exactly.
This native run and its comparisons were emitted together; it is not a blind
comparison or an independent custody record.
