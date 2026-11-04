# Installed framework readers

These dedicated wheels reconstruct the retained LangGraph and Pydantic AI native
packets without installing either agent framework. The builder checks every selected
source byte, and the exact population of `src/probity_observer`, against
`FRAMEWORK-CONSUMER-CONTRACT-2026-10-02.json` before creating standard wheels, and it
builds the observer wheel from the same tree. After changing a selected file, run
`python record_contracts.py PACKAGE_DIR` to re-record both contracts.

```sh
python -m venv .reader-env
.reader-env/bin/python -m pip install --require-hashes -r interop/framework-consumer-2026-10-02/FRAMEWORK-CONSUMER-REQUIREMENTS-2026-10-02.lock
PATH="$PWD/.reader-env/bin:$PATH" bash interop/framework-consumer-2026-10-02/FRAMEWORK-CONSUMER-BUILD-2026-10-02.sh "$PWD" "$PWD/reader-wheels"
.reader-env/bin/python -m pip install --no-deps reader-wheels/*.whl
.reader-env/bin/python -m pip check
```

Run these from `packages/agent-evidence-observer`.

`probity-langgraph-read PACKET --pins-file POLICY` reconstructs six retained
checkpoint/interrupt/resume cases. `probity-pydantic-read PACKET --pins-file POLICY`
reconstructs five typed-tool/retry/error cases. Both retain the native report's
per-case outcomes and ceilings. Each command takes an optional
`--withheld-sources FILE` for packets that keep producer sources as digests only. The
host workflow template requires an exact profile, verified status and complete
denominator before publication.

The retained ZIPs in `retained/` are the original successful Ubuntu artifacts with the
producing operation's source files removed: the operation is run by the operator's
runtime, and the packets keep only each file's SHA-256 in
`retained/WITHHELD-SOURCES.json`, keyed by archive and member. The readers accept an
omitted source only when the list gives exactly the digest the packet's manifest
records. LangGraph comes from [run 37003859466](https://github.com/probityai/agent-evidence-observer/actions/runs/37003859466)
and Pydantic from [run 37003617436](https://github.com/probityai/agent-evidence-observer/actions/runs/37003617436).
The SHA-256 values of the retained archives are selected in `test_installed_readers.py`
and `test_durable_installed_reader.py`. The tests replay the full original packets
through installed commands, require explicit pins, and refuse semantic substitutions
even after an adversary reselects artifact hashes.
`python -I verify_retained.py` replays every retained packet with the public readers
and compares each report with the retained report bytes.

```sh
.reader-env/bin/python -m pip install pytest==8.4.2
.reader-env/bin/python -m pytest -q interop/framework-consumer-2026-10-02/test_installed_readers.py
```

This replays existing native executions. It does not make a new model or framework
call. Fixture pins copied by Probity are local test selections; a host must select
its own policy. In-memory LangGraph checkpoints do not establish process-restart
durability. Synthetic ticket effects, same-operator custody and scripted Pydantic
FunctionModel provenance remain explicit in each report. Host CI adoption and
independent effect custody require separate records. No release tag is created.

The Pydantic AI command reads the retained packet with the framework version that
packet recorded (1.68.0), set in `probity_pydantic_historical_cli.py`. The
[additive durable reader upgrade](DURABLE-INSTALL-2026-10-02.md) installs 0.0.2 with
separate explicit commands and its own source selection.
