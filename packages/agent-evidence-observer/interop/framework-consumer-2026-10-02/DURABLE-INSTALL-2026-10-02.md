# Install the additive durable LangGraph reader

The standard `probity-langgraph-ticket-reader`0.0.2 wheel preserves the original
`probity-langgraph-read` command and historical reader. It adds the
explicit `probity-langgraph-durable-read` command for the separately selected
`probity-langgraph-durable-restart-v0` profile. Each command refuses the other's
packet. Profile selection comes from the reviewed command/host policy, never from
an untrusted packet's own profile field.

The `FRAMEWORK-DURABLE-CONSUMER-CONTRACT-2026-10-02.json` selects every packaged
Observer file, the LangGraph reader sources, both CLI wrappers, wheel metadata, the
dependency lock and the builder. The builder verifies these selected bytes, and that
`src/probity_observer` holds exactly the selected files, before producing normal
wheels. It copies only offline readers, with no graph runner/worker, SQLite
checkpoint package, LangGraph or Pydantic AI dependency. `record_contracts.py`
re-records the selection after a change.

Build from `packages/agent-evidence-observer` of a reviewed checkout, with the
same hash-selected reader/build requirements as the original package:

```sh
set -eu
python -m venv .durable-reader-env
.durable-reader-env/bin/python -m pip install --require-hashes --only-binary=:all: -r interop/framework-consumer-2026-10-02/FRAMEWORK-CONSUMER-REQUIREMENTS-2026-10-02.lock
PATH="$PWD/.durable-reader-env/bin:$PATH" bash interop/framework-consumer-2026-10-02/FRAMEWORK-DURABLE-CONSUMER-BUILD-2026-10-02.sh "$PWD" "$PWD/durable-reader-wheels"
.durable-reader-env/bin/python -m pip install --no-index --no-deps --upgrade durable-reader-wheels/*.whl
.durable-reader-env/bin/python -m pip check
.durable-reader-env/bin/probity-langgraph-durable-read SELECTED_PACKET --pins-file SEPARATELY_REVIEWED_PINS
```

The selected plan/artifact digests and historical evaluation time remain mandatory.
No command automatically accepts the producer's convenience pin file. A historical
read reconstructs the selected validity window; it does not authorize a new effect
or establish current authority. Keep source selection, packet/pin policy and any
host gate policy under the host's review and retain every per-case disposition.

The publication wrapper's original `probity-framework-host-gate-v1` retains only
its historical `langgraph` and `pydantic` reader enums. Durable operation explicitly
selects new schema `probity-framework-host-gate-v2`, reader `langgraph-durable`,
profile `probity-langgraph-durable-restart-v0` and exactly six attempts. It freezes
separately supplied pin bytes before starting the installed child. The reader and
gate keep pending intent incomplete and missing-state controls refused; admitting
the complete bounded record does not turn these individual outcomes into success.
See [the host gate](../consumer-host-2026-10-02/README.md) and its durable template.

The upgrade workflow builds and installs the 0.0.1 historical reader wheels from the
checkout, replays the retained packets and the 36 installed/gate controls, then
normally upgrades the same environment to 0.0.2 and runs the combined durable
acceptance/refusal controls. The installed `probity-langgraph-read` command keeps its
original arguments and gains the optional `--withheld-sources` list. The original
two-reader upgrade receipt remains in `durable-install-verification.json` as history.
