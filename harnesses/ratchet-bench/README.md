# ratchet-bench

The environment in which `ratchet.bench` (the AgentDojo, tau-bench, tau2-bench, Terminal-Bench and
ToolSandbox adapters of [probity-ratchet](../../packages/probity-ratchet/README.md)) runs, is tested and is
type-checked.

It is for anyone reproducing the ratchet's benchmark results. It is not published: the benchmarks are not
on PyPI under their own names, so this directory holds their git sources, two dependency overrides and its
own `uv.lock`, apart from the repository's one root lock.

```sh
cd packages/probity-ratchet
uv sync --project ../../harnesses/ratchet-bench --locked --all-groups
uv run --project ../../harnesses/ratchet-bench python -m ratchet.bench.agentdojo --help
uv run --project ../../harnesses/ratchet-bench python -m pytest -o addopts= -W error -p no:langsmith_plugin tests/bench
```

The ratchet and its case suite install editable from `packages/`, so a change there is tested here at once.
The `bench` job of `.github/workflows/package-ratchet.yml` runs the tests and the type check in this
environment. Run commands and result pages: [RUNNING.md](../../packages/probity-ratchet/docs/RUNNING.md).
