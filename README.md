# Probity

[![CI](https://img.shields.io/github/actions/workflow/status/probityai/probity/ci.yml?label=CI)](https://github.com/probityai/probity/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/probity-verify?label=probity-verify)](https://pypi.org/project/probity-verify/)
[![Downloads](https://static.pepy.tech/badge/probity-verify)](https://pepy.tech/projects/probity-verify)
[![Licence](https://img.shields.io/github/license/probityai/probity)](LICENSE)
[![Stars](https://img.shields.io/github/stars/probityai/probity?style=flat)](https://github.com/probityai/probity)

Open tools that check claims about AI agents against evidence you pinned: an offline verifier today, with the observer joining this repository. The standard layer (corpus, vocabulary, admission rules and crates) lives in https://github.com/probityai/agent-evidence.

It's for auditors, incident reviewers and relying parties who need a decision they can replay, and for tool authors who want their records checked the same way.

Install the released verifier: `uv add probity-verify==0.2.4`, then `pip install probity-verify==0.2.4`.

Verified by Probity (github.com/probityai/probity). The `probityai` command line is released: `uv add probityai==0.1.0`, then `pip install probityai==0.1.0`.

## Quick start

Check a sample claim with the released package. You need Python 3.11 or newer and [uv](https://docs.astral.sh/uv/); there is nothing to clone:

```sh
samples="$(uvx --from probity-verify==0.2.4 python -c 'import importlib.resources as r; print(r.files("probity_verify") / "samples")')"
uvx probity-verify==0.2.4 "$samples/case.json" --policy "$samples/policy-june.json"
```

It prints a decision packet that opens:

```text
Probity decision packet v1
Case: "source-coverage-demo"
Claim: source_text_coverage/v1
Decision: contradicted
Reason: selected_span_missing_from_record
```

A selected passage is in the source capture but missing from the stored report. Swap in `policy-april.json` for `not_established`, or `case-complete.json` with `policy-complete.json` for `supported`.

## Status

| member | what it is | released |
| --- | --- | --- |
| [packages/probity-verify](packages/probity-verify/README.md) | offline verifier: `supported`, `contradicted` or `not_established` for a claim against pinned bytes | 0.2.2 on PyPI |
| [packages/observer](packages/observer/README.md) | records what an agent run did into pinned evidence the verifier can check | 0.1.1 on PyPI (`agent-evidence-observer`) |
| [packages/ratchet](packages/ratchet/README.md) | signed, replayable receipts for improving an agent against held-out cases | 0.2.1 on PyPI (`probity-ratchet`) |
| [packages/probityai](packages/probityai/README.md) | the `probityai` command; `probityai verify` today, each member adds its own subcommand | 0.1.0 on PyPI (`probityai`) |

## Work on the repository

```sh
uv sync --all-packages --all-extras
uv run python -m pytest
```

## Documentation

| page | read it for |
| --- | --- |
| [probity-verify](packages/probity-verify/README.md) | the verifier, its adapters and its recipes |
| [Repository layout](docs/architecture/MONOREPO.md) | the workspace, the `probityai` command seam, CI and releases |
| [Agent instructions](AGENTS.md) | commands to run before a change |
| [Contributing](CONTRIBUTING.md) | reporting a problem and opening a pull request |

## License

Apache-2.0, per directory: each member carries its own `LICENSE`.
