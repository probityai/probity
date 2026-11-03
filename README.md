# Probity

[![CI](https://img.shields.io/github/actions/workflow/status/probityai/probity/ci.yml?label=CI)](https://github.com/probityai/probity/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/probity-verify?label=probity-verify)](https://pypi.org/project/probity-verify/)
[![Downloads](https://static.pepy.tech/badge/probity-verify)](https://pepy.tech/projects/probity-verify)
[![Licence](https://img.shields.io/github/license/probityai/probity)](LICENSE)
[![Stars](https://img.shields.io/github/stars/probityai/probity?style=flat)](https://github.com/probityai/probity)

Open tools that check claims about AI agents against evidence you pinned: an offline verifier, an observer that records agent runs, and the tools around them. The conformance corpus, vocabulary and admission rules live in https://github.com/probityai/agent-evidence-vectors.

<p align="center"><picture><source media="(min-width: 1012px)" srcset="https://raw.githubusercontent.com/probityai/probityai.github.io/main/figures/f3-missing-not-clean/5/wide-auto.svg"><img src="https://raw.githubusercontent.com/probityai/probityai.github.io/main/figures/f3-missing-not-clean/5/narrow-auto.svg" alt="A report.txt of six passages, one fewer than its source. A reader that sees only the report finds nothing to flag and thinks it fine. probity-verify lays the same report over source.html, pairs each source passage with its record passage, finds that the fifth has nothing to pair with, and returns contradicted, reason selected_span_missing_from_record."></picture></p>

It's for auditors, incident reviewers and relying parties who need a decision they can replay, and for tool authors who want their records checked the same way.

Install the released verifier: `uv add probity-verify==0.3.0`, or `pip install probity-verify==0.3.0`.

Verified by Probity (github.com/probityai/probity). The `probityai` command line is released: `uv add probityai==0.1.1`, or `pip install probityai==0.1.1`.

## Quick start

Check a sample claim with the released package. You need Python 3.11 or newer and [uv](https://docs.astral.sh/uv/); there is nothing to clone:

```sh
samples="$(uvx --from probity-verify==0.3.0 python -c 'import importlib.resources as r; print(r.files("probity_verify") / "samples")')"
uvx probity-verify==0.3.0 "$samples/case.json" --policy "$samples/policy-june.json"
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

Two name families, on purpose. `agent-evidence-*` is the neutral evidence layer: formats and checks any tool can pin without adopting ours. `probity*` is the product built on it. Each package keeps its own version and release tag, `<name>-v<version>`.

| layer | package | what it is | install |
| --- | --- | --- | --- |
| evidence | [agent-evidence-mcp](packages/agent-evidence-mcp/README.md) | offline, read-only MCP server: checks a claim against evidence bytes and replays the conformance vectors | `pip install agent-evidence-mcp==0.2.5` |
| evidence | [agent-evidence-observer](packages/agent-evidence-observer/README.md) | records what an agent run did as pinned evidence | `pip install agent-evidence-observer==0.2.0` |
| evidence | [agent-evidence-admission](https://github.com/probityai/agent-evidence-vectors) | checks an artifact has the digest its SBOM or attestation names (in agent-evidence-vectors) | `pip install agent-evidence-admission==0.2.0` |
| evidence | [agent-evidence-vocabulary](https://github.com/probityai/agent-evidence-vectors) | versioned terms for claims about agent execution evidence (in agent-evidence-vectors) | `pip install agent-evidence-vocabulary==0.8.0` |
| evidence | [agent-evidence-vectors](https://github.com/probityai/agent-evidence-vectors) | conformance corpora and reference verifiers | `pip install agent-evidence-vectors==0.32.1` |
| product | [probityai](packages/probityai/README.md) | the `probityai` command; `probityai verify` today | `pip install probityai==0.1.1` |
| product | [probity-verify](packages/probity-verify/README.md) | offline verifier: `supported`, `contradicted` or `not_established` | `pip install probity-verify==0.3.0` |
| product | [probity-ratchet](packages/probity-ratchet/README.md) | signed, replayable receipts for improving an agent against held-out cases | `pip install probity-ratchet==0.3.4` |
| product | [probity-effects](packages/probity-effects/README.md) | keeps one effect per agent tool call when its reply is lost, records the trail, tests it against lost-reply scenarios | `pip install probity-effects==0.2.0` |
| product | [evaluator-replay-kit](packages/evaluator-replay-kit/README.md) | replays a lab's agent action record and flags a changed or missing step | `pip install "git+https://github.com/probityai/probity@evaluator-replay-kit-v0.1.0#subdirectory=packages/evaluator-replay-kit"` (not on PyPI) |

The Claude Code and Cursor plugins ship from [harnesses/agent-evidence-plugins](harnesses/agent-evidence-plugins/README.md).

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
