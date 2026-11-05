# Probity

[![CI](https://img.shields.io/github/actions/workflow/status/probityai/probity/ci.yml?style=flat-square&color=blue&label=CI)](https://github.com/probityai/probity/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/probityai/probity?style=flat-square&color=blue&label=license)](LICENSE)
[![Stars](https://img.shields.io/github/stars/probityai/probity?style=flat-square&color=blue&label=stars)](https://github.com/probityai/probity/stargazers)
[![Downloads](https://img.shields.io/pepy/dt/probity-verify?style=flat-square&color=blue&label=downloads)](https://pepy.tech/projects/probity-verify)

Open tools that check claims about AI agents against evidence you pinned: an offline verifier, an observer that records agent runs, and the tools around them. The conformance corpus, vocabulary and admission rules live in https://github.com/probityai/agent-evidence-vectors.

<p align="center"><picture><source media="(min-width: 1012px)" srcset="https://raw.githubusercontent.com/probityai/probityai.github.io/main/figures/f3-missing-not-clean/5/wide-auto.svg"><img src="https://raw.githubusercontent.com/probityai/probityai.github.io/main/figures/f3-missing-not-clean/5/narrow-auto.svg" alt="A report.txt of six passages, one fewer than its source. A reader that sees only the report finds nothing to flag and thinks it fine. probity-verify lays the same report over source.html, pairs each source passage with its record passage, finds that the fifth has nothing to pair with, and returns contradicted, reason selected_span_missing_from_record."></picture></p>

It's for auditors, incident reviewers and relying parties who need a decision they can replay, and for tool authors who want their records checked the same way.

Install the released verifier: `uv add probity-verify==0.4.1`, or `pip install probity-verify==0.4.1`.

Verified by Probity (github.com/probityai/probity). The `probityai` command line is released: `uv add probityai==0.1.1`, or `pip install probityai==0.1.1`.

## Quick start

Check a sample claim with the released package. You need Python 3.12 or newer and [uv](https://docs.astral.sh/uv/); there is nothing to clone:

```sh
samples="$(uvx --from probity-verify==0.4.1 python -c 'import importlib.resources as r; print(r.files("probity_verify") / "samples")')"
uvx probity-verify==0.4.1 "$samples/case.json" --policy "$samples/policy-june.json"
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

**Evidence layer**

| package | what it is | version | downloads |
| --- | --- | :---: | :---: |
| [agent-evidence-mcp](packages/agent-evidence-mcp/README.md) | offline, read-only MCP server: checks a claim against evidence bytes and replays the conformance vectors | **0.2.5** | [![agent-evidence-mcp downloads](https://img.shields.io/pepy/dt/agent-evidence-mcp?style=flat-square&color=blue&label=)](https://pepy.tech/projects/agent-evidence-mcp) |
| [agent-evidence-observer](packages/agent-evidence-observer/README.md) | records what an agent run did as pinned evidence | **0.2.0** | [![agent-evidence-observer downloads](https://img.shields.io/pepy/dt/agent-evidence-observer?style=flat-square&color=blue&label=)](https://pepy.tech/projects/agent-evidence-observer) |
| [agent-evidence-admission](https://github.com/probityai/agent-evidence-vectors) | checks an artifact has the digest its SBOM or attestation names (in agent-evidence-vectors) | **0.2.0** | [![agent-evidence-admission downloads](https://img.shields.io/pepy/dt/agent-evidence-admission?style=flat-square&color=blue&label=)](https://pepy.tech/projects/agent-evidence-admission) |
| [agent-evidence-vocabulary](https://github.com/probityai/agent-evidence-vectors) | versioned terms for claims about agent execution evidence (in agent-evidence-vectors) | **0.9.0** | [![agent-evidence-vocabulary downloads](https://img.shields.io/pepy/dt/agent-evidence-vocabulary?style=flat-square&color=blue&label=)](https://pepy.tech/projects/agent-evidence-vocabulary) |
| [agent-evidence-vectors](https://github.com/probityai/agent-evidence-vectors) | conformance corpora and reference verifiers | **0.35.0** | [![agent-evidence-vectors downloads](https://img.shields.io/pepy/dt/agent-evidence-vectors?style=flat-square&color=blue&label=)](https://pepy.tech/projects/agent-evidence-vectors) |

**Product**

| package | what it is | version | downloads |
| --- | --- | :---: | :---: |
| [probityai](packages/probityai/README.md) | the `probityai` command; `probityai verify` today | **0.1.1** | [![probityai downloads](https://img.shields.io/pepy/dt/probityai?style=flat-square&color=blue&label=)](https://pepy.tech/projects/probityai) |
| [probity-verify](packages/probity-verify/README.md) | offline verifier: `supported`, `contradicted` or `not_established` | **0.4.1** | [![probity-verify downloads](https://img.shields.io/pepy/dt/probity-verify?style=flat-square&color=blue&label=)](https://pepy.tech/projects/probity-verify) |
| [probity-ratchet](packages/probity-ratchet/README.md) | signed, replayable receipts for improving an agent against held-out cases | **0.4.0** | [![probity-ratchet downloads](https://img.shields.io/pepy/dt/probity-ratchet?style=flat-square&color=blue&label=)](https://pepy.tech/projects/probity-ratchet) |
| [probity-ratchet-cases](packages/probity-ratchet-cases/README.md) | agent task cases graded on final state: a simulated company, tool faults, exact graders | **0.2.0** | [![probity-ratchet-cases downloads](https://img.shields.io/pepy/dt/probity-ratchet-cases?style=flat-square&color=blue&label=)](https://pepy.tech/projects/probity-ratchet-cases) |
| [probity-effects](packages/probity-effects/README.md) | keeps one effect per agent tool call when its reply is lost, records the trail, tests it against lost-reply scenarios | **0.2.0** | - |
| [evaluator-replay-kit](packages/evaluator-replay-kit/README.md) | replays a lab's agent action record and flags a changed or missing step | **0.1.0** | not on PyPI |

Install any of them pinned to the version shown: `pip install <package>==<version>`. evaluator-replay-kit installs from its tag: `pip install "git+https://github.com/probityai/probity@evaluator-replay-kit-v0.1.0#subdirectory=packages/evaluator-replay-kit"`.

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
