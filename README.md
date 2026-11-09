# Probity

<p>
<a href="https://github.com/probityai/probity/actions/workflows/ci.yml"><img height="16" alt="CI" src="https://github.com/probityai/probity/actions/workflows/ci.yml/badge.svg"></a>
<a href="https://pypi.org/project/agent-evidence-verify/"><img height="16" alt="Version" src="https://img.shields.io/pypi/v/agent-evidence-verify?style=flat-square&color=blue&label=&logo=pypi&logoColor=white&cacheSeconds=3600"></a>
<a href="https://pepy.tech/projects/agent-evidence-verify"><img height="16" alt="Downloads" src="assets/badges/dl-verifier-total.svg"></a>
<a href="https://github.com/probityai/probity/blob/main/LICENSE"><img height="16" alt="License" src="assets/badges/license.svg"></a>
<a href="https://github.com/probityai/probity/stargazers"><img height="16" alt="Stars" src="assets/badges/stars.svg"></a>
</p>

Open tools that check claims about AI agents against evidence you pinned: an offline verifier, an observer that records agent runs, and the tools around them. The conformance corpus, vocabulary and admission rules live in https://github.com/probityai/agent-evidence-vectors.

<p align="center"><picture><source media="(min-width: 1012px)" srcset="https://raw.githubusercontent.com/probityai/probityai.github.io/main/figures/f3-missing-not-clean/5/wide-auto.svg"><img src="https://raw.githubusercontent.com/probityai/probityai.github.io/main/figures/f3-missing-not-clean/5/narrow-auto.svg" alt="A report.txt of six passages, one fewer than its source. A reader that sees only the report finds nothing to flag and thinks it fine. agent-evidence-verify lays the same report over source.html, pairs each source passage with its record passage, finds that the fifth has nothing to pair with, and returns contradicted, reason selected_span_missing_from_record."></picture></p>

It's for auditors, incident reviewers and relying parties who need a decision they can replay, and for tool authors who want their records checked the same way.

Install the released verifier: `uv add agent-evidence-verify==0.5.1`, or `pip install agent-evidence-verify==0.5.1`.

Verified by Probity (github.com/probityai/probity). The `probityai` command line is released: `uv add probityai==0.1.1`, or `pip install probityai==0.1.1`.

## Quick start

Check a sample claim with the released package. You need Python 3.12 or newer and [uv](https://docs.astral.sh/uv/); there is nothing to clone:

```sh
samples="$(uvx --from agent-evidence-verify==0.5.1 python -c 'import importlib.resources as r; print(r.files("agent_evidence_verify") / "samples")')"
uvx agent-evidence-verify==0.5.1 "$samples/case.json" --policy "$samples/policy-june.json"
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

| package | registry | version | downloads |
| --- | --- | :---: | :---: |
| [agent-evidence-mcp](packages/agent-evidence-mcp/README.md) | PyPI | **0.2.5** | [![agent-evidence-mcp downloads](assets/badges/dl-pypi-agent-evidence-mcp.svg)](https://pepy.tech/projects/agent-evidence-mcp) |
| [agent-evidence-observer](packages/agent-evidence-observer/README.md) | PyPI | **0.2.0** | [![agent-evidence-observer downloads](assets/badges/dl-pypi-agent-evidence-observer.svg)](https://pepy.tech/projects/agent-evidence-observer) |

- `agent-evidence-mcp`: offline, read-only MCP server: checks a claim against evidence bytes and replays the conformance vectors
- `agent-evidence-observer`: records what an agent run did as pinned evidence

**Product**

| package | registry | version | downloads |
| --- | --- | :---: | :---: |
| [probityai](packages/probityai/README.md) | PyPI | **0.1.1** | [![probityai downloads](assets/badges/dl-pypi-probityai.svg)](https://pepy.tech/projects/probityai) |
| [agent-evidence-verify](packages/agent-evidence-verify/README.md) | PyPI | **0.5.1** | [![agent-evidence-verify downloads](assets/badges/dl-verifier-total.svg)](https://pepy.tech/projects/agent-evidence-verify) |
| [probity-ratchet](packages/probity-ratchet/README.md) | PyPI | **0.4.0** | [![probity-ratchet downloads](assets/badges/dl-pypi-probity-ratchet.svg)](https://pepy.tech/projects/probity-ratchet) |
| [probity-ratchet-cases](packages/probity-ratchet-cases/README.md) | PyPI | **0.2.0** | [![probity-ratchet-cases downloads](assets/badges/dl-pypi-probity-ratchet-cases.svg)](https://pepy.tech/projects/probity-ratchet-cases) |
| [probity-effects](packages/probity-effects/README.md) | PyPI | **0.2.0** | - |
| [agent-evidence-replay](packages/agent-evidence-replay/README.md) | PyPI | **0.1.0** | - |

- `probityai`: the `probityai` command; `probityai verify` today
- `agent-evidence-verify`: offline verifier: supported, contradicted or not established
- `probity-ratchet`: signed, replayable receipts for improving an agent against held-out cases
- `probity-ratchet-cases`: agent task cases graded on final state: a simulated company, tool faults, exact graders
- `probity-effects`: keeps one effect per agent tool call when its reply is lost, records the trail, tests it against lost-reply scenarios
- `agent-evidence-replay`: replays a lab's agent action record and flags a changed or missing step

Install any of them pinned to the version shown: `pip install <package>==<version>`.

The Claude Code and Cursor plugins ship from [harnesses/agent-evidence-plugins](harnesses/agent-evidence-plugins/README.md).

## Work on the repository

```sh
uv sync --all-packages --all-extras
uv run python -m pytest
```

## Documentation

| page | read it for |
| --- | --- |
| [agent-evidence-verify](packages/agent-evidence-verify/README.md) | the verifier, its adapters and its recipes |
| [Repository layout](docs/architecture/MONOREPO.md) | the workspace, the `probityai` command seam, CI and releases |
| [Agent instructions](AGENTS.md) | commands to run before a change |
| [Contributing](CONTRIBUTING.md) | reporting a problem and opening a pull request |

## License

Apache-2.0, per directory: each member carries its own `LICENSE`.
