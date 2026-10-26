# probityai

[![PyPI](https://img.shields.io/pypi/v/probityai.svg)](https://pypi.org/project/probityai/)

The `probityai` command checks a claim about an AI agent against evidence bytes you pinned, offline, and prints a decision you can replay.

It's for platform and security engineers, auditors and incident reviewers who receive a claim about an agent run and need a decision, not a report to trust.

Install the released package: `pip install probityai==0.1.0`.

## Quick start

You need Python 3.11 or newer and [uv](https://docs.astral.sh/uv/). Nothing to clone: the sample case and policies ship inside the wheel.

```sh
samples="$(uvx --from probityai==0.1.0 python -c 'import importlib.resources as r; print(r.files("probity_verify") / "samples")')"
uvx --from probityai==0.1.0 probityai verify "$samples/case.json" --policy "$samples/policy-june.json"
```

It prints a decision packet that opens:

```text
Probity decision packet v1
Case: "source-coverage-demo"
Claim: source_text_coverage/v1
Decision: contradicted
Reason: selected_span_missing_from_record
```

Every valid decision exits 0, including `contradicted` and `not_established`; exit 2 is invalid input. Add `--json` to read `decision` in a CI step.

## Commands

| Command | From | What it does |
|---|---|---|
| `probityai verify` | [probity-verify](https://github.com/probityai/probity/tree/main/packages/probity-verify) | decide a claim against pinned evidence, or a DSSE envelope |
| `probityai done` | [agent-evidence-observer](https://github.com/probityai/probity/tree/main/packages/observer) `[done]` | seal a definition of done and check an agent's claim from outside |

`probityai --help` lists exactly the commands installed. A package adds one with an entry point in the `probityai.cli_subcommands` group; the contract is in [docs/architecture/MONOREPO.md](https://github.com/probityai/probity/blob/main/docs/architecture/MONOREPO.md#the-probityai-command).

## Status

Version 0.1.0, alpha, Apache-2.0. Agent Evidence is the open standard; Probity checks and grades against it: [probityai/agent-evidence](https://github.com/probityai/agent-evidence).
