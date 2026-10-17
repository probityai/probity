# Probity

Open tools that check claims about AI agents against evidence you pinned: an offline verifier today, with the observer, admission rules, vocabulary, conformance vectors and Rust crates joining this repository.

It's for auditors, incident reviewers and relying parties who need a decision they can replay, and for tool authors who want their records checked the same way.

Install the released verifier: `pip install probity-verify==0.1.1`.

## Quick start

Check a sample claim with the released package. You need Python 3.11 or newer and [uv](https://docs.astral.sh/uv/); there is nothing to clone:

```sh
samples="$(uvx --from probity-verify==0.1.1 python -c 'import importlib.resources as r; print(r.files("probity_verify") / "samples")')"
uvx probity-verify==0.1.1 "$samples/case.json" --policy "$samples/policy-june.json"
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
| [packages/probity-verify](packages/probity-verify/README.md) | offline verifier: `supported`, `contradicted` or `not_established` for a claim against pinned bytes | 0.1.1 on PyPI |
| [packages/probityai](packages/probityai/README.md) | the `probity` command; `probity verify` today, each member adds its own subcommand | not yet released |

## Work on the repository

```sh
uv sync --all-packages --all-extras
uv run python -m pytest
```

## Documentation

| page | read it for |
| --- | --- |
| [probity-verify](packages/probity-verify/README.md) | the verifier, its adapters and its recipes |
| [Repository layout](docs/architecture/MONOREPO.md) | the workspace, the `probity` command seam, CI and releases |
| [Agent instructions](AGENTS.md) | commands to run before a change |

## License

Apache-2.0, per directory: each member carries its own `LICENSE`.
