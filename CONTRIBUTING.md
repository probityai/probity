# Contributing

Issues and pull requests are welcome. A record the verifier judges wrongly, a refusal you think is mistaken, or a report the observer cannot read are the most useful reports. Include the bytes, or a command that reproduces them.

Report a security problem privately, as [SECURITY.md](SECURITY.md) describes, rather than in an issue.

## Before you open a pull request

Set up the workspace and run the checks from the repository root:

```bash
uv sync --all-packages --all-extras
uv run --only-group dev ruff check .
uv run python -m pytest
python3 scripts/readme-lint.py README.md
```

`pytest` from the root runs every package's tests and `tests/`. Each package documents its own extra checks in its README and `AGENTS.md`.

A change that alters behaviour comes with a test that fails without it. A fix for a reported bug adds that report's bytes as a test case.

CI runs the checks of every package your change touches. The one required check is `ci-ok`.

## Licence

Contributions are accepted under the Apache License 2.0, the licence of this repository. There is no contributor licence agreement to sign.
