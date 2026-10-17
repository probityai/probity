# Agent instructions

- Set up with `uv sync --all-packages --all-extras`. Run `uv run python -m pytest` from the root before every commit; it runs every member's tests and `tests/`.
- Run `uv run --only-group dev ruff check .` before every commit.
- Run `python3 scripts/readme-lint.py <README>` after editing any README. Keep each under 600 prose words; detail goes in `docs/`.
- Never edit `scripts/readme-lint.py` or `scripts/readme-lint-test.py`; they are shared byte-for-byte with sibling repositories.
- Member rules live with the member: [packages/probity-verify/AGENTS.md](packages/probity-verify/AGENTS.md).
- A new member is a directory under `packages/` with its own `pyproject.toml`, `README.md` and `LICENSE`. `scripts/workspace.py` finds it; add its CI job to `.github/workflows/ci.yml` and to the `needs` of `ci-ok`.
- A new `probity` subcommand is an entry point in the `probityai.cli_subcommands` group; never add a name to the launcher.
