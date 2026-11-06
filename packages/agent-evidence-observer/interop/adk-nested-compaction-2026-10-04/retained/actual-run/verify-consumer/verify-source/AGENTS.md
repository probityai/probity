# Agent instructions

- Set up with `uv sync --extra test`.
- Run `uv run pytest` before every commit. CI also runs `python vectors-source-coverage/check_vectors.py --verifier probity-verify` and the same for `vectors-operand-lineage`; run both after changing an adapter.
- Run `python3 scripts/readme-lint.py README.md` after editing the README. Keep it under 600 prose words; detail goes in `docs/`.
- Never hand-edit fixture bytes under `examples/` or `vectors-*/cases/`: their SHA-256 digests and lengths are pinned in the case and policy files and in each `MANIFEST.json`.
- Never edit `scripts/readme-lint.py` or `scripts/readme-lint-test.py` here; they are shared byte-for-byte with sibling repositories.
- Malformed input must exit 2 without a verdict. A change that turns a malformed input into `not_established` is a bug.
