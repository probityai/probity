# Agent instructions for probity-verify

- Run commands from this directory. `uv run --extra test pytest` runs this member's tests.
- CI also runs `python vectors-source-coverage/check_vectors.py --verifier probity-verify` and the same for `vectors-operand-lineage`; run both after changing an adapter.
- Never hand-edit fixture bytes under `examples/` or `vectors-*/cases/`: their SHA-256 digests and lengths are pinned in the case and policy files and in each `MANIFEST.json`.
- Malformed input must exit 2 without a verdict. A change that turns a malformed input into `not_established` is a bug.
