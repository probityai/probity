# Rules for changing this repository

- Run `python -m pytest -q`. The tests call every tool through a real MCP client against the real packages and corpus. Do not add mocks of the verifier or the vectors.
- Run `python scripts/mutation_check.py` after changing a tool. It breaks one behaviour at a time and every mutation must be killed. Add a test, not an exemption, for a survivor.
- Run `python scripts/readme-lint.py README.md` and `python scripts/pre-push-identity-scan.py --recent 50` before a push.
- Every dependency is pinned exactly in `pyproject.toml`. A new tool wraps a pinned package; it never reimplements one.
- Do not hand-edit `uv.lock`; regenerate it with `uv lock`.
