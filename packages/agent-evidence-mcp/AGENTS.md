# Rules for changing this repository

- Run `python -m pytest -q`. The tests call every tool through a real MCP client against the real packages and corpus. Do not add mocks of the verifier or the vectors.
- Run `python scripts/mutation_check.py` after changing a tool. It breaks one behaviour at a time and every mutation must be killed. Add a test, not an exemption, for a survivor.
- Run `python scripts/readme-lint.py README.md` and `python scripts/pre-push-identity-scan.py --recent 50` before a push.
- Third-party dependencies are pinned exactly in `pyproject.toml`; packages of our own family take a range `>=X.Y.Z,<1`, never an exact pin and never `~=0.X.Y` (it stops at the next minor), so the family installs together. A new tool wraps a family package; it never reimplements one.
- Do not hand-edit `uv.lock`; regenerate it with `uv lock`.
