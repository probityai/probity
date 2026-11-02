"""The README's quick start runs as written and prints what the README says it prints."""

from __future__ import annotations

import contextlib
import io
import re
from pathlib import Path

README = Path(__file__).resolve().parents[1] / "README.md"


def test_quick_start_prints_what_the_readme_shows():
    text = README.read_text(encoding="utf-8")
    code = re.search(r"```python\n(.*?)```", text, re.DOTALL).group(1)
    shown = re.search(r"```text\n(.*?)```", text, re.DOTALL).group(1)
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        exec(compile(code, str(README), "exec"), {})  # noqa: S102 - the README's own example
    assert output.getvalue() == shown
