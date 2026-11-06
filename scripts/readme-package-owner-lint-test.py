#!/usr/bin/env python3
"""Tests for readme-package-owner-lint.py, including the pre-dedupe README."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("lint", Path(__file__).with_name("readme-package-owner-lint.py"))
assert spec and spec.loader
lint = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lint)

OWN = (
    "| [probity-verify](packages/probity-verify/README.md) | verifier | **0.4.1** | "
    "[![d](assets/badges/dl-pypi-probity-verify.svg)](https://pepy.tech/projects/probity-verify) |\n"
)
OLD = (
    "| [agent-evidence-vocabulary](https://github.com/probityai/agent-evidence-vectors) | terms | **0.9.0** | "
    "[![d](assets/badges/dl-pypi-agent-evidence-vocabulary.svg)](https://pepy.tech/projects/agent-evidence-vocabulary) |\n"
)


class OwnerLintTest(unittest.TestCase):
    def run_lint(self, text: str) -> int:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "packages" / "probity-verify").mkdir(parents=True)
            (root / "README.md").write_text(text)
            return int(lint.main([str(root / "README.md"), str(root)]))

    def test_own_package_passes(self) -> None:
        self.assertEqual(self.run_lint(OWN), 0)

    def test_foreign_row_and_badge_fail(self) -> None:
        self.assertEqual(self.run_lint(OWN + OLD), 1)

    def test_foreign_badge_without_row_fails(self) -> None:
        self.assertEqual(self.run_lint("[![d](https://pepy.tech/projects/other-pkg)](x)\n"), 1)

    def test_repository_readme_passes(self) -> None:
        root = Path(__file__).resolve().parent.parent
        self.assertEqual(int(lint.main([str(root / "README.md"), str(root)])), 0)


if __name__ == "__main__":
    unittest.main()
