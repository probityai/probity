#!/usr/bin/env python3
"""Tests for refresh-badges.py: one badge per package name, each matching its page."""

from __future__ import annotations

import importlib.util
import io
import os
import re
import tempfile
import unittest
import urllib.error
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

spec = importlib.util.spec_from_file_location("rb", Path(__file__).with_name("refresh-badges.py"))
assert spec and spec.loader
rb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rb)

REPO_README = Path(rb.__file__).resolve().parent.parent / "README.md"
README = "![d](assets/badges/dl-pypi-probity-verify.svg)\n![d](assets/badges/dl-pypi-agent-evidence-verify.svg)\n"


class PerNameBadgeTest(unittest.TestCase):
    def run_main(self, fetch) -> tuple[int, dict[str, str]]:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "assets" / "badges"
            out.mkdir(parents=True)
            (Path(tmp) / "README.md").write_text(README)
            with (
                mock.patch.dict(os.environ, {"PEPY_API_KEY": "k"}, clear=True),
                mock.patch.object(rb, "fetch", fetch),
                redirect_stdout(io.StringIO()),
            ):
                rc = rb.main(["--out", str(out)])
            return rc, {p.stem: p.read_text(encoding="utf-8") for p in out.glob("*.svg")}

    def test_each_name_gets_its_own_count(self) -> None:
        totals = {"probity-verify": 10_604, "agent-evidence-verify": 3_218}
        rc, svgs = self.run_main(lambda url, headers=None: {"total_downloads": totals[url.rsplit("/", 1)[1]]})
        self.assertEqual(rc, 0)
        self.assertEqual(set(svgs), {"dl-pypi-probity-verify", "dl-pypi-agent-evidence-verify"})
        self.assertIn('aria-label="↓ 10.6k"', svgs["dl-pypi-probity-verify"])
        self.assertIn('aria-label="↓ 3.2k"', svgs["dl-pypi-agent-evidence-verify"])

    def test_a_failed_read_writes_n_a_only_for_a_missing_file(self) -> None:
        def fetch(url, headers=None):
            raise urllib.error.HTTPError(url, 500, "boom", {}, None)  # type: ignore[arg-type]

        rc, svgs = self.run_main(fetch)
        self.assertEqual(rc, 1)
        self.assertTrue(all("n/a" in v for v in svgs.values()))


class RepoReadmeTest(unittest.TestCase):
    def test_no_summed_badge_and_every_badge_links_its_own_page(self) -> None:
        text = REPO_README.read_text(encoding="utf-8")
        self.assertNotRegex(text, r"dl-[a-z0-9-]+-total\.svg")
        pairs = re.findall(r'<a href="([^"]+)"><img[^>]*src="assets/badges/dl-pypi-([^"]+)\.svg"', text)
        pairs += [(u, n) for n, u in re.findall(r"\(assets/badges/dl-pypi-([^)]+)\.svg\)\]\(([^)]+)\)", text)]
        self.assertTrue(pairs)
        for url, name in pairs:
            self.assertEqual(url, f"https://pepy.tech/projects/{name}")
        self.assertIn("dl-pypi-probity-verify.svg", text.split("</p>", 1)[1])
        self.assertIn("dl-pypi-agent-evidence-verify.svg", text)

    def test_package_table_rows_stay_on_one_line(self) -> None:
        text = REPO_README.read_text(encoding="utf-8")
        rows = [ln for ln in text.splitlines() if ln.startswith("| [") and "**" in ln]
        self.assertTrue(rows)
        for ln in rows:
            self.assertNotIn("<br>", ln)
            self.assertNotIn("-", ln.split(" | ")[0].split("](")[0])  # names use &#8209; so they never wrap
            self.assertEqual(len(ln.split(" | ")), 4, ln)


if __name__ == "__main__":
    unittest.main()
