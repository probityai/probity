#!/usr/bin/env python3
"""Tests for refresh-badges.py: the combined verifier badge sums both PyPI names."""

from __future__ import annotations

import importlib.util
import io
import os
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

README = "![d](assets/badges/dl-verifier-total.svg)\n"


def not_found() -> urllib.error.HTTPError:
    return urllib.error.HTTPError("u", 404, "Not Found", {}, None)  # type: ignore[arg-type]


class CombinedBadgeTest(unittest.TestCase):
    def run_main(self, fetch, key: str | None = "k") -> tuple[int, str]:
        env = {"PEPY_API_KEY": key} if key else {}
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "assets" / "badges"
            out.mkdir(parents=True)
            (Path(tmp) / "README.md").write_text(README)
            with (
                mock.patch.dict(os.environ, env, clear=True),
                mock.patch.object(rb, "fetch", fetch),
                redirect_stdout(io.StringIO()),
            ):
                rc = rb.main(["--out", str(out)])
            return rc, (out / "dl-verifier-total.svg").read_text(encoding="utf-8")

    def test_sums_old_and_new_name(self) -> None:
        totals = {"probity-verify": 9034, "agent-evidence-verify": 1200}
        rc, svg = self.run_main(lambda url, headers=None: {"total_downloads": totals[url.rsplit("/", 1)[1]]})
        self.assertEqual(rc, 0)
        self.assertIn("10.2k", svg)
        self.assertIn("verifier", svg)

    def test_a_name_pepy_has_not_seen_counts_zero(self) -> None:
        def fetch(url, headers=None):
            if url.endswith("agent-evidence-verify"):
                raise not_found()
            return {"total_downloads": 9034}

        rc, svg = self.run_main(fetch)
        self.assertEqual(rc, 0)
        self.assertIn("9k", svg)

    def test_other_http_error_leaves_n_a(self) -> None:
        def fetch(url, headers=None):
            raise urllib.error.HTTPError(url, 500, "boom", {}, None)  # type: ignore[arg-type]

        rc, svg = self.run_main(fetch)
        self.assertEqual(rc, 1)
        self.assertIn("n/a", svg)

    def test_no_pepy_key_never_writes_a_partial_total(self) -> None:
        rc, svg = self.run_main(lambda url, headers=None: {"total_downloads": 5}, key=None)
        self.assertEqual(rc, 1)
        self.assertIn("n/a", svg)


class PepyLinkTest(unittest.TestCase):
    ROOT = '<a href="https://pypi.org/project/agent-evidence-verify/"><img src="assets/badges/dl-verifier-total.svg"></a>\n'
    PKG = "# t\n\n[![PyPI](x)](y)\n<!-- downloads-badge:begin -->\n<!-- downloads-badge:end -->\n\ntext\n"

    def relink(self, live: bool) -> tuple[str, str]:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "packages" / "agent-evidence-verify").mkdir(parents=True)
            (root / "README.md").write_text(self.ROOT)
            pkg = root / "packages" / "agent-evidence-verify" / "README.md"
            pkg.write_text(self.PKG)
            rb.relink_verifier(root, live)
            rb.relink_verifier(root, live)  # idempotent
            return (root / "README.md").read_text(), pkg.read_text()

    def test_pepy_404_links_pypi_and_drops_package_badge(self) -> None:
        root_text, pkg_text = self.relink(False)
        self.assertEqual(root_text, self.ROOT)
        self.assertEqual(pkg_text, self.PKG)
        self.assertNotIn("probity-verify", root_text + pkg_text)

    def test_pepy_200_links_pepy_and_adds_package_badge(self) -> None:
        root_text, pkg_text = self.relink(True)
        self.assertIn('href="https://pepy.tech/projects/agent-evidence-verify"', root_text)
        self.assertIn("](https://pepy.tech/projects/agent-evidence-verify)", pkg_text)
        self.assertIn("dl-verifier-total.svg", pkg_text)
        self.assertNotIn("probity-verify", root_text + pkg_text)

    def test_badge_comes_back_off_again_when_pepy_goes_away(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "packages" / "agent-evidence-verify").mkdir(parents=True)
            (root / "README.md").write_text(self.ROOT)
            pkg = root / "packages" / "agent-evidence-verify" / "README.md"
            pkg.write_text(self.PKG)
            rb.relink_verifier(root, True)
            rb.relink_verifier(root, False)
            self.assertEqual(pkg.read_text(), self.PKG)
            self.assertEqual((root / "README.md").read_text(), self.ROOT)

    def test_page_exists_is_false_on_http_error(self) -> None:
        with mock.patch.object(rb.urllib.request, "urlopen", side_effect=not_found()):
            self.assertFalse(rb.page_exists("https://pepy.tech/projects/x"))


if __name__ == "__main__":
    unittest.main()
