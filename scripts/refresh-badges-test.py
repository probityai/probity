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
    def run_main(self, fetch, key: str | None = "k", frozen: dict | None = None) -> tuple[int, str]:
        env = {"PEPY_API_KEY": key} if key else {}
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "assets" / "badges"
            out.mkdir(parents=True)
            (Path(tmp) / "README.md").write_text(README)
            with (
                mock.patch.dict(os.environ, env, clear=True),
                mock.patch.object(rb, "fetch", fetch),
                mock.patch.dict(rb.FROZEN, frozen if frozen is not None else {}, clear=True),
                redirect_stdout(io.StringIO()),
            ):
                rc = rb.main(["--out", str(out)])
            return rc, (out / "dl-verifier-total.svg").read_text(encoding="utf-8")

    def test_sums_old_and_new_name(self) -> None:
        totals = {"probity-verify": 9034, "agent-evidence-verify": 1200}
        rc, svg = self.run_main(lambda url, headers=None: {"total_downloads": totals[url.rsplit("/", 1)[1]]})
        self.assertEqual(rc, 0)
        self.assertIn("10.2k", svg)
        self.assertIn('aria-label="↓ 10.2k"', svg)  # the same label as every other download badge

    def test_a_frozen_name_is_not_read_live(self) -> None:
        seen = []

        def fetch(url, headers=None):
            seen.append(url)
            return {"total_downloads": 1200}

        rc, svg = self.run_main(fetch, frozen={"probity-verify": 9034})
        self.assertEqual(rc, 0)
        self.assertIn("10.2k", svg)
        self.assertFalse(any(u.endswith("/probity-verify") for u in seen))

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

    def test_pepy_404_links_pepy_and_drops_package_badge(self) -> None:
        root_text, pkg_text = self.relink(False)
        self.assertIn(f'href="{rb.PEPY_PAGE}"', root_text)
        self.assertNotIn("pypi.org", root_text)
        self.assertEqual(pkg_text, self.PKG)

    def test_pepy_200_links_pepy_and_adds_package_badge(self) -> None:
        root_text, pkg_text = self.relink(True)
        self.assertIn(f'href="{rb.PEPY_PAGE}"', root_text)
        self.assertIn(f"]({rb.PEPY_PAGE})", pkg_text)
        self.assertIn("dl-verifier-total.svg", pkg_text)

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
            self.assertIn(rb.PEPY_PAGE, (root / "README.md").read_text())

    def test_downloads_page_names_every_summed_package(self) -> None:
        names = rb.COMBINED["dl-verifier-total"][1]
        self.assertGreater(len(names), 1)
        page = rb.downloads_page({n: 1000 + i for i, n in enumerate(names)})
        for n in names:
            self.assertIn(f"https://pepy.tech/projects/{n}", page)
        self.assertIn(f"**{sum(1000 + i for i in range(len(names))):,}**", page)

    def test_downloads_page_reads_as_written_for_a_stranger(self) -> None:
        page = rb.downloads_page({"old-name": 10_003, "new-name": 2_742})
        for word in ("fixed", "double", "twice", "scheduled", "script", ".py", "UTC", "API", "counting"):
            self.assertNotIn(word, page)
        self.assertNotRegex(page, r"\d{4}-\d{2}-\d{2}")
        self.assertIn("10,003", page)
        self.assertIn("**12,745**", page)

    def test_downloads_page_is_not_rewritten_when_nothing_moved(self) -> None:
        build = rb.load_make_badge().build
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "assets" / "badges"
            out.mkdir(parents=True)
            doc = Path(tmp) / rb.DOWNLOADS_DOC
            totals = {"a": 1, "b": 2}
            self.assertEqual(rb.refresh_one(build, out, "dl-x-total", "t", "s", lambda: totals), 0)
            first = doc.read_text()
            self.assertEqual(rb.refresh_one(build, out, "dl-x-total", "t", "s", lambda: totals), 0)
            self.assertEqual(doc.read_text(), first)
            rb.refresh_one(build, out, "dl-x-total", "t", "s", lambda: {"a": 1, "b": 3})
            self.assertIn("| 3 |", doc.read_text())

    def test_old_links_are_rewritten_to_the_pepy_page(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "README.md").write_text(self.ROOT)
            self.assertEqual(rb.relink_verifier(root, True), ["README.md"])
            self.assertIn(rb.PEPY_PAGE, (root / "README.md").read_text())
            self.assertEqual(rb.relink_verifier(root, True), [])
            (root / "README.md").write_text(self.ROOT.replace("https://pypi.org/project/agent-evidence-verify/", rb.OLD_COMPARE_PAGE))
            self.assertEqual(rb.relink_verifier(root, True), ["README.md"])

    def test_repo_readme_verifier_badge_links_the_pepy_page(self) -> None:
        text = (Path(rb.__file__).resolve().parent.parent / "README.md").read_text(encoding="utf-8")
        lines = [ln for ln in text.splitlines() if "dl-verifier-total" in ln]
        self.assertTrue(lines)
        for ln in lines:
            self.assertIn(rb.PEPY_PAGE, ln)

    def test_page_exists_is_false_on_http_error(self) -> None:
        with mock.patch.object(rb.urllib.request, "urlopen", side_effect=not_found()):
            self.assertFalse(rb.page_exists("https://pepy.tech/projects/x"))


if __name__ == "__main__":
    unittest.main()
