#!/usr/bin/env python3
"""Tests for refresh-badges.py: endpoint JSON, and the combined verifier badge sums both names."""

from __future__ import annotations

import importlib.util
import io
import json
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

URL = "https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fprobityai%2Fprobity%2Fbadges%2F{}.json"
README = f"![d]({URL.format('dl-verifier-total')})\n"


def not_found() -> urllib.error.HTTPError:
    return urllib.error.HTTPError("u", 404, "Not Found", {}, None)  # type: ignore[arg-type]


class CombinedBadgeTest(unittest.TestCase):
    def run_main(self, fetch, key: str | None = "k", frozen: dict | None = None) -> tuple[int, dict, str]:
        env = {"PEPY_API_KEY": key} if key else {}
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            readme = Path(tmp) / "README.md"
            readme.write_text(README)
            with (
                mock.patch.dict(os.environ, env, clear=True),
                mock.patch.object(rb, "fetch", fetch),
                mock.patch.dict(rb.FROZEN, frozen if frozen is not None else {}, clear=True),
                redirect_stdout(io.StringIO()),
            ):
                rc = rb.main(["--out", str(out), "--readme", str(readme)])
            page = out / "downloads.md"
            return (
                rc,
                json.loads((out / "dl-verifier-total.json").read_text(encoding="utf-8")),
                page.read_text(encoding="utf-8") if page.exists() else "",
            )

    def test_sums_old_and_new_name(self) -> None:
        totals = {"probity-verify": 9034, "agent-evidence-verify": 1200}
        rc, doc, page = self.run_main(lambda url, headers=None: {"total_downloads": totals[url.rsplit("/", 1)[1]]})
        self.assertEqual(rc, 0)
        self.assertEqual(doc["message"], "↓ 10.2k")  # the same label as every other download badge
        self.assertEqual(doc["schemaVersion"], 1)
        self.assertIn("**10,234**", page)

    def test_a_frozen_name_is_not_read_live(self) -> None:
        seen = []

        def fetch(url, headers=None):
            seen.append(url)
            return {"total_downloads": 1200}

        rc, doc, _ = self.run_main(fetch, frozen={"probity-verify": (9034, "2026-11-08 16:44 UTC")})
        self.assertEqual(rc, 0)
        self.assertEqual(doc["message"], "↓ 10.2k")
        self.assertFalse(any(u.endswith("/probity-verify") for u in seen))

    def test_a_name_pepy_has_not_seen_counts_zero(self) -> None:
        def fetch(url, headers=None):
            if url.endswith("agent-evidence-verify"):
                raise not_found()
            return {"total_downloads": 9034}

        rc, doc, _ = self.run_main(fetch)
        self.assertEqual(rc, 0)
        self.assertEqual(doc["message"], "↓ 9k")

    def test_other_http_error_leaves_n_a(self) -> None:
        def fetch(url, headers=None):
            raise urllib.error.HTTPError(url, 500, "boom", {}, None)  # type: ignore[arg-type]

        rc, doc, _ = self.run_main(fetch)
        self.assertEqual(rc, 1)
        self.assertEqual(doc["message"], "↓ n/a")

    def test_no_pepy_key_never_writes_a_partial_total(self) -> None:
        rc, doc, _ = self.run_main(lambda url, headers=None: {"total_downloads": 5}, key=None)
        self.assertEqual(rc, 1)
        self.assertEqual(doc["message"], "↓ n/a")


class PagesTest(unittest.TestCase):
    def test_downloads_page_names_every_summed_package(self) -> None:
        names = rb.COMBINED["dl-verifier-total"]
        self.assertGreater(len(names), 1)
        page = rb.downloads_page({n: 1000 + i for i, n in enumerate(names)}, "2026-11-08 16:00 UTC")
        for n in names:
            self.assertIn(f"https://pepy.tech/projects/{n}", page)
        self.assertIn(f"**{sum(1000 + i for i in range(len(names))):,}**", page)
        self.assertIn("2026-11-08 16:00 UTC", page)

    def test_downloads_page_not_rewritten_for_time_alone(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            doc = out / rb.DOWNLOADS_DOC
            totals = {"a": 1, "b": 2}
            doc.write_text(rb.downloads_page(totals, "2026-01-01 00:00 UTC"), encoding="utf-8")
            before = doc.read_text(encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                rb.refresh_one(out, "dl-x-total", lambda: totals)
            self.assertEqual(doc.read_text(encoding="utf-8"), before)


if __name__ == "__main__":
    unittest.main()
