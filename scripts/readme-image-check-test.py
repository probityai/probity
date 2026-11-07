#!/usr/bin/env python3
"""Tests for readme-image-check.py."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("ric", Path(__file__).with_name("readme-image-check.py"))
assert spec and spec.loader
ric = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ric)

TEXT = (
    "[![a](https://x.test/a.svg)](https://x.test)\n"
    '<img alt="b" src="https://x.test/b.svg">\n'
    "![rel](docs/local.png)\n"
)


class ImageCheckTest(unittest.TestCase):
    def run_check(self, answers: dict[str, tuple[int, str]]) -> list[str]:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "README.md"
            path.write_text(TEXT)
            return ric.check(path, lambda url: answers[url])

    def test_finds_markdown_and_html_remote_images_only(self) -> None:
        self.assertEqual(ric.image_urls(TEXT), ["https://x.test/a.svg", "https://x.test/b.svg"])

    def test_all_images_pass(self) -> None:
        ok = (200, "image/svg+xml; charset=utf-8")
        self.assertEqual(self.run_check({"https://x.test/a.svg": ok, "https://x.test/b.svg": ok}), [])

    def test_404_json_fails(self) -> None:
        ok = (200, "image/svg+xml")
        out = self.run_check({"https://x.test/a.svg": (404, "application/json"), "https://x.test/b.svg": ok})
        self.assertEqual(len(out), 1)
        self.assertIn("404", out[0])

    def test_200_non_image_fails(self) -> None:
        ok = (200, "image/png")
        out = self.run_check({"https://x.test/a.svg": (200, "text/html"), "https://x.test/b.svg": ok})
        self.assertIn("not an image", out[0])

    def test_no_answer_fails(self) -> None:
        out = self.run_check({"https://x.test/a.svg": (0, ""), "https://x.test/b.svg": (200, "image/png")})
        self.assertIn("nothing", out[0])


if __name__ == "__main__":
    unittest.main()
