#!/usr/bin/env python3
"""Tests for readme-lint.py: each rule fails on the input it exists to refuse.

Run with: python3 scripts/readme-lint-test.py
"""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("readme_lint", HERE / "readme-lint.py")
assert _spec and _spec.loader
lint = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(lint)

GOOD = """# thing

One sentence about the thing.

```bash
pip install thing==1.0.0
```

See [the guide](docs/GUIDE.md) and [the site](https://example.org/).
"""


class ReadmeLintTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "docs").mkdir()
        (self.root / "docs" / "GUIDE.md").write_text("# guide\n")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def run_lint(self, text: str, *args: str) -> int:
        readme = self.root / "README.md"
        readme.write_text(text)
        status: int = lint.main([str(readme), *args])
        return status

    def test_short_readme_passes(self) -> None:
        self.assertEqual(self.run_lint(GOOD), 0)

    def test_over_the_word_limit_fails(self) -> None:
        long = GOOD + "\n" + ("word " * 700) + "\n"
        self.assertEqual(self.run_lint(long), 1)

    def test_limit_is_a_parameter(self) -> None:
        self.assertEqual(self.run_lint(GOOD, "--max-words", "5"), 1)

    def test_code_is_not_counted_as_prose(self) -> None:
        code = "```\n" + ("token " * 2000) + "\n```\n"
        self.assertEqual(self.run_lint(GOOD + code), 0)

    def test_link_targets_and_tags_are_not_words(self) -> None:
        text = '<p align="center"><img src="docs/GUIDE.md" alt="x"></p>\n\none two [three](https://example.org/c/d/e/f)'
        self.assertEqual(lint.prose_words(text), 3)

    def test_no_code_block_fails(self) -> None:
        self.assertEqual(self.run_lint("# thing\n\nJust prose, no install line.\n"), 1)

    def test_code_block_below_the_first_screen_fails(self) -> None:
        late = "# thing\n" + "\n" * 60 + "```\npip install thing==1\n```\n"
        self.assertEqual(self.run_lint(late), 1)
        self.assertEqual(self.run_lint(late, "--first-screen", "80"), 0)

    def test_dead_relative_link_fails(self) -> None:
        self.assertEqual(self.run_lint(GOOD + "\n[moved](docs/GONE.md)\n"), 1)

    def test_dead_image_and_reference_definition_fail(self) -> None:
        self.assertEqual(self.run_lint(GOOD + '\n<img src="assets/gone.svg">\n'), 1)
        self.assertEqual(self.run_lint(GOOD + "\n[x]: docs/GONE.md\n"), 1)

    def test_anchor_on_a_live_file_passes(self) -> None:
        self.assertEqual(self.run_lint(GOOD + "\n[part](docs/GUIDE.md#part)\n"), 0)

    def test_links_inside_code_are_ignored(self) -> None:
        self.assertEqual(self.run_lint(GOOD + "\n```\n[x](docs/GONE.md)\n```\n"), 0)

    def test_github_api_badge_fails(self) -> None:
        bad = "# thing\n\n[![CI](https://img.shields.io/github/actions/workflow/status/o/r/ci.yml)](https://example.org)\n"
        self.assertEqual(self.run_lint(bad + GOOD.split("\n", 1)[1]), 1)
        for kind in ("stars/o/r", "license/o/r", "v/release/o/r", "issues/o/r"):
            url = f'<img alt="x" src="https://img.shields.io/github/{kind}">'
            self.assertEqual(self.run_lint(GOOD + "\n" + url + "\n"), 1, kind)

    def test_other_shields_badges_pass(self) -> None:
        ok = '\n<img alt="v" src="https://img.shields.io/pypi/v/thing">\n'
        self.assertEqual(self.run_lint(GOOD + ok), 0)

    def _row(self, *alts: str) -> str:
        def href(a: str) -> str:
            return "https://pepy.tech/projects/thing" if "downloads" in a.lower() else "https://example.org"

        badges = "\n".join(f'<a href="{href(a)}"><img alt="{a}" src="https://example.org/{a}.svg"></a>' for a in alts)
        return "# thing\n\n<p>\n" + badges + "\n</p>\n" + GOOD.split("\n", 1)[1]

    def test_badge_row_in_order_passes(self) -> None:
        self.assertEqual(self.run_lint(self._row("CI", "Version", "Downloads", "License", "Stars")), 0)
        self.assertEqual(self.run_lint(self._row("CI", "Version", "Downloads", "License", "Stars", "Checked with Probity")), 0)
        self.assertEqual(self.run_lint(self._row("CI", "License")), 0)
        self.assertEqual(self.run_lint(self._row("PyPI", "Downloads (PePy)")), 0)

    def test_badge_row_out_of_order_fails(self) -> None:
        self.assertEqual(self.run_lint(self._row("CI", "License", "Version", "Downloads", "Stars")), 1)
        self.assertEqual(self.run_lint(self._row("Stars", "CI")), 1)
        self.assertEqual(self.run_lint(self._row("CI", "Checked with Probity", "Stars")), 1)

    def test_markdown_badge_row_is_read_too(self) -> None:
        md = "# thing\n\n[![License](https://example.org/l.svg)](https://example.org)\n[![CI](https://example.org/c.svg)](https://example.org)\n"
        self.assertEqual(self.run_lint(md + GOOD.split("\n", 1)[1]), 1)

    def test_prose_paragraph_is_not_a_badge_row(self) -> None:
        self.assertEqual(self.run_lint(GOOD), 0)
        self.assertEqual(lint.top_badge_row(GOOD), [])

    def test_downloads_badge_linking_pepy_passes(self) -> None:
        html = '\n<a href="https://pepy.tech/projects/thing"><img alt="Downloads" src="https://example.org/d.svg"></a>\n'
        md = '\n[![thing downloads](https://example.org/d.svg)](https://pepy.tech/projects/thing)\n'
        self.assertEqual(self.run_lint(GOOD + html + md), 0)

    def test_summed_badge_linking_the_current_pepy_page_passes(self) -> None:
        url = "https://pepy.tech/projects/agent-evidence-verify"
        html = f'\n<a href="{url}"><img height="16" alt="Downloads" src="assets/badges/dl-thing-total.svg"></a>\n'
        md = f'\n[![thing downloads](assets/badges/dl-thing-total.svg)]({url})\n'
        self.assertEqual(lint.bad_download_links(html + md), [])
        self.assertEqual(lint.bad_summed_links(html + md), [])

    def test_summed_badge_linking_the_downloads_page_fails(self) -> None:
        for url in ("https://github.com/probityai/probity/blob/main/docs/downloads.md", "docs/downloads.md"):
            html = f'\n<a href="{url}"><img height="16" alt="Downloads" src="assets/badges/dl-thing-total.svg"></a>\n'
            self.assertEqual(lint.bad_summed_links(html), [url], url)

    def test_downloads_badge_linking_pepy_compare_fails(self) -> None:
        for url in ("https://pepy.tech/compare?packages=a,b", "https://github.com/probityai/probity/blob/main/docs/other.md"):
            md = f'\n[![thing downloads](https://example.org/d.svg)]({url})\n'
            self.assertEqual(lint.bad_download_links(md), [url], url)

    def test_summed_badge_linking_one_project_page_fails(self) -> None:
        one = "https://pepy.tech/projects/new-name"
        html = f'\n<a href="{one}"><img alt="Downloads" src="assets/badges/dl-verifier-total.svg"></a>\n'
        md = f'\n[![new-name downloads](assets/badges/dl-verifier-total.svg)]({one})\n'
        self.assertEqual(lint.bad_download_links(html + md), [])  # a legal pepy link on its own
        self.assertEqual(lint.bad_summed_links(html + md), [one, one])
        cmp = "https://pepy.tech/compare?packages=old-name,new-name"
        self.assertEqual(lint.bad_summed_links(html.replace(one, cmp)), [cmp])

    def test_summed_badge_is_checked_by_the_linter(self) -> None:
        one = "https://pepy.tech/projects/new-name"
        img = "https://example.org/assets/badges/dl-verifier-total.svg"
        html = f'\n<a href="{one}"><img alt="Downloads" src="{img}"></a>\n'
        self.assertEqual(self.run_lint(GOOD + html), 1)
        both = html.replace(one, "https://pepy.tech/projects/agent-evidence-verify")
        self.assertEqual(self.run_lint(GOOD + both), 0)

    def test_downloads_badge_linking_pypi_fails(self) -> None:
        html = '\n<a href="https://pypi.org/project/thing/"><img height="16" alt="Downloads" src="https://example.org/d.svg"></a>\n'
        md = '\n[![thing DOWNLOADS](https://example.org/d.svg)](https://pypi.org/project/thing/)\n'
        self.assertEqual(self.run_lint(GOOD + html), 1)
        self.assertEqual(self.run_lint(GOOD + md), 1)
        self.assertEqual(lint.bad_download_links(html + md), ["https://pypi.org/project/thing/"] * 2)

    def test_downloads_badge_linking_npm_or_crates_passes(self) -> None:
        npm = '\n[![Downloads](https://example.org/d.svg)](https://www.npmjs.com/package/thing)\n'
        stat = '\n[![Downloads](https://example.org/d.svg)](https://npm-stat.com/charts.html?package=thing)\n'
        crate = '\n[![Downloads](https://example.org/d.svg)](https://crates.io/crates/thing)\n'
        self.assertEqual(self.run_lint(GOOD + npm + stat + crate), 0)

    def test_non_downloads_image_may_link_anywhere(self) -> None:
        other = '\n[![PyPI](https://example.org/v.svg)](https://pypi.org/project/thing/)\n'
        self.assertEqual(self.run_lint(GOOD + other), 0)

    def test_badge_cache_above_an_hour_fails(self) -> None:
        slow = "![Version](https://img.shields.io/pypi/v/thing?cacheSeconds=86400)"
        self.assertEqual(self.run_lint(GOOD + "\n" + slow + "\n"), 1)
        self.assertEqual(self.run_lint(GOOD + "\n" + slow.replace("86400", "3601") + "\n"), 1)
        self.assertEqual(
            self.run_lint(GOOD + '\n<img src="https://img.shields.io/pypi/v/thing?cacheSeconds=3600">\n'),
            0,
        )
        self.assertEqual(
            self.run_lint(GOOD + "\n![Version](https://img.shields.io/pypi/v/thing)\n"), 0
        )

    def test_unreadable_readme_exits_two(self) -> None:
        self.assertEqual(lint.main([str(self.root / "MISSING.md")]), 2)


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False, verbosity=1).result.wasSuccessful() else 1)
