#!/usr/bin/env python3
"""Tests for version-pins.py, including the mutation check on this repository.

The mutation check is the one that matters: it copies this repository's tracked
pages into a scratch checkout, makes one tracked pin stale, and requires the
check to go red. A check that stays green on a stale pin guards nothing, and
only running it against a planted fault shows which kind this one is.
Standard library only; run with `python3 scripts/version-pins-test.py`.
"""

from __future__ import annotations

import importlib.util
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SPEC = importlib.util.spec_from_file_location("version_pins", HERE / "version-pins.py")
assert SPEC and SPEC.loader
vp = importlib.util.module_from_spec(SPEC)
sys.modules["version_pins"] = vp
SPEC.loader.exec_module(vp)


def git_repo(files: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp(prefix="version-pins-"))
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text, encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
    return root


CONFIG = """
repository = "probityai/demo"
registry_pages = { "README.md" = "pypi:demo" }
[[own]]
key = "pypi:demo"
manifest = "pyproject.toml"
pages = ["README.md"]
[family]
"pypi:agent-evidence-vectors" = "0.30.0"
"crates:dsse" = "0.1.6"
"npm:dsse" = "0.1.0"
"action:agent-evidence-vectors" = "0.30.0"
[scan]
historical = ["docs/paper/**"]
"""
PYPROJECT = '[project]\nname = "demo"\nversion = "1.2.3"\n'


class Fixture(unittest.TestCase):
    def run_check(self, readme: str, extra: dict[str, str] | None = None):
        files = {"version-pins.toml": CONFIG, "pyproject.toml": PYPROJECT, "README.md": readme}
        files.update(extra or {})
        root = git_repo(files)
        self.addCleanup(shutil.rmtree, root)
        cfg = vp.load_config(root)
        findings, _ = vp.scan(cfg)
        return root, cfg, findings

    def test_current_pins_pass(self):
        _, _, found = self.run_check(
            "pip install demo==1.2.3\nuvx agent-evidence-vectors==0.30.0\n"
            "cargo add dsse@=0.1.6\nnpm install dsse@0.1.0\n"
            "- uses: probityai/agent-evidence-vectors@v0.30.0\nVersion 1.2.3.\n"
        )
        self.assertEqual(found, [])

    def test_each_stale_form_is_found(self):
        _, _, found = self.run_check(
            "pip install demo==1.2.2\nuvx agent-evidence-vectors==0.29.2\n"
            "cargo add dsse@0.1.5\nnpm i dsse@0.0.9\n"
            "- uses: probityai/agent-evidence-vectors@v0.26.0\nVersion 1.0.0.\n"
            "the `dsse` (0.1.5) crate\n| x | 0.29.0 on PyPI (`agent-evidence-vectors`) |\n"
        )
        self.assertEqual(len(found), 8, "\n".join(map(str, found)))

    def test_link_text_must_name_its_target(self):
        _, _, found = self.run_check(
            "[v0.30.0 release](https://github.com/probityai/agent-evidence-vectors/releases/tag/v0.26.0)\n"
        )
        self.assertTrue(any("link text says 0.30.0" in f.message for f in found), found)

    def test_registry_page_refuses_relative_links_and_write_fixes_them(self):
        root, cfg, found = self.run_check(
            "See [the guide](docs/guide.md) and ![demo](docs/demo.gif).\n",
            {"docs/guide.md": "x\n", "docs/demo.gif": "GIF89a"},
        )
        self.assertEqual(len(found), 2, found)
        vp.write(cfg)
        text = (root / "README.md").read_text()
        self.assertIn("https://github.com/probityai/demo/blob/main/docs/guide.md", text)
        self.assertIn("https://raw.githubusercontent.com/probityai/demo/main/docs/demo.gif", text)

    def test_own_link_to_a_missing_file_is_found(self):
        _, _, found = self.run_check("[gone](https://github.com/probityai/demo/blob/main/docs/gone.md)\n")
        self.assertTrue(any("does not hold" in f.message for f in found), found)

    def test_historical_pages_and_keep_markers_are_exempt(self):
        _, _, found = self.run_check(
            "pip install demo==1.0.0 <!-- version-pins: keep -->\n",
            {"docs/paper/README.md": "uvx agent-evidence-vectors==0.12.0\n",
             "CHANGELOG.md": "uvx agent-evidence-vectors==0.1.0\n"},
        )
        self.assertEqual(found, [])

    def test_write_renders_every_pin_from_its_owner(self):
        root, cfg, _ = self.run_check("pip install demo==1.0.0\nuvx agent-evidence-vectors==0.29.2\n")
        changed, remaining = vp.write(cfg)
        self.assertEqual((changed, remaining), (2, []))
        self.assertIn("demo==1.2.3", (root / "README.md").read_text())

    def test_a_bumped_manifest_turns_the_old_pins_red(self):
        root, _, found = self.run_check("pip install demo==1.2.3\n")
        self.assertEqual(found, [])
        (root / "pyproject.toml").write_text(PYPROJECT.replace("1.2.3", "1.3.0"))
        findings, _ = vp.scan(vp.load_config(root))
        self.assertEqual(len(findings), 1)

    def test_two_owners_for_one_package_is_a_config_error(self):
        bad = CONFIG + '\n[[own]]\nkey = "pypi:agent-evidence-vectors"\nmanifest = "pyproject.toml"\n'
        root = git_repo({"version-pins.toml": bad, "pyproject.toml": PYPROJECT})
        self.addCleanup(shutil.rmtree, root)
        with self.assertRaises(vp.ConfigError):
            vp.load_config(root)


class ThisRepository(unittest.TestCase):
    """The real pages pass, and a planted stale pin turns the check red."""

    def test_pages_agree(self):
        cfg = vp.load_config(ROOT)
        findings, _ = vp.scan(cfg)
        self.assertEqual(findings, [], "\n".join(map(str, findings)))

    def test_mutation_a_stale_pin_is_caught(self):
        cfg = vp.load_config(ROOT)
        rules = vp.pin_rules(cfg.entries)
        target = None
        for rel in vp.tracked_files(ROOT):
            if not vp.matches(rel, cfg.include) or vp.matches(rel, cfg.historical):
                continue
            if vp.matches(rel, cfg.skip):
                continue
            text = (ROOT / rel).read_text(encoding="utf-8", errors="replace")
            for rule in rules:
                m = rule.pattern.search(text)
                if m and m.group(1) == rule.entry.version and rule.line_kind is None:
                    target = (rel, text, m.span(1))
                    break
            if target:
                break
        if target is None:
            self.fail("no tracked pin on any page to mutate; the check is vacuous here")
        rel, text, (start, end) = target
        stale = "0.0.1" if text[start:end] != "0.0.1" else "0.0.2"
        scratch = Path(tempfile.mkdtemp(prefix="version-pins-mutant-"))
        self.addCleanup(shutil.rmtree, scratch)
        subprocess.run(["git", "clone", "-q", "--no-hardlinks", str(ROOT), str(scratch / "r")], check=True)
        mutant = scratch / "r"
        for name in (vp.CONFIG, "scripts/version-pins.py"):
            shutil.copy2(ROOT / name, mutant / name)
        for item in vp.load_config(ROOT).entries:
            if item.manifest:
                (mutant / item.manifest).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / item.manifest, mutant / item.manifest)
        (mutant / rel).write_text(text[:start] + stale + text[end:], encoding="utf-8")
        subprocess.run(["git", "-C", str(mutant), "add", "-A"], check=True)
        done = subprocess.run(
            [sys.executable, str(mutant / "scripts/version-pins.py"), "check", "--root", str(mutant)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(done.returncode, 1, f"the check stayed green on {rel}:\n{done.stdout}")
        self.assertTrue(re.search(re.escape(stale), done.stdout), done.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
