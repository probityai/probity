"""A committed pin of a live file must match its bytes (scripts/pinned-digests.py)."""

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("pinned_digests", ROOT / "scripts/pinned-digests.py")
CHECK = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECK
SPEC.loader.exec_module(CHECK)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


class PinnedDigests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        CHECK.ROOT, self.saved = self.root, CHECK.ROOT
        self.addCleanup(setattr, CHECK, "ROOT", self.saved)
        profile = self.root / "pkg" / "interop" / "profile"
        (profile / "src" / "mod").mkdir(parents=True)
        (self.root / "pkg" / "pyproject.toml").write_bytes(b"dependencies = []\n")
        (profile / "requirements.lock").write_bytes(b"a==1\n")
        (profile / "src" / "mod" / "reader.py").write_bytes(b"x = 1\n")
        (profile / "retained").mkdir()
        self.pins = profile / "pins.json"
        self.write({"ownedFiles": {"requirements.lock": sha(b"a==1\n")},
                    "pythonSources": {"mod/reader.py": sha(b"x = 1\n")},
                    "source_files": {"pyproject.toml": {"sha256": sha(b"dependencies = []\n"),
                                                        "git_blob_sha1": CHECK.git_blob(b"dependencies = []\n")}},
                    "commit": "0" * 40})
        (profile / "retained" / "old.json").write_text(json.dumps({"requirements.lock": "1" * 64}))

    def write(self, value):
        self.pins.write_text(json.dumps(value, indent=2) + "\n")
        subprocess.run(["git", "init", "-q"], cwd=self.root, check=True)
        subprocess.run(["git", "add", "-A"], cwd=self.root, check=True)

    def test_current_pins_pass_and_retained_records_are_not_read(self):
        self.assertEqual(CHECK.stale({}), [])

    def test_a_dependency_change_leaves_every_kind_of_pin_stale(self):
        (self.root / "pkg" / "pyproject.toml").write_bytes(b'dependencies = ["records"]\n')
        (self.root / "pkg" / "interop" / "profile" / "requirements.lock").write_bytes(b"a==1\nrecords==1\n")
        (self.root / "pkg" / "interop" / "profile" / "src" / "mod" / "reader.py").write_bytes(b"x = 2\n")
        found = {(pin.name, pin.kind) for pin in CHECK.stale({})}
        self.assertEqual(found, {("requirements.lock", "sha256"), ("mod/reader.py", "sha256"),
                                 ("pyproject.toml", "sha256"), ("pyproject.toml", "blob")})
        self.assertEqual(CHECK.update(CHECK.stale({})), 0)
        self.assertEqual(CHECK.stale({}), [])

    def test_historical_and_alias_rules(self):
        (self.root / "pkg" / "pyproject.toml").write_bytes(b"changed\n")
        rule = {"historical": [{"file": "pkg/interop/profile/pins.json", "name": "pyproject.toml"}]}
        self.assertEqual(CHECK.stale(rule), [])
        self.write({"sources/x/reader.py": sha(b"old\n")})
        alias = {"alias": [{"file": "*/pins.json", "prefix": "sources/x/", "to": "pkg/interop/profile/src/mod/"}]}
        self.assertEqual([pin.name for pin in CHECK.stale(alias)], ["sources/x/reader.py"])


if __name__ == "__main__":
    unittest.main()
