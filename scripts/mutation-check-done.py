"""Break each done-receipt adapter rule in a copy of the source; its tests must fail.

Each mutation replaces one exact snippet (which must occur once) in a copy of
src/ and runs the adapter's tests against that copy. A mutation the tests still
pass is a rule nothing checks, and the script exits 1 naming it. Each test file
must first pass on the unmutated copy, or the script exits 2 without a result.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ADAPTERS = "src/probity_verify/adapters/"
RECORDS = ADAPTERS + "done_records.py"
PROTECTED = (ADAPTERS + "protected_paths.py", "tests/test_protected_paths.py")

MUTATIONS = [
    ("protected: rename or link target ignored", *PROTECTED,
     'hit(event["path"]) or ("target" in event and hit(event["target"]))',
     'hit(event["path"])'),
    ("protected: excluded segments still protected", RECORDS, PROTECTED[1],
     'return not set(below) & set(entry.get("exclude", ()))', "return True"),
    ("protected: one mutation type visible is enough", *PROTECTED,
     "required_types=records.MUTATION_TYPES", 'required_types=frozenset({"write"})'),
    ("protected: changed final tree ignored", *PROTECTED,
     "        if changed:\n", "        if False:\n"),
    ("protected: self-reported tree accepted", *PROTECTED,
     "            and records.independent(tree, tree_pin, observed_party)):",
     "            ):"),
    ("protected: supported without a final tree", *PROTECTED,
     '    if tree_check["status"] != "met":', "    if False:"),
    ("records: scope from the record alone", RECORDS, PROTECTED[1],
     'record["witness_scope"] == pin["witness_scope"] == "EXTERNAL"',
     'record["witness_scope"] == "EXTERNAL"'),
]


def survives(name: str, source: str, tests: str, old: str | None, new: str) -> bool:
    with tempfile.TemporaryDirectory() as scratch:
        copy = Path(scratch) / "src"
        shutil.copytree(ROOT / "src", copy)
        target = copy / Path(source).relative_to("src")
        text = target.read_text()
        if old is None:
            new = old = text
        elif text.count(old) != 1:
            raise SystemExit(f"mutation-check: snippet for {name!r} occurs "
                             f"{text.count(old)} times in {source}")
        target.write_text(text.replace(old, new))
        env = {**os.environ, "PYTHONPATH": str(copy), "PYTHONDONTWRITEBYTECODE": "1"}
        completed = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider",
             str(ROOT / tests)], cwd=ROOT, env=env, capture_output=True, text=True,
            check=False)
    return completed.returncode == 0


def main() -> int:
    for tests in sorted({mutation[2] for mutation in MUTATIONS}):
        if not survives("control", RECORDS, tests, None, ""):
            print(f"mutation-check: {tests} fails on the unmutated copy; nothing measured")
            return 2
    survivors = []
    for name, source, tests, old, new in MUTATIONS:
        alive = survives(name, source, tests, old, new)
        print(f"{'SURVIVED' if alive else 'killed  '}  {name}")
        if alive:
            survivors.append(name)
    print(f"mutation-check: {len(MUTATIONS) - len(survivors)} of {len(MUTATIONS)} killed")
    return 1 if survivors else 0


if __name__ == "__main__":
    raise SystemExit(main())
