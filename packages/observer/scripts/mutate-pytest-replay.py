"""Mutation check for the pytest replay of sealed ids: every mutant must turn the tests red.

Each mutant deletes or weakens one rule: the parent's count and its repeats, the purity and
fresh-child checks, the failure type no test can catch, the module and attribute limits, the
refused remote names, the argv and path checks, the verifier's own count in the grade, and the
isolation reading of replay-covered worker commands. Each is applied to the source, its tests
run (without bytecode, so a restored file is never measured through a stale cache), and the
file is restored. Run from ``packages/observer`` in an environment with the ``test`` and
``done`` extras:

    python scripts/mutate-pytest-replay.py
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

DONE = Path("src/probity_observer/done")
REPLAY = DONE / "pytest_replay.py"
RUNNER = DONE / "runner.py"
GRADE = DONE / "verify_run.py"
CONTRACT = DONE / "contract.py"
UNIT = ["tests/done/test_pytest_replay.py"]
PIPELINE = ["tests/done/test_grade_pipeline.py"]
MUTANTS = [
    # The parent counts every repeat of every test.
    (REPLAY, UNIT, "        self.repeats = max(1, repeats)", "        self.repeats = 1"),
    (REPLAY, UNIT, '            counts[report.outcome] = counts.get(report.outcome, 0) + 1',
     '            counts["passed"] = counts.get("passed", 0) + 1'),
    # Purity and the fresh child.
    (REPLAY, UNIT, '    elif impure:\n        failure = "answers differ on one request"',
     '    elif False:\n        failure = "answers differ on one request"'),
    (REPLAY, UNIT, "    for key in order:\n        with Child(", "    for key in []:\n        with Child("),
    # No test can catch a failure to answer.
    (REPLAY, UNIT, "class CandidateFailed(BaseException):", "class CandidateFailed(Exception):"),
    (REPLAY, UNIT, "              if isinstance(value, type) and issubclass(value, Exception)}",
     "              if isinstance(value, type) and issubclass(value, BaseException)}"),
    # A module handle must be the candidate's; nothing may be set on a remote module.
    (REPLAY, UNIT, "        if found.split(\".\", 1)[0] not in session.remote:",
     "        if False:"),
    (REPLAY, UNIT, '        if (name.startswith("__") and name.endswith("__")) or isinstance(item, RemoteModule):',
     '        if True:'),
    # Remote names the parent holds are refused.
    (REPLAY, UNIT, " or name in sys.modules\n", "\n"),
    (REPLAY, UNIT, "                or os.path.exists(os.path.join(root, name))\n", "\n"),
    # Calls and reads are counted, imports are not.
    (REPLAY, UNIT, '        keys = [key for key, request in self.requests.items() if request["op"] != "import"]',
     '        keys = []'),
    # A replay that never reached the candidate is no pass; a src layout is served.
    (REPLAY, UNIT, "    elif not calls:\n", "    elif False:\n"),
    (REPLAY, UNIT, "        sys.path.insert(1, source)", "        pass"),
    (CONTRACT, UNIT, '    trees += [tree / "src" for tree in trees if (tree / "src").is_dir()',
     '    trees += [tree / "src" for tree in trees if False and (tree / "src").is_dir()'),
    (CONTRACT, UNIT, "    kept = [test_id for test_id in passing if _under(file(test_id), protected)]",
     "    kept = list(passing)"),
    # The argv and the sealed paths.
    (RUNNER, UNIT, '            or items[PYTEST_IDS_FROM - 1] != "--" or not items[9].isdigit()):',
     '            or not items[9].isdigit()):'),
    (RUNNER, UNIT, "    return found if found == sealed or sealed in found.parents else None",
     "    return found"),
    (RUNNER, UNIT, "    if not remote or any(not name.isidentifier() for name in remote):",
     "    if not remote:"),
    # The grade reads the replay's own count, and covered worker runs only add failures.
    (GRADE, PIPELINE, '            if "ids" in item and is_pytest_replay(item["argv"]):',
     '            if False:'),
    (GRADE, PIPELINE, '    return "exe" in item or (bool(item.get("ids")) and not is_replay(item["argv"])',
     '    return "exe" in item or (False and not is_replay(item["argv"])'),
    (GRADE, UNIT, '    replayed = {(item["id"].startswith("heldout"), test_id) for item in commands',
     '    replayed = {(False, test_id) for item in commands'),
    # The contract seals the replays, and only for protected test files.
    (CONTRACT, PIPELINE, "        commands += pytest_replays(", "        commands += [] and pytest_replays("),
    (CONTRACT, PIPELINE, '            ("heldout-fail-to-pass", hidden, "../heldout/tree", True, "fail")):',
     '            ("heldout-fail-to-pass", hidden, None, True, "fail")):'),
    (CONTRACT, UNIT, "            if entry.is_symlink():\n                continue",
     "            if False:\n                continue"),
]


def run(tests: list[str]) -> int:
    return subprocess.run([sys.executable, "-B", "-m", "pytest", "-q", "-x", "-p",
                           "no:cacheprovider", *tests], capture_output=True,
                          check=False).returncode


def main() -> int:
    if run(UNIT + PIPELINE) != 0:
        print("BASELINE RED")
        return 1
    survived = 0
    for index, (path, tests, old, new) in enumerate(MUTANTS):
        source = path.read_text()
        if source.count(old) != 1:
            print(f"MUTANT {index} NOT APPLICABLE ({path.name})")
            survived += 1
            continue
        try:
            path.write_text(source.replace(old, new, 1))
            code = run(tests)
        finally:
            path.write_text(source)
        print(f"MUTANT {index} {path.name} {'KILLED' if code != 0 else 'SURVIVED'}")
        survived += code == 0
    print(f"MUTANTS {len(MUTANTS)} surviving={survived}")
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main())
