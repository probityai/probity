"""Mutation check for the pytest replay of sealed ids: every mutant must turn the tests red.

Each mutant deletes or weakens one rule: the parent's count and its repeats, the purity and
fresh-child checks, the failure type no test can catch, the module and attribute limits, the
refused remote names, the argv and path checks, the verifier's own count in the grade, the
isolation reading of replay-covered worker commands, the proof of which ids reduce to one
sealed comparison, and the parent's own enforcement of it (the instrumented comparison, its
one call and strict type, a pass only after it ran, no candidate data outside it, boolean
comparisons made both ways), the refusal of a function a call returns, and the finder
that serves sealed code only. Each is applied to the source, its tests
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
PROOF = DONE / "pytest_proof.py"
UNIT = ["tests/done/test_pytest_replay.py"]
PROVE = ["tests/done/test_pytest_proof.py"]
PIPELINE = ["tests/done/test_grade_pipeline.py"]
MUTANTS = [
    # The parent counts every repeat of every test.
    (REPLAY, UNIT, "        self.repeats = max(1, repeats)", "        self.repeats = 1"),
    (REPLAY, UNIT, '            counts[outcome] = counts.get(outcome, 0) + 1',
     '            counts["passed"] = counts.get("passed", 0) + 1'),
    # Purity and the fresh child.
    (REPLAY, UNIT, '    elif impure:\n        failure = "answers differ on one request"',
     '    elif False:\n        failure = "answers differ on one request"'),
    (REPLAY, UNIT, "        if _answer(reply) != session.answers[key][0]:\n            found.append(key)",
     "        if False:\n            found.append(key)"),
    (REPLAY, UNIT, "    fresh_mismatch = fresh_mismatches(request, session, order, timeout)",
     "    fresh_mismatch = []"),
    # No test can catch a failure to answer.
    (REPLAY, UNIT, "class CandidateFailed(BaseException):", "class CandidateFailed(Exception):"),
    (REPLAY, UNIT, "              if isinstance(value, type) and issubclass(value, Exception)}",
     "              if isinstance(value, type) and issubclass(value, BaseException)}"),
    # A malformed reply never raises an exception a test could expect.
    (REPLAY, UNIT, "        if not isinstance(reply, dict):\n", "        if False:\n"),
    (REPLAY, UNIT, "            raise CandidateFailed(\"malformed raise\")", "            pass"),
    (REPLAY, UNIT, "            if type(args) is not tuple:", "            if False:"),
    # A module handle must be the candidate's; nothing may be set on a remote module.
    (REPLAY, UNIT, "                or found.split(\".\", 1)[0] not in session.remote):",
     "                or False):"),
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
    # The compiler replays only proven ids, visible, kept and held-out alike.
    (CONTRACT, UNIT, "    visible, _ = pytest_proof.proven(shown, fail)", "    visible = list(fail)"),
    (CONTRACT, UNIT, "    kept, _ = pytest_proof.proven(shown, passing)", "    kept = list(passing)"),
    (CONTRACT, UNIT, "    hidden, _ = pytest_proof.proven(overlaid, fail)", "    hidden = list(fail)"),
    (CONTRACT, UNIT, '    overlaid = pytest_proof.Sources([held / "tree", root], remote)',
     "    overlaid = pytest_proof.Sources([root], remote)"),
    # The proof: only sealed comparisons, of one remote call, against a sealed value.
    (PROOF, PROVE, "            if not isinstance(statement, ast.Assert):",
     "            if not isinstance(statement, (ast.Assert, ast.Expr, ast.For, ast.If)):"),
    (PROOF, PROVE, "                and isinstance(test.ops[0], ast.Eq) and len(test.comparators) == 1):",
     "                and len(test.comparators) == 1):"),
    (PROOF, PROVE, "            if value is None:", "            if False:"),
    (PROOF, PROVE, "            if isinstance(site.expected, ast.Name) and site.expected.id in echoed:",
     "            if False:"),
    (PROOF, PROVE, '        if binding.module.split(".", 1)[0] not in remote:', "        if False:"),
    (PROOF, PROVE, '        if alias.name.split(".", 1)[0] not in remote:', "        if False:"),
    (PROOF, PROVE, "        if len(nodes) != 1:", "        if not nodes:"),
    (PROOF, PROVE, "        if set(params) != set(table):", "        if False:"),
    (PROOF, PROVE, "            if not (isinstance(decorator, ast.Call) and _chain(decorator.func) == list(PARAMETRIZE)",
     "            if not (isinstance(decorator, ast.Call)"),
    (PROOF, PROVE, '                _literal(argument, line, "argument")', "                pass"),
    (PROOF, PROVE, "        if not proof.sites:", "        if False:"),
    (PROOF, PROVE, "    return {callee for callee, values in seen.items() if values != {True, False}}",
     "    return set()"),
    (PROOF, PROVE, '        if names[0] in params:', "        if False:"),
    (PROOF, PROVE, '            self.error = "a star import can bind any name"', "            pass"),
    (PROOF, PROVE, "    if len(parts) != 2 or not parts[0].endswith(\".py\"):", "    if False:"),
    # The parent: a pass needs the instrumented run, which compares here, strictly, once.
    (REPLAY, UNIT, '                if outcome == "passed" and report.nodeid not in self.verified:',
     "                if False:"),
    (REPLAY, UNIT, "            self.unproven[item.nodeid] = proof\n            raise CandidateFailed",
     "            self.unproven[item.nodeid] = proof\n            return pytest_proof\n            raise CandidateFailed"),
    (REPLAY, UNIT, "        if calls != 1:", "        if False:"),
    (REPLAY, UNIT, "        if not strict_eq(result, expected):", "        if result != expected:"),
    (REPLAY, UNIT, "            if not handle(request, reply):", "            if False:"),
    (REPLAY, UNIT, "                    reply = {\"error\": OUTSIDE}\n", "                    pass\n"),
    (REPLAY, UNIT, "    if session.outside:\n        failure = OUTSIDE", "    if False:\n        failure = OUTSIDE"),
    (REPLAY, UNIT, "        if (not all(part.isidentifier() for part in found.split(\".\"))\n                or ",
     "        if ("),
    (REPLAY, UNIT, "        found = sorted(nodeid for nodeid, callees in self.boolean_items.items() if callees & weak)",
     "        found = []"),
    (REPLAY, UNIT, '    elif pytest_plugins.passed(counter.items, request["ids"]) != len(request["ids"]):',
     "    elif False:"),
    # The nonce, the call that returns a function, the finder and the order of the checks.
    (REPLAY, UNIT, "    if call:\n        raise_for(reply)", "    if False:\n        raise_for(reply)"),
    (REPLAY, UNIT, " or not self.sealed_importer():", ":"),
    (REPLAY, UNIT, "    import _pytest.runner  # noqa: F401\n    import pytest  # noqa: F401\n", ""),
]


def run(tests: list[str]) -> int:
    return subprocess.run([sys.executable, "-B", "-m", "pytest", "-q", "-x", "-p",
                           "no:cacheprovider", *tests], capture_output=True,
                          check=False).returncode


def main() -> int:
    if run(PROVE + UNIT + PIPELINE) != 0:
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
