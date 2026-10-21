"""Mutation check for the pytest replay of sealed ids: every mutant must turn the tests red.

Each mutant deletes or weakens one rule: the parent's count and its repeats, the purity and
fresh-child checks, the failure type no test can catch, the module and attribute limits, the
refused remote names, the argv and path checks, the verifier's own count in the grade, the
isolation reading of replay-covered worker commands, the proof of which ids reduce to one
sealed comparison, and the parent's own enforcement of it (each answer sealed and compared
once, right after its call, with its sealed value and strictly; a pass only after every
comparison ran; no candidate data outside a run; boolean comparisons made both ways), the
request nonce, the refusal of a function a call returns,
and the finder that serves sealed code only. Each is applied to the source, its tests
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
HARNESS = DONE / "replay.py"
STALLS = [f"tests/done/test_replay.py::{name}" for name in (
    "test_a_partial_reply_line_is_stopped_at_the_call_limit",
    "test_lines_are_read_one_at_a_time_and_a_line_has_a_limit",
    "test_a_stall_after_a_definitive_failure_never_reads_as_no_answer",
    "test_answers_given_before_a_stall_decide_the_determinism_probe",
    "test_a_mismatch_given_before_a_stall_decides_the_type_strict_probe",
    "test_a_wrong_answer_then_a_stalled_fresh_child_stays_definitive",
    "test_a_stalled_fresh_child_never_hides_a_later_wrong_fresh_answer",
    "test_a_run_whose_budget_runs_out_is_no_answer",
    "test_a_type_strict_run_cut_at_its_budget_keeps_the_mismatch_it_was_given")]
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
    (REPLAY, UNIT, '    if not isinstance(reply, dict) or reply.get("nonce") != nonce:',
     '    if reply.get("nonce") != nonce:'),
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
    (PROOF, PROVE, "            if found and all(leaf is None for leaf in found):",
     "            if False:"),
    # None and booleans are judged at every place inside a sealed value, not only at the top.
    (PROOF, PROVE, "    if kind is list or kind is tuple:", "    if False:"),
    (PROOF, PROVE, "    elif kind is dict:", "    elif False:"),
    (PROOF, PROVE, "            yield callee + path, leaf", "            yield callee, leaf"),
    # A name an except clause binds is a binding like any other.
    (PROOF, PROVE, "        elif isinstance(node, ast.ExceptHandler) and node.name:",
     "        elif False:"),
    (REPLAY, UNIT,
     "        for key, leaf in pytest_proof.boolean_leaves(self.proof.sites[index].callee, expected):",
     "        for key, leaf in ([(self.proof.sites[index].callee, expected)]\n"
     "                          if type(expected) is bool else []):"),
    (PROOF, PROVE, "            if isinstance(site.expected, ast.Name) and site.expected.id in echoed:",
     "            if False:"),
    (PROOF, PROVE, '        if binding.module.split(".", 1)[0] not in remote:', "        if False:"),
    (PROOF, PROVE, '        if alias.name.split(".", 1)[0] not in remote:', "        if False:"),
    (PROOF, PROVE, "        if len(nodes) != 1:", "        if not nodes:"),
    (PROOF, PROVE, "        if set(params) != set(table):", "        if False:"),
    (PROOF, PROVE, "            if not (isinstance(decorator, ast.Call) and _chain(decorator.func) == list(PARAMETRIZE)",
     "            if not (isinstance(decorator, ast.Call)"),
    (PROOF, PROVE, '                arguments = (_literal(argument, line, "argument"),)',
     "                arguments = ()"),
    (PROOF, PROVE, "                    plain(value)\n                except TypeError:\n"
     "                    raise Unproven(f\"{line}: an argument",
     "                    pass\n                except TypeError:\n"
     "                    raise Unproven(f\"{line}: an argument"),
    (PROOF, PROVE, "        if not proof.sites:", "        if False:"),
    (PROOF, PROVE, "    return {callee for callee, values in seen.items() if values != {True, False}}",
     "    return set()"),
    (PROOF, PROVE, '        if names[0] in params:', "        if False:"),
    (PROOF, PROVE, '            self.error = "a star import can bind any name"', "            pass"),
    (PROOF, PROVE, "    if len(parts) != 2 or not parts[0].endswith(\".py\"):", "    if False:"),
    # The parent: a pass needs the sealed run, each answer compared once, in order, strictly.
    (REPLAY, UNIT, '                if outcome == "passed" and report.nodeid not in self.verified:',
     "                if False:"),
    (REPLAY, UNIT, "            self.unproven[item.nodeid] = proof\n            raise CandidateFailed",
     "            self.unproven[item.nodeid] = proof\n            return pytest_proof\n            raise CandidateFailed"),
    (REPLAY, UNIT, "        if index >= len(self.expected) or len(self.compared) != index:",
     "        if index >= len(self.expected):"),
    (REPLAY, UNIT, "        if index >= len(self.expected) or len(self.compared) != index:",
     "        if len(self.compared) != index:"),
    (REPLAY, UNIT, "        if index != self.calls - 1 or len(self.compared) != index:", "        if False:"),
    (REPLAY, UNIT, "        if not strict_eq(other, expected):", "        if other != expected:"),
    (REPLAY, UNIT, "        return strict_eq(answer, expected)", "        return answer == expected"),
    (REPLAY, UNIT, '        raise CandidateFailed("a sealed answer is only compared")', "        return True"),
    (REPLAY, UNIT, "        return phase.wrap(found)", "        return found"),
    (REPLAY, UNIT, "        if self.phase is None or request[\"op\"] != \"call\":", "        if self.phase is None:"),
    (REPLAY, UNIT, "            if not handle(request, reply):", "            if False:"),
    (REPLAY, UNIT, "                    reply = {\"error\": OUTSIDE}\n", "                    pass\n"),
    (REPLAY, UNIT, "    if session.outside:\n        failure = OUTSIDE", "    if False:\n        failure = OUTSIDE"),
    (REPLAY, UNIT, "        if (not all(part.isidentifier() for part in found.split(\".\"))\n                or ",
     "        if ("),
    (REPLAY, UNIT, "        found = sorted(nodeid for nodeid, keys in self.boolean_items.items() if keys & weak)",
     "        found = []"),
    (REPLAY, UNIT, '    elif pytest_plugins.passed(counter.items, request["ids"]) != len(request["ids"]):',
     "    elif False:"),
    # The nonce, the call that returns a function, the finder and the order of the checks.
    (REPLAY, UNIT, '        reply["nonce"] = nonce\n', "\n"),
    (REPLAY, UNIT, "    if call:\n        raise_for(reply)", "    if False:\n        raise_for(reply)"),
    (REPLAY, UNIT, " or not self.sealed_importer():", ":"),
    (REPLAY, UNIT, "    import _pytest.runner  # noqa: F401\n    import pytest  # noqa: F401\n", ""),
    # The parent runs with the scrubbed environment, never the verifier's own.
    (RUNNER, UNIT, "                              env=parent_env(), start_new_session=True)",
     "                              start_new_session=True)"),
    (RUNNER, UNIT, "    env.update({key: os.environ[key] for key in RUNTIME_ENV if key in os.environ})",
     "    env.update(os.environ)"),
    (RUNNER, UNIT, '    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"\n', "\n"),
    (RUNNER, UNIT, "    if command and not os.path.isabs(command[0]):", "    if False:"),
    # A whole reply line inside the call's limit, and no stall read over a definitive failure.
    (HARNESS, STALLS, '        while b"\\n" not in self.pending:', "        while not self.pending:"),
    (HARNESS, STALLS, "            if len(self.pending) > LINE_LIMIT:", "            if False:"),
    (HARNESS, STALLS, '    return isinstance(reply, ClientFailure) and reply.get("error") in STALLS',
     '    return isinstance(reply, dict) and reply.get("error") in STALLS'),
    (HARNESS, STALLS, '    if not result["passed"] and not result.get("definitive") and (',
     '    if not result["passed"] and ('),
    (HARNESS, STALLS, "    definitive = failure is not None\n    if not definitive and (first_out",
     "    definitive = False\n    if not definitive and (first_out"),
    (HARNESS, STALLS, "              if not stall(reply)] for index in range(len(cases))]",
     "              ] for index in range(len(cases))]"),
    (HARNESS, STALLS, "    if mismatched and (failure is None or stalled):",
     "    if failure is None and mismatched:"),
    (HARNESS, STALLS, "    definitive = (failure is not None and not proxy.timed_out) or any(",
     "    definitive = False or any("),
    # A budget that runs out is no answer; a fresh stall never ends the search for a wrong one.
    (HARNESS, STALLS, "    definitive = (failure is not None and not proxy.timed_out) or any(",
     "    definitive = (failure is not None) or any("),
    (HARNESS, STALLS, '            failure = failure or "timeout"\n        if _text(reply)',
     '            failure = failure or "timeout"\n            break\n        if _text(reply)'),
    (HARNESS, STALLS, "    stalled = timed_out\n", "    stalled = False\n"),
    (HARNESS, STALLS, "            definitive = definitive or not stall(reply)", "            pass"),
    (REPLAY, UNIT, '            "definitive": failure is not None,', '            "definitive": False,'),
    # An attribute the candidate's module lacks is an absent handle, raised in the parent's words.
    (REPLAY, UNIT, '                 or reply.get("raised") == ABSENT))', "                 ))"),
    (REPLAY, UNIT, "    if reply.get(\"raised\") == ABSENT:\n", "    if False:\n"),
    (REPLAY, UNIT,
     "    fresh_mismatch = [] if failure else fresh_mismatches(request, session, order, timeout)",
     "    fresh_mismatch = fresh_mismatches(request, session, order, timeout)"),
]


def run(tests: list[str]) -> int:
    return subprocess.run([sys.executable, "-B", "-m", "pytest", "-q", "-x", "-p",
                           "no:cacheprovider", *tests], capture_output=True,
                          check=False).returncode


def main() -> int:
    if run(PROVE + UNIT + PIPELINE + STALLS) != 0:
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
