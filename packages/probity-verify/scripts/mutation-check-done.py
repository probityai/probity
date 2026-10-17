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
ACCEPTANCE = (ADAPTERS + "acceptance_observed.py", "tests/test_acceptance_observed.py")
CLAIMS = (ADAPTERS + "tool_claim_match.py", "tests/test_tool_claim_match.py")
CORE = ("src/probity_verify/core.py", "tests/test_witness_scope.py")
RECEIPT = (ADAPTERS + "done_receipt.py", "tests/test_done_receipt.py")

MUTATIONS = [
    ("protected: rename or link target ignored", *PROTECTED,
     'hit(event["path"]) or ("target" in event and hit(event["target"]))',
     'hit(event["path"])'),
    ("protected: excluded segments still protected", RECORDS, PROTECTED[1],
     '(item in below) if "/" not in item', 'False if "/" not in item'),
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
     'record["witness_scope"] == pin["witness_scope"] == EXTERNAL',
     'record["witness_scope"] == EXTERNAL'),
    ("records: witness scope outside the vocabulary accepted", RECORDS, "tests/test_vocabulary.py",
     '    if record["witness_scope"] not in SCOPES:', "    if False:"),
    ("acceptance: grade tree binding skipped", *ACCEPTANCE,
     '"tree": grade["tree_sha256"] == tree["tree_sha256"]}', '"tree": True}'),
    ("acceptance: grade contract binding skipped", *ACCEPTANCE,
     'grade["contract_sha256"] == contract_pin["consumer_pinned_sha256"]', "True"),
    ("acceptance: grade vantage skipped", *ACCEPTANCE,
     "grade_ok = records.independent(grade, grade_pin, observed_party)", "grade_ok = True"),
    ("acceptance: nonzero exit passes", *ACCEPTANCE,
     'if item["exit"] != 0]', 'if item["exit"] > 1]'),
    ("acceptance: zero adequacy supports", *ACCEPTANCE,
     '"met" if adequacy["killed"] > 0', '"met" if True'),
    ("acceptance: missing result ignored", *ACCEPTANCE,
     '            return "acceptance_result_missing", outcomes',
     "            continue"),
    ("records: tree digest not recomputed", RECORDS, ACCEPTANCE[1],
     'raise CaseError("tree.tree_sha256: does not match the listed entries")', "pass"),
    ("claims: stale runs accepted", *CLAIMS,
     'fresh = [event for event in candidates if event["step"] > last_edit]',
     "fresh = candidates"),
    ("claims: every claimed tree excused", *CLAIMS,
     '                  else event.get("origin") not in own)]', "                  else True)]"),
    ("claims: argv ignored", *CLAIMS,
     'candidates = [event for event in execs if event["argv"] == claim["argv"]]',
     "candidates = execs"),
    ("claims: claimed exit ignored", *CLAIMS,
     'if event.get("exit") == claim["exit"]]', "]"),
    ("claims: unseen exit treated as a mismatch", *CLAIMS,
     '    if any("exit" not in event for event in clear):', "    if False:"),
    ("claims: incomplete coverage settles", *CLAIMS,
     '    complete = record["coverage"] == "complete"', "    complete = True"),
    ("claims: exec visibility not required", *CLAIMS,
     "REQUIRED_TYPES = records.MUTATION_TYPES | {records.EXEC_TYPE}",
     'REQUIRED_TYPES = frozenset({"write"})'),
    ("claims: self-reported observation accepted", *CLAIMS,
     "independent = records.independent(record, observation_pin, observed_party)",
     "independent = True"),
    ("protected: symlink or special file under an entry ignored", *PROTECTED,
     "return any(name in ancestors or records.protects(entry, name) for name in others)",
     "return any(name in ancestors for name in others)"),
    ("protected: symlinked ancestor ignored", *PROTECTED,
     "name in ancestors or records.protects", "records.protects"),
    ("protected: equivalence accepted without comparing trees", *PROTECTED,
     "return sealed is not None and final is not None and records.same_ast(sealed, final)",
     "return sealed is not None and final is not None"),
    ("protected: equivalence ignored", *PROTECTED,
     "return sealed is not None and final is not None and records.same_ast(sealed, final)",
     "return False"),
    ("protected: sealed source taken from the final tree", *PROTECTED,
     'sealed = records.source(case, root, entry["sha256"])',
     "sealed = records.source(case, root, now)"),
    ("records: different syntax trees equivalent", RECORDS, PROTECTED[1],
     "return trees[0] == trees[1]", "return True"),
    ("protected: grader-path effect ignored", *PROTECTED,
     "        if effects:\n", "        if False:\n"),
    ("records: grader path taken from the label alone", RECORDS, PROTECTED[1],
     '            or any(grader_path(name) for name in entry["paths"])]', "]"),
    ("records: .pth not a grader path", RECORDS, PROTECTED[1],
     'or parts[-1].endswith(".pth")', ""),
    ("records: grader directories not grader paths", RECORDS, PROTECTED[1],
     "or bool(set(parts[:-1]) & GRADER_SEGMENTS))", ")"),
    ("records: agent gaps ignored", RECORDS, PROTECTED[1],
     'gaps = [gap for gap in record.get("gaps", []) if gap["gap_cause"] == "agent"]',
     "gaps = []"),
    ("records: any gap counted as the agent's", RECORDS, PROTECTED[1],
     'if gap["gap_cause"] == "agent"]', "]"),
    ("records: tracer loss reported as a bounded gap", RECORDS, PROTECTED[1],
     'if any(gap["end"] == record["scope"]["end"] for gap in gaps):', "if False:"),
    ("protected: agent gap ignored", *PROTECTED,
     '        if sabotage:\n            return decide("contradicted", sabotage, observation_pair)\n',
     ""),
    ("records: path exclusion matched as a name", RECORDS, PROTECTED[1],
     'if (item in below) if "/" not in item else under(name, item):',
     'if item.rsplit("/", 1)[-1] in below:'),
    ("records: path exclusions ignored", RECORDS, PROTECTED[1],
     "else under(name, item):", "else False:"),
    ("records: path exclusion outside the entry accepted", RECORDS, PROTECTED[1],
     'raise CaseError(f"{label}.exclude: a path must lie under the entry")', "pass"),
    ("records: executable bit outside the tree digest", RECORDS, ACCEPTANCE[1],
     '("x:" if name in executable else "")', '""'),
    ("records: symlink target outside the tree digest", RECORDS, ACCEPTANCE[1],
     'lines[name] = "l:" + hashlib.sha256(target.encode("utf-8", "surrogateescape")).hexdigest()',
     'lines[name] = "l:"'),
    ("records: special kind outside the tree digest", RECORDS, ACCEPTANCE[1],
     'lines[name] = "s:" + kind', 'lines[name] = "s:"'),
    ("records: steps may repeat across the two lists", RECORDS, CLAIMS[1],
     'if entry["step"] in steps or (events', "if (events"),
    ("records: outside mutation may name a workspace path", RECORDS, CLAIMS[1],
     'raise CaseError(f"{label}.paths: an outside mutation names a workspace path")', "pass"),
    ("records: class counts need not sum", RECORDS, ACCEPTANCE[1],
     'if totals != [mutants, adequacy["killed"]]:', "if False:"),
    ("claims: outside mutations never edits", *CLAIMS,
     '    steps += [entry["step"] for entry in record["external_mutations"]\n'
     '              if entry.get("origin") not in own]\n', ""),
    ("claims: a run's own outside writes are edits", *CLAIMS,
     '              if entry.get("origin") not in own]', "              ]"),
    ("claims: shadowed runs match", *CLAIMS,
     'clear = [event for event in fresh if not shadows[event["id"]][0]]', "clear = fresh"),
    ("claims: workspace executable not a shadow", *CLAIMS,
     '    place("exe", event["exe"])', "    pass"),
    ("claims: agent-written shadow only possible", *CLAIMS,
     "definite = definite or agent", "definite = definite or False"),
    ("claims: loader paths ignored", *CLAIMS,
     '                place(f"env.{key}", name)', "                pass"),
    ("claims: empty search-list entry not the working directory", *CLAIMS,
     '        parts = value.split(":")', '        parts = [part for part in value.split(":") if part]'),
    ("claims: loader option variables ignored", *CLAIMS,
     'reasons.extend(f"env.{key}" for key in OPTION_KEYS if event["env"].get(key))', "pass"),
    ("claims: import path directory ignored", *CLAIMS,
     '        place("python_path_zero", directory)', "        pass"),
    ("claims: module file ignored", *CLAIMS,
     '                place("python_path_zero", name)', "                pass"),
    ("claims: -P ignored", *CLAIMS,
     'if "P" in flags or "I" in flags:', 'if "I" in flags:'),
    ("claims: safe-path variable trusted under -E", *CLAIMS,
     'return "E" not in flags and bool(', "return bool("),
    ("claims: writes after the run shadow it", *CLAIMS,
     'records.written(record, event["step"])', "records.written(record)"),
    ("claims: sealed run writes ignored", *CLAIMS,
     "writes = _own_writes(claim, contract)", "writes = None"),
    ("claims: cache directories not the run's own", *CLAIMS,
     "or bool(set(name.split(\"/\")) & CACHE_SEGMENTS) for name in names)",
     "for name in names)"),
    ("claims: agent gap ignored", *CLAIMS,
     '    if sabotage:\n        return decide("contradicted", sabotage)\n', ""),
    ("acceptance: held-out failure not named", *ACCEPTANCE,
     "all(item.startswith(HELDOUT_PREFIX) for item in failed)", "False"),
    ("acceptance: any held-out failure named held-out", *ACCEPTANCE,
     "all(item.startswith(HELDOUT_PREFIX) for item in failed)",
     "any(item.startswith(HELDOUT_PREFIX) for item in failed)"),
    ("acceptance: no held-out split required", *ACCEPTANCE,
     '"met" if heldout or allow_no_heldout else "unavailable"', '"met"'),
    ("acceptance: split digest without a held-out command", *ACCEPTANCE,
     'return "heldout_split_sha256" in contract and any(',
     'return "heldout_split_sha256" in contract or any('),
    ("acceptance: silent replay accepted", *ACCEPTANCE,
     '"calls_intercepted") == 0]', '"calls_intercepted") == -1]'),
    ("acceptance: unexercised hunk accepted", *ACCEPTANCE,
     'if hunk["mutants"] and not hunk["killed"]]', "if False]"),
    ("acceptance: collection count ignored", *ACCEPTANCE,
     'if "ids_sealed" in item and item.get("collected") != item["ids_sealed"]]', "if False]"),
    ("receipt: missing verifier id accepted", *RECEIPT,
     '        raise CaseError("receipt.predicate.verifier.id: required")', "        pass"),
    ("receipt: verifier id not a URI accepted", *RECEIPT,
     'if not isinstance(verifier["id"], str) or not URI.fullmatch(verifier["id"]):',
     "if False:"),
    ("receipt: legacy predicate type read", *RECEIPT,
     'if value["predicateType"] != records.DONE_RECEIPT_PREDICATE:', "if False:"),
    ("receipt: verifier pin ignored", *RECEIPT,
     'pinned = accepted is None or result["verifier_id"] in accepted', "pinned = True"),
    ("receipt: record digests unbound", *RECEIPT,
     '                     != bound[role][1]["consumer_pinned_sha256"])', "                     and False)"),
    ("receipt: subject not bound to the final tree", *RECEIPT,
     "        if not named:\n", "        if False:\n"),
    ("receipt: reported verdict trusted", *RECEIPT,
     "    if not agrees:\n", "    if False:\n"),
    ("receipt: reason not compared", *RECEIPT,
     'agrees = (reported["decision"], reported["reason"]) == (derived["decision"],\n'
     '                                                             derived["reason"])',
     'agrees = reported["decision"] == derived["decision"]'),
    ("receipt: a later contradiction names the verdict", *RECEIPT,
     '    for entry in found:\n        if entry["decision"] == "contradicted":',
     '    for entry in reversed(found):\n        if entry["decision"] == "contradicted":'),
    ("receipt: verifier id not reported", *RECEIPT,
     'result["verifier_id"] = predicate["verifier"]["id"]', "pass"),
    ("core: witness scope requirement ignored", *CORE,
     '    if require_witness_scope == EXTERNAL:\n        _require_external(result)\n',
     ""),
    ("core: contradicted verdict held by EXTERNAL requirement", *CORE,
     'if result["decision"] != "supported" or scope == EXTERNAL:',
     'if result["decision"] == "not_established" or scope == EXTERNAL:'),
    ("core: unstated scope meets EXTERNAL", *CORE,
     'or scope == EXTERNAL:', 'or scope in (EXTERNAL, None):'),
    ("core: decision line qualifiers dropped", *CORE,
     """return f" ({', '.join(parts)})" if parts else """"", 'return ""'),
    ("core: invalid adapter scope accepted", *CORE,
     'result.get("witness_scope", PEER) not in WITNESS_SCOPES', "False"),
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
