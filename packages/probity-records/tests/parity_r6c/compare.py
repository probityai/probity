"""Cases where the Python and TypeScript readers disagree, and the refusal codes no case reaches in either language.

Usage: compare.py <cases.json> <ts.json>. The codes are every registered code verified_identities.py and possession.py
spell (the reader the differential covers); each must be some case's refusal in Python and in TypeScript, or the
parity of that code is unproven and the run fails.
"""
import json
import re
import sys
from collections import Counter
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src" / "probity_records"


def reader_codes() -> set[str]:
    registered = {c["code"] for c in json.loads((SRC / "refusal_codes.json").read_text())["codes"]}
    text = "".join((SRC / name).read_text() for name in ("verified_identities.py", "possession.py", "stamp.py"))
    return {code for code in re.findall(r'"([a-z][a-z0-9_]+)"', text) if code in registered} - NOT_A_REQUEST_CODE


#: Codes stamp.py spells that no request reaches through verify_request, each with its reason.
NOT_A_REQUEST_CODE = {
    "stamp_dropped",  # verify_stamp on a request with no stamp: verify_request reads the tokens of such a request
    # the window certificate of a stamp signed by a window key (verify_stamp_in_window): not part of verify_request,
    # and the TypeScript twin has no window reader
    "stamp_window_missing", "stamp_window_malformed", "stamp_window_refused", "stamp_window_outside",
}


def refused(value: object) -> str | None:
    return value.get("refused") if isinstance(value, dict) else None


def as_the_grammar_says(c: dict[str, object], verdict: object) -> bool:
    """Whether ``verdict`` is what the grammar says of case ``c`` (grammar_cases.py): accepted, refused, refused by one
    code, not refused by one code, or one exact value. A case that says nothing is judged for parity only."""
    expect, code = c.get("expect"), c.get("code")
    if isinstance(verdict, str):  # RAISED
        return False
    if "value" in c and verdict != c["value"]:
        return False
    if expect == "accept":
        return refused(verdict) is None
    if expect == "refuse":
        return refused(verdict) is not None and (code is None or refused(verdict) == code)
    if expect == "not-code":
        return refused(verdict) != code
    return True


with open(sys.argv[1]) as f:
    cases = json.load(f)
with open(sys.argv[2]) as f:
    ts = json.load(f)
diff, raised_py, raised_ts = [], [], []
for c in cases:
    p, t = c["python"], ts.get(c["case"])
    if isinstance(p, str) and p.startswith("RAISED"):
        raised_py.append((c["case"], p))
    if isinstance(t, str) and t.startswith("RAISED"):
        raised_ts.append((c["case"], t))
    if p != t:
        diff.append((c["case"], p, t))
print(f"PARITY total={len(cases)} differ={len(diff)} py_raised={len(raised_py)} ts_raised={len(raised_ts)}")
kinds = Counter("/".join(case.split("/")[1:2] + case.split("/")[-1:]) for case, _, _ in diff)
for k, n in kinds.most_common():
    print(f"  DIFF_KIND {k} {n}")
seen = set()
for case, p, t in diff:
    key = case.split("/")[-1]
    if key in seen:
        continue
    seen.add(key)
    print(f"  DIFF {case} py={json.dumps(p)[:120]} ts={json.dumps(t)[:120]}")
for case, p in raised_py[:20]:
    print(f"  PY_RAISED {case} {p}")
for case, t in raised_ts[:20]:
    print(f"  TS_RAISED {case} {t}")

codes = reader_codes()
py_codes = {refused(c["python"]) for c in cases} & codes
ts_codes = {refused(v) for v in ts.values()} & codes
print(f"PARITY_CODES registered={len(codes)} reached_py={len(py_codes)} reached_ts={len(ts_codes)}")
for code in sorted(codes):
    n = sum(refused(c["python"]) == code for c in cases)
    print(f"  CODE {code} py_cases={n} {'py' if code in py_codes else 'NOT-py'} {'ts' if code in ts_codes else 'NOT-ts'}")
unreached = sorted(codes - (py_codes & ts_codes))
print(f"PARITY_UNREACHED {len(unreached)} {' '.join(unreached)}".rstrip())

# The grammar: every generated case is judged as its grammar file says, by both readers, and every production has a
# case the readers accept and a case they refuse.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from grammar_cases import JUDGED_PRODUCTIONS

misses = []
tally: dict[str, Counter[str]] = {name: Counter() for name in JUDGED_PRODUCTIONS}
for c in cases:
    production = c.get("production")
    if production is None:
        continue
    for reader, verdict in (("py", c["python"]), ("ts", ts.get(c["case"]))):
        if not as_the_grammar_says(c, verdict):
            misses.append((c["case"], reader, c.get("expect"), c.get("code"), verdict))
        elif production in tally and c.get("expect") in ("accept", "refuse", "not-code"):
            tally[production][f"{reader}-{'refuse' if c['expect'] == 'refuse' else 'accept'}"] += 1
generated = sum(1 for c in cases if c.get("production") is not None)
print(f"GRAMMAR cases={generated} misses={len(misses)}")
for case, reader, expect, code, verdict in misses[:40]:
    print(f"  GRAMMAR_MISS {case} {reader} expect={expect} code={code} got={json.dumps(verdict)[:100]}")
unproven = []
for name, counts in tally.items():
    need = ("py-accept", "ts-accept", "py-refuse", "ts-refuse")
    print(f"  PRODUCTION {name} " + " ".join(f"{k}={counts[k]}" for k in need))
    if any(counts[k] == 0 for k in need):
        unproven.append(name)
print(f"GRAMMAR_UNPROVEN {len(unproven)} {' '.join(unproven)}".rstrip())
sys.exit(1 if diff or raised_py or raised_ts or unreached or misses or unproven else 0)
