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
    text = (SRC / "verified_identities.py").read_text() + (SRC / "possession.py").read_text()
    return {code for code in re.findall(r'"([a-z][a-z0-9_]+)"', text) if code in registered}


def refused(value: object) -> str | None:
    return value.get("refused") if isinstance(value, dict) else None


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
sys.exit(1 if diff or raised_py or raised_ts or unreached else 0)
