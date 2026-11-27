"""Rows where the Python and TypeScript readers disagree. Usage: compare.py <cases.json> <ts.json>"""
import json
import sys
from collections import Counter

cases = json.load(open(sys.argv[1]))
ts = json.load(open(sys.argv[2]))
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
