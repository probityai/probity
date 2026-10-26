#!/usr/bin/env bash
# The two wrong patches the old suite passed under: new tests must pass now and fail under each.
set -u
F=packages/probity-verify/src/probity_verify/adapters/done_records.py
T=packages/probity-verify/tests/test_protected_paths.py
uv sync -q --package probity-verify --extra test
echo "##### fixed code"
.venv/bin/python -m pytest $T -q -p no:cacheprovider > /tmp/gap-ok.log 2>&1; tail -2 /tmp/gap-ok.log
cp $F /tmp/done_records.orig
python3 - <<'P'
p="packages/probity-verify/src/probity_verify/adapters/done_records.py"
s=open(p).read()
a='    kind = _string(event["type"], f"{label}.type")\n'
assert a in s
open(p,"w").write(s.replace(a,a+'    if kind == "read":\n        raise CaseError(f"{label}: unknown event type")\n',1))
P
echo "##### wrong patch 1: refuse read events"
.venv/bin/python -m pytest $T -q -p no:cacheprovider > /tmp/gap-1.log 2>&1; grep -E "passed|failed" /tmp/gap-1.log
cp /tmp/done_records.orig $F
python3 - <<'P'
p="packages/probity-verify/src/probity_verify/adapters/done_records.py"
s=open(p).read()
assert 'entry.get("exclude", ())' in s
open(p,"w").write(s.replace('entry.get("exclude", ())','()',1))
P
echo "##### wrong patch 2: protect the excluded cache directory"
.venv/bin/python -m pytest $T -q -p no:cacheprovider > /tmp/gap-2.log 2>&1; grep -E "passed|failed" /tmp/gap-2.log
cp /tmp/done_records.orig $F
