#!/usr/bin/env bash
# Box run for the oracle round 1 fixes: new tests on the fixed code, then on the code with the fixes reverted.
set -u
BASE=574638f
NEW="packages/probity-verify/tests/test_grader_path_scratch.py packages/probity-verify/tests/test_done_argv_env_assignment.py packages/probity-verify/tests/test_tree_path_control_characters.py"
uv sync -q --package probity-verify --extra test
echo "##### probity-verify full suite, fixed code"
.venv/bin/python -m pytest packages/probity-verify/tests -q -p no:cacheprovider > /tmp/pv-full.log 2>&1; tail -4 /tmp/pv-full.log
(cd packages/observer && uv sync -q --extra test --extra done > /tmp/obs-sync.log 2>&1; echo "obs sync rc=$?")
echo "##### observer new + record_oe + staging tests, fixed code"
(cd packages/observer && .venv/bin/python -m pytest tests/test_treedigest_names.py tests/done -q -p no:cacheprovider > /tmp/obs-fixed.log 2>&1; tail -6 /tmp/obs-fixed.log)
echo "##### fixes reverted: new tests must fail"
git diff $BASE HEAD -- 'packages/*/src/*' > /tmp/fix.diff
git apply -R /tmp/fix.diff && echo reverted
.venv/bin/python -m pytest $NEW -q -p no:cacheprovider > /tmp/pv-red.log 2>&1; grep -E "passed|failed" /tmp/pv-red.log
(cd packages/observer && .venv/bin/python -m pytest tests/test_treedigest_names.py -q -p no:cacheprovider > /tmp/obs-red.log 2>&1; grep -E "passed|failed" /tmp/obs-red.log)
git apply /tmp/fix.diff && echo restored
