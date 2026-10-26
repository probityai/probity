#!/usr/bin/env bash
# Box run for the parent-directory configuration fix: the verifier, observer and launcher tests on the fixed
# code, then the end-to-end test with the launcher change reverted (it must fail).
set -u
BASE=9798e56
uv sync -q --package probity-verify --extra test
echo "##### probity-verify full suite, fixed code"
.venv/bin/python -m pytest packages/probity-verify/tests -q -p no:cacheprovider > /tmp/a09-pv.log 2>&1
tail -3 /tmp/a09-pv.log
(cd packages/observer && uv sync -q --extra test --extra done > /tmp/a09-sync.log 2>&1; echo "obs sync rc=$?")
echo "##### observer suite, fixed code"
(cd packages/observer && .venv/bin/python -m pytest tests -q -p no:cacheprovider > /tmp/a09-obs.log 2>&1; tail -4 /tmp/a09-obs.log)
echo "##### launcher change reverted: the end-to-end test must fail"
git diff $BASE -- packages/observer/src/probity_observer/launch > /tmp/a09-launch.diff
git apply -R /tmp/a09-launch.diff && echo reverted
(cd packages/observer && .venv/bin/python -m pytest tests/launch/test_docker_launch.py -q -p no:cacheprovider -k "parent_config" > /tmp/a09-red.log 2>&1; grep -E "^(FAILED|ERROR)|passed|failed" /tmp/a09-red.log)
git apply /tmp/a09-launch.diff && echo restored
