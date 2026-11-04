#!/usr/bin/env bash
# Scratch box script (never committed): the installed-framework-readers job steps.
set -u
cd packages/agent-evidence-observer
P=$PWD
I=interop/framework-consumer-2026-10-02
T=$(mktemp -d)
uv venv --seed --python 3.13 "$T/e" >/dev/null 2>&1
echo VENV $?
"$T/e/bin/python" --version
"$T/e/bin/python" -m pip install --require-hashes --only-binary=:all: -r $I/FRAMEWORK-CONSUMER-REQUIREMENTS-2026-10-02.lock >"$T/lock.log" 2>&1
echo LOCK $?
PATH="$T/e/bin:$PATH" bash $I/FRAMEWORK-CONSUMER-BUILD-2026-10-02.sh "$P" "$T/w1"
echo BUILD1 $?
"$T/e/bin/python" -m pip install --no-index --no-deps "$T"/w1/*.whl
echo INST1 $?
"$T/e/bin/python" -m pip check
echo CHECK1 $?
"$T/e/bin/python" -m pip install pytest==8.4.2 ruff==0.15.6 >"$T/pt.log" 2>&1
echo PYTEST_INSTALL $?
"$T/e/bin/python" -I -B $I/verify_retained.py
echo VERIFY $?
"$T/e/bin/python" -m pytest -q $I/test_installed_readers.py interop/consumer-host-2026-10-02/test_framework_gate.py
echo HISTORICAL $?
PATH="$T/e/bin:$PATH" bash $I/FRAMEWORK-DURABLE-CONSUMER-BUILD-2026-10-02.sh "$P" "$T/w2"
echo BUILD2 $?
"$T/e/bin/python" -m pip install --no-index --no-deps --upgrade "$T"/w2/*.whl
echo INST2 $?
"$T/e/bin/python" -m pip check
echo CHECK2 $?
"$T/e/bin/python" -m ruff check --isolated $I/*.py interop/consumer-host-2026-10-02/*.py
echo RUFF $?
"$T/e/bin/python" -m ruff check --isolated --select C901 --config "lint.mccabe.max-complexity=5" $I/*.py interop/consumer-host-2026-10-02/*.py
echo RUFFC901 $?
FRAMEWORK_DURABLE_SELECTED_SOURCE="$P" "$T/e/bin/python" -m pytest -q $I/test_installed_readers.py $I/test_durable_installed_reader.py interop/consumer-host-2026-10-02/test_framework_gate.py interop/consumer-host-2026-10-02/test_durable_framework_gate.py
echo FULL $?
