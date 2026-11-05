#!/usr/bin/env bash
# Final proof (untracked, never committed).
set -u
export DIST_CLEAN_PRIVATE_NAMES="$(printf %s "$DIST_CLEAN_NAMES_B64" | base64 -d)"
T="${TMPDIR:-/tmp}"
git log -1 --format='HEAD %H'
uv venv -q --clear -p 3.13 "$T/rel" || exit 10
. "$T/rel/bin/activate"
uv pip install -q --require-hashes -r requirements-release.lock || exit 11
export PYTHONHASHSEED=0 SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)"
rm -rf dist dependencies
mapfile -t dirs < <(python3 scripts/workspace.py requires agent-evidence-observer)
target="${dirs[-1]}"
for dir in "${dirs[@]}"; do
  out=dependencies; [ "$dir" = "$target" ] && out=dist
  python -m build --no-isolation --outdir "$out" "$dir" > "$T/build.log" 2>&1 || { echo "BUILD FAIL $dir"; tail -20 "$T/build.log"; }
done
ls dist
python -m twine check --strict dist/*; echo "TWINE rc=$?"
python scripts/check-dist-clean.py --self-test; echo "SELFTEST rc=$?"
python scripts/check-dist-clean.py --allowlist scripts/dist-allowlist.toml --freeze scripts/release-freeze.toml --distribution agent-evidence-observer dist/*; echo "FREEZE rc=$?"
deactivate
P=packages/agent-evidence-observer
I=$P/interop
run_dir() { # name lock test-args...
  d=$1; lock=$2; shift 2
  v="$T/iop-$d"; uv venv -q --clear -p 3.13 "$v" >/dev/null || { echo "IOP $d venv FAIL"; return; }
  if [ -n "$lock" ]; then VIRTUAL_ENV="$v" uv pip install -q --require-hashes -r "$lock" > "$T/inst-$d.log" 2>&1 || { echo "IOP $d LOCK FAIL"; tail -5 "$T/inst-$d.log"; }; fi
  VIRTUAL_ENV="$v" uv pip install -q --no-deps "$P" > /dev/null 2>&1 || echo "IOP $d OBSERVER INSTALL FAIL"
  VIRTUAL_ENV="$v" uv pip install -q pytest hypothesis sortedcontainers ruff > /dev/null 2>&1
  (cd "$I/$d" && "$v/bin/python" verify_retained.py; echo "VERIFY $d rc=$?")
  (cd "$I/$d" && "$v/bin/python" -m pytest -q -p no:cacheprovider "$@" > "$T/iop-$d.log" 2>&1; echo "IOPTEST $d rc=$?"; tail -3 "$T/iop-$d.log"; grep -E '^(FAILED|ERROR) ' "$T/iop-$d.log" | head -20)
}
run_dir langgraph-crash-window-2026-10-03 "$I/joint-recovery-2026-10-02/requirements-reader.lock"
run_dir joint-recovery-2026-10-02 "$I/joint-recovery-2026-10-02/requirements-reader.lock"
run_dir target-recovery-2026-10-02 "$I/target-recovery-2026-10-02/requirements.lock"
run_dir langgraph-recovery-authority-2026-10-02 "$I/langgraph-ticket-2026-10-02/requirements-restart.lock" tests
run_dir pydantic-ai-native-2026-10-02 "$I/pydantic-ai-native-2026-10-02/requirements.lock" tests
for d in pydantic-recovery-2026-10-03 authority-unreachable-2026-10-03 aps-durable-refund-2026-10-05 eight-component-host-2026-10-02; do
  lock=""; for c in requirements-reader.lock requirements.lock requirements.txt; do [ -f "$I/$d/$c" ] && { lock="$I/$d/$c"; break; }; done
  run_dir "$d" "$lock"
done
v="$T/iop-fc"; uv venv -q --clear -p 3.13 "$v" >/dev/null; VIRTUAL_ENV="$v" uv pip install -q --require-hashes --only-binary :all: -r "$I/framework-consumer-2026-10-02/FRAMEWORK-CONSUMER-REQUIREMENTS-2026-10-02.lock" >/dev/null 2>&1 || echo "FC LOCK FAIL"
VIRTUAL_ENV="$v" uv pip install -q --no-deps "$P" pytest >/dev/null 2>&1
(cd "$P" && "$v/bin/python" -I -B "interop/framework-consumer-2026-10-02/verify_retained.py"; echo "VERIFY framework-consumer rc=$?")
uv venv -q --clear -p 3.13 "$T/obs" || exit 12
. "$T/obs/bin/activate"
(cd "$P" && uv pip install -q -e ".[test,witness,done]") || exit 14
(cd "$P" && python -m pytest -q -p no:cacheprovider tests > "$T/obs-pytest.log" 2>&1; echo "PYTEST rc=$?")
grep -E '^(FAILED|ERROR) |passed|failed' "$T/obs-pytest.log" | tail -80
grep -n -A25 'test_each_interop_retained_driver_passes' "$T/obs-pytest.log" | grep -E 'AssertionError|verify_retained.py:|Error' | head -20
echo "EXIT=0"
