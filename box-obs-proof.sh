#!/usr/bin/env bash
# One-off proof run on a box (untracked, never committed).
set -u
export DIST_CLEAN_PRIVATE_NAMES="$(printf %s "$DIST_CLEAN_NAMES_B64" | base64 -d)"
uv venv -q --clear -p 3.13 /tmp/obs-proof || exit 10
. /tmp/obs-proof/bin/activate
uv pip install -q --require-hashes -r requirements-release.lock || exit 11
export PYTHONHASHSEED=0 SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)"
rm -rf dist dependencies
fail=0
mapfile -t dirs < <(python3 scripts/workspace.py requires agent-evidence-observer)
target="${dirs[-1]}"
for dir in "${dirs[@]}"; do
  out=dependencies; [ "$dir" = "$target" ] && out=dist
  python -m build --no-isolation --outdir "$out" "$dir" > /tmp/build.log 2>&1 || { echo "BUILD FAIL $dir"; tail -20 /tmp/build.log; fail=1; }
done
ls dist
python -m twine check --strict dist/*; echo "TWINE rc=$?"
python scripts/check-dist-clean.py --self-test; echo "SELFTEST rc=$?"
python scripts/check-dist-clean.py --allowlist scripts/dist-allowlist.toml --freeze scripts/release-freeze.toml --distribution agent-evidence-observer dist/*; echo "FREEZE rc=$?"
uv venv -q --clear -p 3.13 /tmp/obs-test && . /tmp/obs-test/bin/activate || exit 12
cd packages/agent-evidence-observer || exit 13
uv pip install -q -e ".[test,witness,done]" || exit 14
python -m pytest -q -p no:cacheprovider tests > /tmp/obs-pytest.log 2>&1; echo "PYTEST rc=$?"
tail -40 /tmp/obs-pytest.log
for d in langgraph-crash-window-2026-10-03; do
  (cd interop/$d && python verify_retained.py; echo "VERIFY $d rc=$?")
done
uv pip install -q hypothesis sortedcontainers pytest || true
for d in langgraph-crash-window-2026-10-03; do
  (cd interop/$d && python -m pytest -q -p no:cacheprovider > /tmp/iop-$d.log 2>&1; echo "IOP $d rc=$?"; tail -3 /tmp/iop-$d.log)
done
echo "EXIT=$fail"
