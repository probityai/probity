#!/usr/bin/env bash
# One-off base comparison (untracked, never committed): done/launch failures at df162fb8.
set -u
git checkout -q -f --detach df162fb8 || exit 9
git log -1 --format=%h df162fb8
uv venv -q --clear -p 3.13 "$TMPDIR/obs-base" || exit 12
. "$TMPDIR/obs-base/bin/activate"
cd packages/agent-evidence-observer || exit 13
uv pip install -q -e ".[test,witness,done]" || exit 14
python -m pytest -q -p no:cacheprovider tests/done tests/launch > "$TMPDIR/base.log" 2>&1; echo "BASEPYTEST rc=$?"
grep -E '^(FAILED|ERROR) |passed|failed' "$TMPDIR/base.log" | tail -60
grep -nE '^E  ' "$TMPDIR/base.log" | sort -t: -k3 | uniq -f1 -c | head -15
