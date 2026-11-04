#!/usr/bin/env bash
# Box-only runner (not committed): mirrors a workflow's reader steps. Usage: box-iop3.sh <name>
set -uo pipefail
W=$PWD
OBS=$W/packages/agent-evidence-observer
sed -i 's/^version = "0.2.0"/version = "0.1.4"/' "$OBS/pyproject.toml"
T=$(mktemp -d)
fail=0
name=$1
case $name in
 a2a) dir=adk-a2a-failed-task-2026-10-03; lock=requirements-reader.lock; py=3.12;;
 smol) dir=smolagents-native-2026-10-03; lock=requirements-reader.lock; py=3.13;;
 hay) dir=haystack-native-2026-10-03; lock=requirements-reader.lock; py=3.13;;
 nested) dir=adk-nested-compaction-2026-10-04; lock=requirements-reader.lock; py=3.13;;
 user) dir=adk-user-responses-2026-10-04; lock=requirements-reader.lock; py=3.13;;
 ag2) dir=ag2-push-authority-2026-10-04; lock=requirements-reader.lock; py=3.12;;
 crew) dir=crewai-job-fences-2026-10-04; lock=requirements-runtime-reader.lock; py=3.13;;
 *) echo "unknown $name"; exit 2;;
esac
P=$OBS/interop/$dir V=$T/$name
echo "=== $name"
uv venv "$V" --python "$py" -q || { echo "STEP $name venv FAIL"; exit 1; }
uv pip install -q --python "$V/bin/python" --require-hashes -r "$P/$lock" || { echo "STEP $name lock FAIL"; exit 1; }
uv pip install -q --python "$V/bin/python" --no-deps "$OBS" "$P" || { echo "STEP $name install FAIL"; exit 1; }
uv pip check --python "$V/bin/python" || { echo "STEP $name check FAIL"; fail=1; }
"$V/bin/python" -I -B "$P/verify_retained.py" > "$T/$name.vr" 2>&1; rc=$?; echo "STEP $name verify_retained rc=$rc"; [ "$rc" -ne 0 ] && fail=1; tail -c 300 "$T/$name.vr"
step() { rc=$?; echo "STEP $name $1 rc=$rc"; [ "$rc" -ne 0 ] && fail=1; tail -3 "$T/$name.log"; }
case $name in
 a2a) for v in baseline proposed-fix; do ADK_FAILURE_VARIANT=$v "$V/bin/python" -I -B -m pytest -c /dev/null "$P/test_native.py" --import-mode=importlib -q -p no:cacheprovider > "$T/$name.log" 2>&1; step "pytest-$v"; done;;
 smol|hay) "$V/bin/python" -I -B -m pytest -c /dev/null "$P/test_native.py" -q -p no:cacheprovider > "$T/$name.log" 2>&1; step pytest;;
 nested|user|ag2|crew)
  case $name in nested) E=ADK_NESTED_PACKET;; user) E=ADK_RESPONSES_PACKET;; ag2) E=AG2_PUSH_PACKET;; crew) E=CREWAI_JOB_PACKET;; esac
  "$V/bin/python" -I -B "$P/verify_retained.py" --materialize "$T/run" > "$T/$name.log" 2>&1 \
   && env "$E=$T/run/packet" "$V/bin/python" -I -B "$P/test_controls.py" -v >> "$T/$name.log" 2>&1; step controls;;
esac
if [ "$name" = nested ] || [ "$name" = user ] || [ "$name" = crew ]; then
  # consumer step: needs the pinned probity-verify source (workflow checks it out)
  VS=$T/selected-verify
  git clone -q https://github.com/probityai/probity-verify.git "$VS" && git -C "$VS" checkout -q e835ce2bd6a960e7a1cc2fa6522f16d55dce728a
  if [ -d "$VS/src" ]; then
    uv build -q --wheel --out-dir "$T/vw" "$VS" > "$T/$name.log" 2>&1 \
     && uv pip install -q --python "$V/bin/python" --no-deps "$T"/vw/probity_verify-0.1.0-py3-none-any.whl >> "$T/$name.log" 2>&1 \
     && uv pip check --python "$V/bin/python" >> "$T/$name.log" 2>&1 \
     && python3 -I -B "$P/verify_consumer.py" --reader "$V/bin/python" --source "$VS" --wheel "$T/vw/probity_verify-0.1.0-py3-none-any.whl" --packet "$T/run/packet" --policy "$T/run/host-policy.json" --policy-sha256 "$(sha256sum "$T/run/host-policy.json" | cut -d' ' -f1)" --output "$T/vc" >> "$T/$name.log" 2>&1
    step consumer
  else
    echo "STEP $name consumer FAIL (verify source not cloned)"; fail=1; echo ""
  fi
fi
echo "STEPS $name fail=$fail"
exit $fail
