#!/usr/bin/env bash
# Build Observer and this profile as wheels, install them into a separate reader
# environment, and replay the retained run through the installed reader. Every
# report it writes must equal the retained copy byte for byte.
set -euo pipefail

profile_dir="$(cd "$(dirname "$0")" && pwd)"
repository_dir="$(cd "$profile_dir/../.." && pwd)"
run_dir="${1:?new absolute output directory required}"
alakris_source="${2:-}"
authority_python="${AUTHORITY_PROFILE_PYTHON:-python}"
retained="$profile_dir/retained"
[[ "$run_dir" == /* ]] || { echo "output directory must be absolute" >&2; exit 2; }
# A fixed build time makes wheel hashes comparable between independent rebuilds of the same revision.
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-315532800}"

mkdir -p "$run_dir/wheels" "$run_dir/empty"
"$authority_python" -m build --no-isolation --wheel --outdir "$run_dir/wheels" "$repository_dir"
"$authority_python" -m build --no-isolation --wheel --outdir "$run_dir/wheels" "$profile_dir"
sha256sum "$run_dir"/wheels/*.whl > "$run_dir/wheel-sha256.txt"

"$authority_python" -m venv --without-pip "$run_dir/reader-env"
"$authority_python" -m pip --python "$run_dir/reader-env/bin/python" install -r "$profile_dir/requirements.txt" "$run_dir"/wheels/*.whl > "$run_dir/reader-install.txt"
"$run_dir/reader-env/bin/python" -m pip check > "$run_dir/reader-pip-check.txt"

"$authority_python" -m venv --without-pip "$run_dir/audit-env"
"$authority_python" -m pip --python "$run_dir/audit-env/bin/python" install -r "$profile_dir/requirements-audit.txt" > "$run_dir/audit-install.txt"
"$authority_python" "$profile_dir/audit_environment.py" "$run_dir/reader-env/bin/python" \
  "$run_dir/audit-env/bin/python" "$run_dir/reader-dependency-audit.json"

cd "$run_dir/empty"
env -u PYTHONPATH ALAKRIS_SOURCE="$alakris_source" "$run_dir/reader-env/bin/python" -m pytest -p no:cacheprovider \
  "$profile_dir/test_authority_profile.py" "$profile_dir/test_implementation_records.py" "$profile_dir/test_audit_environment.py" \
  --rootdir="$profile_dir" --import-mode=importlib --junitxml="$run_dir/tests.xml"
env -u PYTHONPATH "$run_dir/reader-env/bin/python" -I -m reader "$retained/native" --pins "$retained/native/consumer-pins.json" --output "$run_dir/reader-report.json"
cmp "$run_dir/reader-report.json" "$retained/reader-report.json"
discriminator_report="$retained/source-discriminator-report.json"
if [[ -n "$alakris_source" ]]; then
  env -u PYTHONPATH "$run_dir/reader-env/bin/python" -I -m source_discriminator "$alakris_source" "$run_dir/source-discriminator-report.json"
  cmp "$run_dir/source-discriminator-report.json" "$retained/source-discriminator-report.json"
  discriminator_report="$run_dir/source-discriminator-report.json"
fi
env -u PYTHONPATH "$run_dir/reader-env/bin/python" -I -m implementation_records "$profile_dir/implementation-records" \
  "$run_dir/implementation-records-report.json" --reference-report "$run_dir/reader-report.json" --discriminator-report "$discriminator_report"
cmp "$run_dir/implementation-records-report.json" "$retained/implementation-records-report.json"
"$run_dir/reader-env/bin/python" -I -c 'import authority_checks,probity_observer,sys;print(sys.version);print(authority_checks.__file__);print(probity_observer.__file__)' > "$run_dir/installed-reader-location.txt"
