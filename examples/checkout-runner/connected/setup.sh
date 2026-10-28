#!/usr/bin/env bash
# Fetch every pinned component of the connected refund run and build its environment.
#
#   connected/setup.sh <work dir> <checkout-runner commit>
#
# Writes <work dir>/env.sh with the paths run_connected.py needs. Pins come from pins.json beside this file.
# Needs git, Node 22 or later with npm, Python 3.12 for the PIC venv and uv for the runner.
set -euo pipefail
work=$(realpath -m "$1")
runner_commit=$2
here=$(cd "$(dirname "$0")" && pwd)
pins="$here/pins.json"
pin() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d[sys.argv[2]][sys.argv[3]])' "$pins" "$1" "$2"; }
node=${NODE:-node}
python312=${PYTHON312:-python3.12}
"$node" -e 'process.exit(Number(process.versions.node.split(".")[0]) >= 22 ? 0 : 1)' \
  || { echo "setup: $node is $("$node" --version); the Horizon Shield adapter needs Node 22 or later" >&2; exit 2; }
mkdir -p "$work"

fetch() {  # fetch <dir> <url> <commit>
  if [ ! -d "$1/.git" ]; then git init -q "$1"; git -C "$1" remote add origin "$2"; fi
  git -C "$1" fetch -q --depth 1 origin "$3"
  git -C "$1" checkout -q --detach FETCH_HEAD
  test "$(git -C "$1" rev-parse HEAD)" = "$3"
}

fetch "$work/pic-standard" "$(pin pic repo)" "$(pin pic producer_commit)"
fetch "$work/horizon-shield" "$(pin horizon repo)" "$(pin horizon commit)"
fetch "$work/probity" "$(pin runner repo)" "$runner_commit"

pic_example="$work/pic-standard/examples/refund-sandbox"
if [ ! -x "$work/pic-venv/bin/python" ]; then "$python312" -m venv "$work/pic-venv"; fi
"$work/pic-venv/bin/python" -m pip install -q --disable-pip-version-check -r "$pic_example/requirements.txt" -c "$pic_example/constraints.txt"

adapter="$work/horizon-shield/$(pin horizon adapter_path)"
(cd "$adapter" && PATH="$(dirname "$(command -v "$node")"):$PATH" npm ci --ignore-scripts --no-audit --no-fund >/dev/null)
"$node" "$adapter/adapter_aps_receipt.mjs" --pins

(cd "$work/probity/examples/checkout-runner" && uv sync -q --frozen)

cat > "$work/env.sh" <<EOF
export CONNECTED_NODE=$(command -v "$node")
export CONNECTED_PIC_PYTHON=$work/pic-venv/bin/python
export CONNECTED_PIC_CHECKOUT=$work/pic-standard
export CONNECTED_HORIZON_CHECKOUT=$work/horizon-shield
export CONNECTED_RUNNER=$work/probity/examples/checkout-runner
EOF
echo "setup done: $work/env.sh"
