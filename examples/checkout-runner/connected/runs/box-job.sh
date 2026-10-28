#!/usr/bin/env bash
# Box job for the connected refund J01 run (research/1070). Run through box_run.sh from the lane worktree:
#
#   box_run.sh refund-j01 --no-deps --no-sync --fetch box-out <local dir> -- bash research/1070-refund-j01-run-2026-10-28/box/runs.sh
#
# Fetches the probityai/probity harness at HEAD, sets up both runner commits, then runs
# r1 (checkout_runner at OLD, the main branch before the fix) and r2 (checkout_runner at HEAD).
set -u
export PATH=$HOME/.local/share/mise/installs/node/22.23.3/bin:$HOME/.local/bin:$PATH
HEAD=129e15c5ab4a406f672a6930008b9b1c77d1efe5
OLD=0792af8cd7d4367cda7bfb883dcade8f82572db8
OUT=$PWD/box-out
WORK=${TMPDIR:-/tmp}/refund-j01-work
mkdir -p "$OUT/runs" "$WORK"
# Node 22: the mise install on the box when present, else the official tarball, checked against SHASUMS256.txt.
NODE_V=v22.23.3
NODE=$(ls -d "$HOME"/.local/share/mise/installs/node/22.23.3/bin/node 2>/dev/null || true)
if [ -z "$NODE" ]; then
  tarball=node-$NODE_V-linux-x64.tar.xz
  curl -fsSL -o "$WORK/$tarball" "https://nodejs.org/dist/$NODE_V/$tarball"
  curl -fsSL -o "$WORK/SHASUMS256.txt" "https://nodejs.org/dist/$NODE_V/SHASUMS256.txt"
  (cd "$WORK" && grep " $tarball\$" SHASUMS256.txt | sha256sum -c -) > "$OUT/node-download.log" 2>&1 || { cat "$OUT/node-download.log"; exit 3; }
  tar -C "$WORK" -xJf "$WORK/$tarball"
  NODE=$WORK/node-$NODE_V-linux-x64/bin/node
fi
export NODE
echo "NODE=$NODE $("$NODE" --version)" > "$OUT/node.txt"
git init -q "$WORK/harness" && git -C "$WORK/harness" fetch -q --depth 1 https://github.com/probityai/probity.git "$HEAD" \
  && git -C "$WORK/harness" checkout -q --detach FETCH_HEAD
SETUP=$WORK/harness/examples/checkout-runner/connected/setup.sh
H=$WORK/harness/examples/checkout-runner/connected
"$SETUP" "$WORK/w-old" "$OLD" > "$OUT/setup-old.log" 2>&1; echo "EXIT=$?" >> "$OUT/setup-old.log"
"$SETUP" "$WORK/w-head" "$HEAD" > "$OUT/setup-head.log" 2>&1; echo "EXIT=$?" >> "$OUT/setup-head.log"
run() {  # run <run id> <runner work dir>
  . "$2/env.sh"
  uv run --frozen --project "$CONNECTED_RUNNER" python "$H/run_connected.py" --out "$OUT/runs/$1" --run-id "$1" \
    --node "$CONNECTED_NODE" --pic-python "$CONNECTED_PIC_PYTHON" --pic-checkout "$CONNECTED_PIC_CHECKOUT" \
    --horizon-checkout "$CONNECTED_HORIZON_CHECKOUT" --runner-checkout "$2/probity" > "$OUT/runs/$1.log" 2>&1
  echo "EXIT=$?" >> "$OUT/runs/$1.log"
}
run j01-connected-20261028-r1 "$WORK/w-old"
run j01-connected-20261028-r2 "$WORK/w-head"
tail -3 "$OUT/runs/"*.log
exit 0
