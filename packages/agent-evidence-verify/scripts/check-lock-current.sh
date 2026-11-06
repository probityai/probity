#!/bin/sh
# Usage: check-lock-current.sh <input.in> <committed.lock> <python-version> <scratch-dir>
# Fails when the committed lock no longer satisfies its input. It recompiles
# onto a copy of the committed lock, so uv keeps every existing pin as a
# preference and only an edit to the input (or a pin the lock cannot meet)
# produces a diff. A new upstream release of a transitive dependency does not.
# To take newer versions on purpose: uv pip compile --upgrade <input> -o <lock>.
set -eu
input=$1
lock=$2
pyver=$3
scratch=$4
mkdir -p "$scratch"
out="$scratch/$(basename "$lock")"
cp "$lock" "$out"
uv pip compile --quiet --no-header --python-version "$pyver" "$input" -o "$out"
diff -u "$lock" "$out"
