#!/usr/bin/env bash
# Build otelcol-audit (stock contrib verifyprocessor v0.165.0) into $1 (default ./dist); prints the binary path.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
out="${1:-$here/dist}"
command -v go >/dev/null || { echo "go is not installed" >&2; exit 2; }
GOBIN="$out/bin" go install go.opentelemetry.io/collector/cmd/builder@v0.165.0
mkdir -p "$out"
sed "s#output_path: ./dist#output_path: $out#" "$here/builder-config.yaml" > "$out/builder-config.yaml"
"$out/bin/builder" --config "$out/builder-config.yaml" >&2
echo "$out/otelcol-audit"
