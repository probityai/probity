#!/bin/sh
# Run the six-step refund demo against a local Temporal dev server, then verify its records offline.
set -e
cd "$(dirname "$0")/.."
unset VIRTUAL_ENV
export UV_PROJECT_ENVIRONMENT=.venv
uv sync -q --frozen
rm -rf demo-out
uv run --frozen probity-temporal demo run --dir demo-out
uv run --frozen probity-temporal verify demo-out --key demo-out/authority.pub --checkpoint demo-out/checkpoint.json
