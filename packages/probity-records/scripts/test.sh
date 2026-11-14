#!/bin/sh
set -e
cd "$(dirname "$0")/.."
unset VIRTUAL_ENV
export UV_PROJECT_ENVIRONMENT=.venv
uv sync -q --frozen
exec uv run --frozen python -m pytest -q tests "$@"
