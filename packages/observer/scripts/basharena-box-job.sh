#!/usr/bin/env bash
# The job basharena-box-run.sh runs on the remote host (from the checkout its runner made there).
#
#   basharena-box-job.sh <rows.jsonl> <out-dir> openai-api/<service>/<model> <revision> [episode-runner args...]
#
# Needs <SERVICE>_BASE_URL and <SERVICE>_API_KEY in the environment, the variables Inspect reads for the
# model (on the host the URL is the reverse tunnel's local end). Prepares what the runner expects, then
# runs it: BashArena at a pinned revision with its own environment, the observer image, a signing seed
# kept on the host outside the checkout, and the episode runner with the build cache pruned after each
# task (the host is not shared with other Docker work while an episode runs).
set -euo pipefail
rows="$1" out="$2" model="$3" revision="$4"
shift 4
service="$(printf '%s' "$model" | cut -d/ -f2 | tr '[:lower:]-' '[:upper:]_')"
for var in "${service}_BASE_URL" "${service}_API_KEY"; do
    [ -n "${!var:-}" ] || { echo "$var is not set" >&2; exit 64; }
done
BASHARENA_REV="${BASHARENA_REV:-86082fd}"
state="$HOME/basharena-state"
arena="$state/basharena_public"
mkdir -p "$state"
docker compose version > /dev/null || { echo "the Docker Compose plugin is missing on this host" >&2; exit 69; }

if [ ! -d "$arena/.git" ]; then
    git clone -q https://github.com/redwoodresearch/basharena_public "$arena"
fi
git -C "$arena" fetch -q origin
git -C "$arena" checkout -q "$BASHARENA_REV"
(cd "$arena" && uv sync --frozen)

observer_dir="$(pwd)/packages/observer/src/probity_observer/done/basharena"
image="probity-observer-basharena:$(sha256sum "$observer_dir/observer.Dockerfile" "$observer_dir/observer_tools.txt" | sha256sum | cut -c1-12)"
docker image inspect "$image" > /dev/null 2>&1 || docker build -q -f "$observer_dir/observer.Dockerfile" -t "$image" "$observer_dir"

seed="$state/signer.seed"
[ -s "$seed" ] || { umask 077; head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$seed"; }

exec uv run --package probity-observer --extra "done" python -m probity_observer.done.basharena.run \
    --rows "$rows" --out "$out" --basharena "$arena" --observer-image "$image" --model "$model" \
    --key "$seed" --revision "$revision" --prune-build-cache "$@"
