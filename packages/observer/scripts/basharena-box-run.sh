#!/usr/bin/env bash
# Run BashArena episodes on a Hetzner gate box instead of this workstation, the model still on HiPerGator.
#
#   BOX_RUN_HOSTS=root@<box> HPG_API_KEY=... basharena-box-run.sh <name> <rows.jsonl> <model> <local-out> \
#       <hpg-tunnel-port> [episode-runner args...]
#
#   rows.jsonl       inside the checkout (box_run.sh ships it with the tree)
#   local-out        where the episode directories come back to
#   hpg-tunnel-port  the local end of the workstation's tunnel to the HiPerGator model server; this
#                    script reverse-forwards it to the box, so the box reaches the model with no HPG
#                    login of its own
#
# The box is pinned with BOX_RUN_HOSTS (the reverse tunnel must end on the box the job runs on).
# Docker Compose on the box comes from config/box-apt-packages (box-apt-install.sh). Set
# BASHARENA_DRY_RUN=1 to print the two commands and run nothing.
set -euo pipefail
[ "$#" -ge 5 ] || { sed -n 2,14p "$0" >&2; exit 64; }
name="$1" rows="$2" model="$3" local_out="$4" port="$5"
shift 5
box="${BOX_RUN_HOSTS:?pin one box with BOX_RUN_HOSTS=root@<ip>}"
case "$box" in *,*|*" "*) echo "BOX_RUN_HOSTS must name exactly one box" >&2; exit 64 ;; esac
: "${HPG_API_KEY:?HPG_API_KEY is not set}"
box_run="${BOX_RUN_SH:-$HOME/.claude/scripts/box_run.sh}"
remote_port=18000
revision="$(git rev-parse HEAD)"
out="basharena-out/$name"
key=()
[ -z "${BOX_RUN_KEY:-}" ] || key=(-o IdentitiesOnly=yes -i "$BOX_RUN_KEY")
tunnel=(ssh -o BatchMode=yes -o ExitOnForwardFailure=yes "${key[@]}" \
    -N -R "127.0.0.1:$remote_port:127.0.0.1:$port" "$box")
job=("$box_run" "$name" --forward-env HPG_API_KEY --forward-env HPG_BASE_URL --fetch "$out" "$local_out" -- \
    packages/observer/scripts/basharena-box-job.sh "$rows" "$out" "$model" "$revision" "$@")
if [ -n "${BASHARENA_DRY_RUN:-}" ]; then
    printf 'TUNNEL %s\n' "${tunnel[*]}"
    printf 'JOB HPG_BASE_URL=http://127.0.0.1:%s/v1 %s\n' "$remote_port" "${job[*]}"
    exit 0
fi
"${tunnel[@]}" &
tunnel_pid=$!
trap 'kill "$tunnel_pid" 2> /dev/null || true' EXIT
sleep 3
kill -0 "$tunnel_pid" || { echo "the reverse tunnel to $box did not start" >&2; exit 69; }
HPG_BASE_URL="http://127.0.0.1:$remote_port/v1" "${job[@]}"
