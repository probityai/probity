#!/usr/bin/env bash
# Run BashArena episodes on a remote Docker host, with the model server reached from this machine.
#
#   BOX_RUN_SH=<runner> BOX_RUN_HOSTS=root@<host> <SERVICE>_API_KEY=... basharena-box-run.sh <name> \
#       <rows.jsonl> openai-api/<service>/<model> <local-out> <tunnel-port> [episode-runner args...]
#
#   BOX_RUN_SH       a runner that ships this checkout to the host and runs a command in it, called as
#                    <runner> <name> --forward-env VAR... --fetch <remote dir> <local dir> -- <command...>
#   rows.jsonl       inside the checkout (the runner ships it with the tree)
#   model            an Inspect openai-api model; its <SERVICE>_API_KEY and <SERVICE>_BASE_URL are the
#                    variables Inspect reads, with <service> upper-cased and dashes as underscores
#   local-out        where the episode directories come back to
#   tunnel-port      a local port that reaches the model server; this script reverse-forwards it to the
#                    host, so the host reaches the model with no credentials of its own
#
# The host is pinned with BOX_RUN_HOSTS (the reverse tunnel must end on the host the job runs on), and
# needs Docker with the Compose plugin. Set BASHARENA_DRY_RUN=1 to print the two commands and run nothing.
set -euo pipefail
[ "$#" -ge 5 ] || { sed -n 2,17p "$0" >&2; exit 64; }
name="$1" rows="$2" model="$3" local_out="$4" port="$5"
shift 5
box="${BOX_RUN_HOSTS:?pin one host with BOX_RUN_HOSTS=root@<ip>}"
case "$box" in *,*|*" "*) echo "BOX_RUN_HOSTS must name exactly one host" >&2; exit 64 ;; esac
box_run="${BOX_RUN_SH:?BOX_RUN_SH must name the runner that ships the checkout to the host}"
case "$model" in openai-api/*/*) ;; *) echo "the model must be openai-api/<service>/<model>" >&2; exit 64 ;; esac
service="$(printf '%s' "$model" | cut -d/ -f2 | tr '[:lower:]-' '[:upper:]_')"
key_var="${service}_API_KEY" url_var="${service}_BASE_URL"
[ -n "${!key_var:-}" ] || { echo "$key_var is not set" >&2; exit 64; }
remote_port=18000
revision="$(git rev-parse HEAD)"
out="basharena-out/$name"
key=()
[ -z "${BOX_RUN_KEY:-}" ] || key=(-o IdentitiesOnly=yes -i "$BOX_RUN_KEY")
tunnel=(ssh -o BatchMode=yes -o ExitOnForwardFailure=yes "${key[@]}" \
    -N -R "127.0.0.1:$remote_port:127.0.0.1:$port" "$box")
job=("$box_run" "$name" --forward-env "$key_var" --forward-env "$url_var" --fetch "$out" "$local_out" -- \
    packages/observer/scripts/basharena-box-job.sh "$rows" "$out" "$model" "$revision" "$@")
if [ -n "${BASHARENA_DRY_RUN:-}" ]; then
    printf 'TUNNEL %s\n' "${tunnel[*]}"
    printf 'JOB %s=http://127.0.0.1:%s/v1 %s\n' "$url_var" "$remote_port" "${job[*]}"
    exit 0
fi
"${tunnel[@]}" &
tunnel_pid=$!
trap 'kill "$tunnel_pid" 2> /dev/null || true' EXIT
sleep 3
kill -0 "$tunnel_pid" || { echo "the reverse tunnel to $box did not start" >&2; exit 69; }
export "$url_var=http://127.0.0.1:$remote_port/v1"
"${job[@]}"
