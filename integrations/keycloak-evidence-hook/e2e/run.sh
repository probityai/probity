#!/usr/bin/env bash
# End-to-end run: test the alignment check, build the listener, check that the pinned Keycloak image
# ships every runtime dependency at the pom's version, start Keycloak with it, drive three grants,
# check every receipt offline. Needs docker, openssl, python3 and uv; run from anywhere
# in a checkout.
# Writes the run's outputs to $EVIDENCE_OUT (default: e2e/recorded) and its logs beside them.
set -uo pipefail
cd "$(dirname "$0")" || exit 1
HERE=$(pwd)
ROOT=$(git -C "$HERE" rev-parse --show-toplevel) || exit 1
OUT=${EVIDENCE_OUT:-$HERE/recorded}
export EVIDENCE_WORK
EVIDENCE_WORK=$(mktemp -d)
mkdir -p "$OUT"
# The Keycloak image is named once, in docker-compose.yml; check_alignment.py holds it to one line.
KEYCLOAK_IMAGE=$(sed -n 's/^ *image: *\(quay\.io\/keycloak\/keycloak:[^ ]*\) *$/\1/p' "$HERE/docker-compose.yml")

step() { printf 'STEP %s %s\n' "$1" "$2"; }

cleanup() {
  docker compose -f "$HERE/docker-compose.yml" logs --no-color keycloak > "$OUT/keycloak.log" 2>&1
  docker compose -f "$HERE/docker-compose.yml" down -v > /dev/null 2>&1
  # The sink is written by the container's user; remove it with the same pinned image.
  docker run --rm --user 0 --entrypoint /bin/rm -v "$EVIDENCE_WORK":/w "$KEYCLOAK_IMAGE" \
    -rf /w/sink > /dev/null 2>&1
  rm -rf "$EVIDENCE_WORK"
}
trap cleanup EXIT

python3 -I "$HERE/../test_check_alignment.py" > "$OUT/align-tests.log" 2>&1
rc=$?; step align-tests "rc=$rc"; [ "$rc" = 0 ] || { cat "$OUT/align-tests.log"; exit 1; }

LOCK_OUT="$OUT/resolved.lock" "$HERE/../build.sh" > "$OUT/build.log" 2>&1
rc=$?; step build "rc=$rc"; [ "$rc" = 0 ] || { tail -40 "$OUT/build.log"; exit 1; }

# A tag does not bind the digest beside it, so read the jars the pinned image actually holds.
docker run --rm --entrypoint /bin/ls "$KEYCLOAK_IMAGE" -1 /opt/keycloak/lib/lib/boot /opt/keycloak/lib/lib/main \
  > "$OUT/image-jars.txt" 2> "$OUT/image-jars.err"
rc=$?; step image-jars "rc=$rc"; [ "$rc" = 0 ] || { cat "$OUT/image-jars.err"; exit 1; }
python3 -I "$HERE/../check_alignment.py" --image "$HERE/.." "$OUT/image-jars.txt" > "$OUT/align-image.log" 2>&1
rc=$?; step align-image "rc=$rc"; [ "$rc" = 0 ] || { cat "$OUT/align-image.log"; exit 1; }

# A throwaway recorder key for this run only. A realm operator supplies their own key files.
mkdir -p "$EVIDENCE_WORK/keys" "$EVIDENCE_WORK/sink"
openssl genpkey -algorithm ed25519 -out "$EVIDENCE_WORK/keys/recorder.pem" || exit 1
openssl pkey -in "$EVIDENCE_WORK/keys/recorder.pem" -pubout -out "$EVIDENCE_WORK/keys/recorder.pub.pem" || exit 1
chmod 0644 "$EVIDENCE_WORK/keys/recorder.pem" "$EVIDENCE_WORK/keys/recorder.pub.pem"
chmod 0777 "$EVIDENCE_WORK/sink"
step keys "rc=0"

docker compose -f "$HERE/docker-compose.yml" up -d > "$OUT/compose-up.log" 2>&1
rc=$?; step compose-up "rc=$rc"; [ "$rc" = 0 ] || { cat "$OUT/compose-up.log"; exit 1; }

READY=0
for _ in $(seq 1 90); do
  if curl -fsS http://127.0.0.1:8080/realms/agents/.well-known/openid-configuration > /dev/null 2>&1; then
    READY=1; break
  fi
  sleep 2
done
step keycloak-ready "ready=$READY"; [ "$READY" = 1 ] || exit 1

python3 "$HERE/drive.py" "$EVIDENCE_WORK/observed.json"
rc=$?; step drive "rc=$rc"; [ "$rc" = 0 ] || exit 1

(cd "$ROOT" && uv sync --frozen --package agent-evidence-verify > "$OUT/uv-sync.log" 2>&1)
rc=$?; step uv-sync "rc=$rc"; [ "$rc" = 0 ] || { tail -20 "$OUT/uv-sync.log"; exit 1; }

(cd "$ROOT" && uv run --frozen --package agent-evidence-verify python "$HERE/check.py" \
  "$EVIDENCE_WORK" "$OUT/checks" uv run --frozen --package agent-evidence-verify agent-evidence-verify)
rc=$?; step check "rc=$rc"
cp "$EVIDENCE_WORK/sink/receipts.jsonl" "$OUT/receipts.jsonl"
cp "$EVIDENCE_WORK/keys/recorder.pub.pem" "$OUT/recorder.pub.pem"
echo "EXIT=$rc"
exit "$rc"
