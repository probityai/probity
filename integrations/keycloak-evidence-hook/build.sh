#!/usr/bin/env bash
# Build and test the listener in a pinned Maven image, then hold every artifact Maven fetched to
# maven.lock (path and SHA-256 of each jar and pom). --update-lock rewrites the lock instead.
# Needs docker only. Writes target/keycloak-evidence-hook-0.1.0.jar.
set -euo pipefail
cd "$(dirname "$0")"
IMAGE="maven:3.9.11-eclipse-temurin-21@sha256:6fdc855a6ed81d288ca7ca37ac6ff5e9308b612485c0801d70b25a858c83d237"
M2="$(mktemp -d)"
trap 'rm -rf "$M2"' EXIT
docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -e MAVEN_CONFIG=/tmp/.m2 \
  -v "$PWD":/src -v "$M2":/m2 -w /src "$IMAGE" \
  mvn -B -ntp -Dmaven.repo.local=/m2/repository -Dstyle.color=never clean verify
(cd "$M2/repository" && find . -type f \( -name '*.jar' -o -name '*.pom' \) -print0 | sort -z \
  | xargs -0 sha256sum) > "$M2/resolved.lock"
if [ "${1:-}" = "--update-lock" ]; then
  cp "$M2/resolved.lock" maven.lock
  echo "LOCK_UPDATED $(wc -l < maven.lock) artifacts"
elif diff -u maven.lock "$M2/resolved.lock"; then
  echo "LOCK_OK $(wc -l < maven.lock) artifacts match maven.lock"
else
  echo "LOCK_MISMATCH: Maven resolved artifacts that differ from maven.lock" >&2
  exit 1
fi
sha256sum target/keycloak-evidence-hook-0.1.0.jar
