#!/usr/bin/env bash
# Start Keycloak in a container, mint a client-credentials token, record one agent
# action with the token's principal, and check the record. Needs docker, openssl,
# curl and uv; no account anywhere. Writes everything under out/.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="${KQ_OUT:-$here/out}"
port="${KQ_PORT:-8443}"
name="kq-keycloak-$$"
image="quay.io/keycloak/keycloak:26.8.2@sha256:3879c623248408de29a5303178b5816c77e8dfef3890c361f8c0bbeaa979ba3b"
issuer="https://localhost:$port/realms/probity-demo"

rm -rf "$out"
mkdir -p "$out/certs"
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT

echo "== 1. a local certificate, so the issuer is an https URL"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost" \
  -keyout "$out/certs/tls.key" -out "$out/certs/tls.crt" 2>/dev/null
chmod 644 "$out/certs/tls.key"

echo "== 2. start Keycloak with the probity-demo realm"
docker run -d --name "$name" -p "127.0.0.1:$port:8443" \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  -e KC_HOSTNAME="https://localhost:$port" \
  -e KC_HTTPS_CERTIFICATE_FILE=/certs/tls.crt -e KC_HTTPS_CERTIFICATE_KEY_FILE=/certs/tls.key \
  -v "$out/certs:/certs:ro" \
  -v "$here/realm:/opt/keycloak/data/import:ro" \
  "$image" start-dev --import-realm >/dev/null
for _ in $(seq 1 90); do
  if curl -fsS --cacert "$out/certs/tls.crt" "$issuer/.well-known/openid-configuration" \
    -o "$out/discovery.json" 2>/dev/null; then break; fi
  sleep 2
done
test -s "$out/discovery.json" || { docker logs "$name" | tail -30; echo "keycloak did not start"; exit 1; }
echo "issuer: $(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["issuer"])' "$out/discovery.json")"

echo "== 3. client-credentials token for the reconciler client"
curl -fsS --cacert "$out/certs/tls.crt" -u reconciler:reconciler-demo-secret \
  -d grant_type=client_credentials "$issuer/protocol/openid-connect/token" \
  | python3 -c 'import json,sys; sys.stdout.write(json.load(sys.stdin)["access_token"])' >"$out/token.jwt"
curl -fsS --cacert "$out/certs/tls.crt" "$issuer/protocol/openid-connect/certs" -o "$out/jwks.json"
echo "token: $(wc -c <"$out/token.jwt") bytes, JWKS keys: $(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["keys"]))' "$out/jwks.json")"

echo "== 4. read the principal out of the token"
kq() { (cd "$here" && uv run --frozen keycloak-quickstart "$@"); }
kq principal --token "$out/token.jwt" --jwks "$out/jwks.json" \
  --auth-method client_secret_basic --out "$out/principal.json"

echo "== 5. record one action; the sealed record carries the principal"
kq record --principal "$out/principal.json" --out "$out"
