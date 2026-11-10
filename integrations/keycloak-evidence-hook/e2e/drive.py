"""Drive three token grants through a running Keycloak and record what each client received.

Standard library only. Writes ``observed.json``: for each grant, the issuer, grant type, client,
the ``sub`` and the SHA-256 of the ``jti`` read from the access token the client got, and the
SHA-256 of the subject token it presented. Token values are hashed here and never written.
"""

from __future__ import annotations

import base64
import hashlib
import http.server
import json
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

KC = "http://127.0.0.1:8080"
ISSUER = f"{KC}/realms/agents"
TOKEN_URL = f"{ISSUER}/protocol/openid-connect/token"
GATEWAY = ("agent-gateway", "gateway-e2e-secret")
SCOPES = "tools:read tools:execute"


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def post(url: str, data: dict[str, str] | None = None, auth: tuple[str, str] | None = None,
         body: bytes | None = None, headers: dict[str, str] | None = None) -> tuple[int, bytes]:
    request_headers = dict(headers or {})
    payload = body
    if data is not None:
        payload = urllib.parse.urlencode(data).encode("ascii")
        request_headers["Content-Type"] = "application/x-www-form-urlencoded"
    if auth is not None:
        basic = base64.b64encode(f"{auth[0]}:{auth[1]}".encode("ascii")).decode("ascii")
        request_headers["Authorization"] = f"Basic {basic}"
    request = urllib.request.Request(url, data=payload, headers=request_headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def token(data: dict[str, str], auth: tuple[str, str] | None = None) -> str:
    status, body = post(TOKEN_URL, data, auth)
    if status != 200:
        raise SystemExit(f"token request failed: HTTP {status} {body.decode('utf-8', 'replace')}")
    return str(json.loads(body)["access_token"])


def claims(jwt: str) -> dict:
    part = jwt.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def observed(name: str, grant_type: str, jwt: str, subject_token: str | None) -> dict:
    c = claims(jwt)
    aud = c.get("aud", [])
    return {"name": name, "issuer": ISSUER, "grant_type": grant_type, "actor_client_id": GATEWAY[0],
            "subject_user_id": c["sub"], "access_token_id_sha256": sha256(c["jti"]),
            "audience": sorted(set([aud] if isinstance(aud, str) else aud)),
            "scope": sorted(set(str(c.get("scope", "")).split())),
            "subject_token_sha256": sha256(subject_token) if subject_token else None}


class AuthDevice(http.server.BaseHTTPRequestHandler):
    """Stub of the user's authentication device for the CIBA grant: it approves every request."""

    seen: list[str] = []

    def do_POST(self) -> None:  # noqa: N802 -- http.server API
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        AuthDevice.seen.append(self.headers.get("Authorization", "").removeprefix("Bearer "))
        self.send_response(201)
        self.end_headers()

    def log_message(self, *_args: object) -> None:
        return


def ciba() -> str:
    server = http.server.HTTPServer(("127.0.0.1", 8099), AuthDevice)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        status, body = post(f"{ISSUER}/protocol/openid-connect/ext/ciba/auth",
                            {"scope": f"openid {SCOPES}", "login_hint": "alice",
                             "binding_message": "ApproveToolAccess"}, GATEWAY)
        if status != 200:
            raise SystemExit(f"CIBA request failed: HTTP {status} {body!r}")
        auth_req_id = json.loads(body)["auth_req_id"]
        deadline = time.time() + 15
        while not AuthDevice.seen and time.time() < deadline:
            time.sleep(0.2)
        if not AuthDevice.seen:
            raise SystemExit("Keycloak never called the authentication device")
        status, body = post(f"{ISSUER}/protocol/openid-connect/ext/ciba/auth/callback",
                            body=json.dumps({"status": "SUCCEED"}).encode("ascii"),
                            headers={"Authorization": f"Bearer {AuthDevice.seen[0]}",
                                     "Content-Type": "application/json"})
        if status not in (200, 204):
            raise SystemExit(f"CIBA approval failed: HTTP {status} {body!r}")
        for _ in range(20):
            status, body = post(TOKEN_URL, {"grant_type": "urn:openid:params:grant-type:ciba",
                                             "auth_req_id": auth_req_id}, GATEWAY)
            if status == 200:
                return str(json.loads(body)["access_token"])
            time.sleep(2)
        raise SystemExit("no CIBA token after approval")
    finally:
        server.shutdown()


def main() -> int:
    out = sys.argv[1]
    user_token = token({"grant_type": "password", "client_id": "agent-ui", "username": "alice",
                        "password": "alice-e2e-password", "scope": SCOPES})
    exchanged = token({"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                       "subject_token": user_token,
                       "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                       "audience": "tools-api", "scope": SCOPES}, GATEWAY)
    service = token({"grant_type": "client_credentials", "scope": SCOPES}, GATEWAY)
    ciba_token = ciba()
    grants = [
        observed("token-exchange", "urn:ietf:params:oauth:grant-type:token-exchange", exchanged, user_token),
        observed("client-credentials", "client_credentials", service, None),
        observed("ciba", "urn:openid:params:grant-type:ciba", ciba_token, None),
    ]
    with open(out, "w", encoding="utf-8") as stream:
        json.dump({"grants": grants}, stream, indent=2, sort_keys=True)
        stream.write("\n")
    for grant in grants:
        print(f"GRANT {grant['name']} jti_sha256={grant['access_token_id_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
