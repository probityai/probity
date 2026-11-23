"""Write the web_bot_auth/v1 example: one signed request, its body, the pinned key directory, the case and the policy.

Run ``python3 generate.py`` to write the files and ``python3 generate.py --check`` to compare them with the
committed bytes. The signing key is derived from a fixed public label, so the bytes are the same on every run
and carry no trust outside this example. The signature base is written here by hand from the component list,
so the verifier is not the oracle for the request it judges.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

HERE = Path(__file__).resolve().parent
CASE_ID = "web-bot-auth-signed-deploy-request"
AGENT = "https://agent.example/.well-known/http-message-signatures-directory"
AUTHORITY = "api.example"
URL = "https://api.example/v1/deploy"
BODY = b'{"service":"billing","revision":"7f3a9c1"}'
CREATED = 1795262400  # 2026-11-21T12:00:00Z
EXPIRES = CREATED + 300
AT = "2026-11-21T12:02:00Z"

CHECK = False
STALE: list[str] = []


def write(name: str, data: bytes) -> dict:
    if CHECK:
        if not (HERE / name).is_file() or (HERE / name).read_bytes() != data:
            STALE.append(name)
    else:
        (HERE / name).write_bytes(data)
    return {"path": name, "length": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def render(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def main() -> None:
    private = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"web-bot-auth-example").digest())
    x = b64url(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
    thumbprint = json.dumps({"crv": "Ed25519", "kty": "OKP", "x": x}, separators=(",", ":"), sort_keys=True)
    kid = b64url(hashlib.sha256(thumbprint.encode()).digest())

    digest = f"sha-256=:{base64.b64encode(hashlib.sha256(BODY).digest()).decode()}:"
    agent_member = f'agent1="{AGENT}"'
    params = ('("@method" "@authority" "@path" "content-digest" "signature-agent";key="agent1")'
              f';created={CREATED};expires={EXPIRES};keyid="{kid}";alg="ed25519";nonce="deploy-0001";tag="web-bot-auth"')
    base = "\n".join([
        '"@method": POST', f'"@authority": {AUTHORITY}', '"@path": /v1/deploy', f'"content-digest": {digest}',
        f'"signature-agent";key="agent1": "{AGENT}"', f'"@signature-params": {params}',
    ])
    signature = base64.b64encode(private.sign(base.encode("ascii"))).decode("ascii")
    request = {"method": "POST", "url": URL, "headers": [
        ["Host", AUTHORITY], ["Content-Type", "application/json"], ["Content-Digest", digest],
        ["Signature-Agent", agent_member], ["Signature-Input", f"sig1={params}"], ["Signature", f"sig1=:{signature}:"],
    ]}
    directory = render({"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": kid, "x": x, "use": "sig"}]})

    artifacts = {"request.json": write("request.json", render(request)),
                 "body.bin": write("body.bin", BODY),
                 "directory.json": write("directory.json", directory)}
    write("case.json", render({"schema_version": "probity-case/v1", "case_id": CASE_ID, "artifacts": artifacts}))
    write("policy.json", render({"schema_version": "probity-policy/v1", "assessments": {CASE_ID: {
        "claim_type": "web_bot_auth/v1", "request": "request.json", "body": "body.bin",
        "directory": "directory.json", "directory_sha256": artifacts["directory.json"]["sha256"],
        "signature_agent": AGENT, "authority": AUTHORITY, "at": AT,
        "required_components": ["@method", "@path", "content-digest"],
        "max_age_seconds": 600, "max_validity_seconds": 600}}}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    CHECK = parser.parse_args().check
    main()
    if STALE:
        raise SystemExit(f"stale example files: {', '.join(STALE)}")
    print("web bot auth fixture bytes pass" if CHECK else "web bot auth example generated")
