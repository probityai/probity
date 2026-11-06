"""Turn a verified Keycloak access token into the ``principal`` member.

The token's signature is checked against the realm's JWKS first, so the member
describes a token the issuer's key signed, not one that merely parses.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
from typing import Any

from agent_evidence_vectors.auditrecord import canonical_bytes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

#: Members each key type contributes to its RFC 7638 thumbprint, section 3.2.
THUMBPRINT_MEMBERS = {
    "RSA": ("e", "kty", "n"),
    "EC": ("crv", "kty", "x", "y"),
    "OKP": ("crv", "kty", "x"),
}


class TokenError(ValueError):
    """The token cannot be tied to a key in the supplied JWKS."""


def b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def jwk_thumbprint(jwk: dict[str, Any]) -> str:
    """RFC 7638 SHA-256 thumbprint: the required members, sorted, no whitespace."""
    try:
        names = THUMBPRINT_MEMBERS[jwk["kty"]]
        subset = {name: jwk[name] for name in names}
    except KeyError as exc:
        raise TokenError(f"jwk lacks {exc} for thumbprint") from exc
    body = json.dumps(subset, separators=(",", ":"), sort_keys=True).encode("ascii")
    return b64u_encode(hashlib.sha256(body).digest())


def split_token(token: str) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise TokenError("not a compact JWS")
    header = json.loads(b64u_decode(parts[0]))
    claims = json.loads(b64u_decode(parts[1]))
    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    return header, claims, signing_input, b64u_decode(parts[2])


def _public_key(jwk: dict[str, Any]) -> Any:
    if jwk["kty"] == "RSA":
        numbers = rsa.RSAPublicNumbers(
            int.from_bytes(b64u_decode(jwk["e"]), "big"),
            int.from_bytes(b64u_decode(jwk["n"]), "big"),
        )
        return numbers.public_key()
    if jwk["kty"] == "EC" and jwk.get("crv") == "P-256":
        return ec.EllipticCurvePublicNumbers(
            int.from_bytes(b64u_decode(jwk["x"]), "big"),
            int.from_bytes(b64u_decode(jwk["y"]), "big"),
            ec.SECP256R1(),
        ).public_key()
    raise TokenError(f"unsupported key {jwk.get('kty')}/{jwk.get('crv')}")


def check_signature(alg: str, jwk: dict[str, Any], signing_input: bytes, signature: bytes) -> None:
    key = _public_key(jwk)
    try:
        if alg == "RS256":
            key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
        elif alg == "ES256":
            half = len(signature) // 2
            der = encode_dss_signature(
                int.from_bytes(signature[:half], "big"), int.from_bytes(signature[half:], "big")
            )
            key.verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
        else:
            raise TokenError(f"unsupported alg {alg}")
    except InvalidSignature as exc:
        raise TokenError("token signature does not verify under the JWKS key") from exc


def rfc3339(epoch: int) -> str:
    stamp = datetime.datetime.fromtimestamp(epoch, datetime.UTC)
    return stamp.strftime("%Y-%m-%dT%H:%M:%SZ")


def build_principal(
    token: str, jwks: dict[str, Any], auth_method: str, source: str = "jwt-access-token"
) -> dict[str, Any]:
    """The ``principal`` member for ``token``, read against ``jwks``.

    ``auth_method`` is how the client authenticated at the token endpoint; the
    token does not say, so the caller states it.
    """
    header, claims, signing_input, signature = split_token(token)
    kid = header.get("kid")
    keys = jwks.get("keys", [])
    matches = [k for k in keys if k.get("kid") == kid and k.get("use", "sig") == "sig"]
    if len(matches) != 1:
        raise TokenError(f"JWKS holds {len(matches)} signing keys for kid {kid!r}")
    jwk = matches[0]
    check_signature(header["alg"], jwk, signing_input, signature)
    audience = claims["aud"] if isinstance(claims["aud"], list) else [claims["aud"]]
    public = {name: jwk[name] for name in (*THUMBPRINT_MEMBERS[jwk["kty"]], "kid")}
    return {
        "issuer": claims["iss"],
        "subject": claims["sub"],
        "clientId": claims.get("client_id") or claims["azp"],
        "audience": audience,
        "authMethod": auth_method,
        "source": source,
        "tokenDigest": hashlib.sha256(token.strip().encode("ascii")).hexdigest(),
        "issuedAt": rfc3339(claims["iat"]),
        "expiresAt": rfc3339(claims["exp"]),
        "kid": kid,
        "key": public,
        "keyThumbprint": jwk_thumbprint(jwk),
        "jwksDigest": hashlib.sha256(canonical_bytes(jwks)).hexdigest(),
    }
