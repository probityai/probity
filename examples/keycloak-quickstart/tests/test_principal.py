"""The principal member: thumbprints, token binding and refusal of a forged token."""

from __future__ import annotations

import base64
import hashlib
import json

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from keycloak_quickstart import principal

# RFC 7638 section 3.1: the example key and its published thumbprint.
RFC_KEY = {
    "kty": "RSA",
    "n": (
        "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
    ),
    "e": "AQAB",
    "alg": "RS256",
    "kid": "2011-04-29",
}
RFC_THUMBPRINT = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"


def _jwk(key: rsa.RSAPrivateKey, kid: str) -> dict:
    numbers = key.public_key().public_numbers()

    def enc(value: int) -> str:
        return principal.b64u_encode(value.to_bytes((value.bit_length() + 7) // 8, "big"))

    return {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid, "n": enc(numbers.n), "e": enc(numbers.e)}


def _token(key: rsa.RSAPrivateKey, kid: str, claims: dict) -> str:
    header = principal.b64u_encode(json.dumps({"alg": "RS256", "kid": kid, "typ": "JWT"}).encode())
    body = principal.b64u_encode(json.dumps(claims).encode())
    signature = key.sign(f"{header}.{body}".encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{header}.{body}.{principal.b64u_encode(signature)}"


CLAIMS = {
    "iss": "https://idp.example.org/realms/demo",
    "sub": "service-account-reconciler",
    "azp": "reconciler",
    "client_id": "reconciler",
    "aud": "mcp://files",
    "iat": 1_790_000_000,
    "exp": 1_790_000_300,
}


def test_thumbprint_matches_rfc_7638_example():
    assert principal.jwk_thumbprint(RFC_KEY) == RFC_THUMBPRINT


def test_principal_names_the_token_and_the_key():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwks = {"keys": [_jwk(key, "k1")]}
    token = _token(key, "k1", CLAIMS)
    built = principal.build_principal(token, jwks, "client_secret_basic")
    assert built["issuer"] == CLAIMS["iss"]
    assert built["subject"] == CLAIMS["sub"]
    assert built["clientId"] == "reconciler"
    assert built["audience"] == ["mcp://files"]
    assert built["kid"] == "k1"
    assert built["tokenDigest"] == hashlib.sha256(token.encode()).hexdigest()
    assert built["keyThumbprint"] == principal.jwk_thumbprint(jwks["keys"][0])
    assert built["issuedAt"] == "2026-09-21T14:13:20Z"
    assert set(built["key"]) == {"e", "kid", "kty", "n"}


def test_token_signed_by_another_key_is_refused():
    real = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    forger = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwks = {"keys": [_jwk(real, "k1")]}
    with pytest.raises(principal.TokenError, match="does not verify"):
        principal.build_principal(_token(forger, "k1", CLAIMS), jwks, "client_secret_basic")


def test_unknown_kid_is_refused():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(principal.TokenError, match="0 signing keys"):
        principal.build_principal(_token(key, "other", CLAIMS), {"keys": [_jwk(key, "k1")]}, "none")


def test_base64url_roundtrip():
    raw = bytes(range(256))
    assert principal.b64u_decode(principal.b64u_encode(raw)) == raw
    assert "=" not in principal.b64u_encode(b"a")
    assert base64.urlsafe_b64decode(principal.b64u_encode(b"ab") + "=") == b"ab"
