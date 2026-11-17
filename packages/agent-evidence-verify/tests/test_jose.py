"""The shared JOSE primitives: an Ed25519 key that binds no one verifies nothing.

OpenSSL accepts an Ed25519 public key that is a point of small order. Under the identity point the
signature ``R = identity, S = 0`` verifies every message, so a reader that trusts the library's
verdict reports a record signed by nobody as signed. These tests pin that fact about the library
and the refusal that answers it.
"""

import pytest
from agent_evidence_verify.jose import ed25519_weak_key, jwk_signs, verify_signature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

P = 2**255 - 19
IDENTITY = b"\x01" + b"\x00" * 31


def _y(value: int, sign: int = 0) -> bytes:
    raw = bytearray(value.to_bytes(32, "little"))
    raw[31] |= sign << 7
    return bytes(raw)


def test_the_library_accepts_the_universal_forgery_under_the_identity_point() -> None:
    """Why the check exists: without it, one 64-byte value 'signs' every message."""
    Ed25519PublicKey.from_public_bytes(IDENTITY).verify(IDENTITY + b"\x00" * 32, b"any message")


@pytest.mark.parametrize("message", [b"", b"any message", b"\xff" * 300])
def test_verify_signature_refuses_the_identity_key(message: bytes) -> None:
    assert verify_signature("EdDSA", IDENTITY, message, IDENTITY + b"\x00" * 32) is False


@pytest.mark.parametrize("raw", [
    IDENTITY,                      # order 1
    _y(P - 1),                     # (0, -1), order 2
    b"\x00" * 32,                  # y = 0, x = sqrt(-1): order 4
    _y(1 + P),                     # the identity spelled non-canonically (y >= p)
    _y(2),                         # y = 2 names no point on the curve
    _y(1, sign=1),                 # x = 0 with the sign bit set: no such point
    b"\x01" * 31,                  # 31 bytes
])
def test_weak_and_malformed_ed25519_keys(raw: bytes) -> None:
    assert ed25519_weak_key(raw)


L = 2**252 + 27742317777372353535851937790883648493  # the prime subgroup's order


def _add(a: tuple[int, int], b: tuple[int, int]) -> tuple[int, int]:
    from agent_evidence_verify import jose
    t = jose._ED_D * a[0] * b[0] * a[1] * b[1] % P
    return ((a[0] * b[1] + a[1] * b[0]) * pow(1 + t, -1, P) % P,
            (a[1] * b[1] + a[0] * b[0]) * pow(1 - t, -1, P) % P)


def _times(k: int, point: tuple[int, int]) -> tuple[int, int]:
    out = (0, 1)
    while k:
        if k & 1:
            out = _add(out, point)
        point, k = _add(point, point), k >> 1
    return out


def _encode(point: tuple[int, int]) -> bytes:
    return _y(point[1], point[0] & 1)


def test_every_point_of_the_torsion_subgroup_is_weak() -> None:
    """[L]Q of a curve point Q lies in the order-8 subgroup; walk a generator of it."""
    from agent_evidence_verify import jose
    generator = None
    for y in range(2, 200):
        point = jose._ed_point(_y(y))
        if point is not None:
            torsion = _times(L, point)
            if _times(4, torsion) != (0, 1):
                generator = torsion
                break
    assert generator is not None, "a curve point with a full torsion component"
    points = {_encode(_times(k, generator)) for k in range(8)}
    assert len(points) == 8
    assert all(ed25519_weak_key(raw) for raw in points)


def test_a_real_key_is_not_weak() -> None:
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    assert not ed25519_weak_key(raw)
    assert verify_signature("EdDSA", raw, b"m", key.sign(b"m"))


@pytest.mark.parametrize(("jwk", "signs"), [
    ({}, True), ({"use": "sig"}, True), ({"use": "enc"}, False),
    ({"key_ops": ["verify"]}, True), ({"key_ops": ["sign", "verify"]}, True),
    ({"key_ops": ["encrypt"]}, False), ({"key_ops": "verify"}, False), ({"key_ops": []}, False),
])
def test_jwk_signs(jwk: dict, signs: bool) -> None:
    assert jwk_signs(jwk) is signs
