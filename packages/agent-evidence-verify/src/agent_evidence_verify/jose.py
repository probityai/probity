"""JOSE primitives the signed-record adapters share: strict base64url, JWK keys, JWS signatures.

One reading of each, so two adapters never accept two different encodings of one signature:
base64url is unpadded and in its one canonical form (RFC 7515 section 2); a JWK becomes a key only
as an Ed25519 OKP key of 32 bytes or a P-256 EC point whose coordinates lie in the field (SEC 1
section 2.3.4); a JWS signature is EdDSA over 64 bytes or ES256 as raw ``r || s`` (RFC 7518 section
3.4); a DSSE signature also reads ES256 in strict DER, the form DSSE signers commonly write.

An Ed25519 public key that is not the canonical encoding of a point, or that encodes a point of
order dividing 8, verifies nothing here. OpenSSL accepts such a key, and under the identity point the
signature ``R = identity, S = 0`` verifies every message (RFC 8032 section 5.1.7 does not exclude
it), so a record "signed" under it binds no one: :func:`ed25519_weak_key` names those keys and
:func:`verify_signature` refuses them.
"""

from __future__ import annotations

import base64
import re
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

_B64URL = re.compile(r"[A-Za-z0-9_-]*")
#: The P-256 field prime: a JWK coordinate at or past it names no point (SEC 1 section 2.3.4).
P256_FIELD = 2**256 - 2**224 + 2**192 + 2**96 - 1
#: A DER integer of an ES256 signature fits in 32 bytes.
_P256_ORDER_BITS = 256


def b64url_decode(text: Any) -> bytes:
    """Strict unpadded base64url (RFC 7515 section 2), in its one canonical form."""
    if not isinstance(text, str) or not _B64URL.fullmatch(text) or len(text) % 4 == 1:
        raise ValueError("not unpadded base64url")
    raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != text:
        raise ValueError("non-canonical base64url")
    return raw


#: Ed25519's field prime, curve constant ``d`` and a square root of -1 (RFC 8032 section 5.1).
_ED_P = 2**255 - 19
_ED_D = -121665 * pow(121666, -1, _ED_P) % _ED_P
_ED_SQRT_M1 = pow(2, (_ED_P - 1) // 4, _ED_P)


def _ed_point(raw: bytes) -> tuple[int, int] | None:
    """The affine point a 32-byte Ed25519 encoding names (RFC 8032 section 5.1.3), else None."""
    y = int.from_bytes(raw, "little") & ((1 << 255) - 1)
    sign = raw[31] >> 7
    if y >= _ED_P:
        return None  # a non-canonical encoding: a second spelling of a point, never a key
    u, v = (y * y - 1) % _ED_P, (_ED_D * y * y + 1) % _ED_P
    x2 = u * pow(v, -1, _ED_P) % _ED_P
    if x2 == 0:
        return None if sign else (0, y)
    x = pow(x2, (_ED_P + 3) // 8, _ED_P)
    if (x * x - x2) % _ED_P:
        x = x * _ED_SQRT_M1 % _ED_P
    if (x * x - x2) % _ED_P:
        return None
    return (_ED_P - x if x & 1 != sign else x), y


def _ed_double(point: tuple[int, int]) -> tuple[int, int]:
    """``2P`` on edwards25519 (a = -1), by the complete twisted Edwards addition law."""
    x, y = point
    t = _ED_D * x * x * y * y % _ED_P
    return (2 * x * y * pow(1 + t, -1, _ED_P) % _ED_P,
            (y * y + x * x) * pow(1 - t, -1, _ED_P) % _ED_P)


def ed25519_weak_key(raw: Any) -> bool:
    """Whether 32 key bytes name no Ed25519 key a signature can bind: not 32 bytes, a non-canonical
    or off-curve encoding, or a point of order dividing 8 (``8P`` is the identity)."""
    if not isinstance(raw, bytes) or len(raw) != 32:
        return True
    point = _ed_point(raw)
    if point is None:
        return True
    for _ in range(3):
        point = _ed_double(point)
    return point == (0, 1)


def jwk_signs(jwk: dict[str, Any]) -> bool:
    """RFC 7517 sections 4.2 and 4.3: a key marked for encryption, or not for verify, never signs."""
    if "use" in jwk and jwk["use"] != "sig":
        return False
    ops = jwk.get("key_ops")
    return ops is None or (isinstance(ops, list) and "verify" in ops)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _coordinate(text: Any) -> int:
    return int.from_bytes(b64url_decode(text), "big")


def public_key(method: dict[str, Any]) -> tuple[str, Any]:
    """The algorithm a method's JWK verifies and the key object, or ``("none", None)``."""
    jwk = method.get("publicKeyJwk")
    if not isinstance(jwk, dict):
        return "none", None
    try:
        if jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519":
            raw = b64url_decode(jwk["x"])
            # The raw 32 bytes: a point that does not decode fails at verification, as the
            # reference rail's does, not here as a key of no algorithm.
            return ("EdDSA", raw) if len(raw) == 32 else ("none", None)
        if jwk.get("kty") == "EC" and jwk.get("crv") == "P-256":
            x, y = _coordinate(jwk["x"]), _coordinate(jwk["y"])
            if max(x, y) >= P256_FIELD:
                return "none", None
            point = b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")
            return "ES256", ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
    except (KeyError, ValueError, TypeError):
        pass
    return "none", None


def verify_signature(alg: str, key: Any, message: bytes, signature: bytes) -> bool:
    """A JWS signature: EdDSA over 64 bytes, or ES256 as raw r || s (RFC 7518 section 3.4).

    An Ed25519 key :func:`ed25519_weak_key` names verifies nothing.
    """
    try:
        if alg == "EdDSA":
            if len(signature) != 64 or ed25519_weak_key(key):
                return False
            Ed25519PublicKey.from_public_bytes(key).verify(signature, message)
            return True
        if alg == "ES256" and len(signature) == 64:
            r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
            key.verify(encode_dss_signature(r, s), message, ec.ECDSA(hashes.SHA256()))
            return True
    except (InvalidSignature, ValueError):
        return False
    return False


def _der_integer(data: bytes, at: int) -> tuple[int, int] | None:
    """One minimal, non-negative DER INTEGER with a short-form length at ``at``."""
    if at + 2 > len(data) or data[at] != 0x02 or not 0 < data[at + 1] < 0x80:
        return None
    end = at + 2 + data[at + 1]
    body = data[at + 2:end]
    if end > len(data) or body[0] & 0x80 or (len(body) > 1 and body[0] == 0 and body[1] < 0x80):
        return None
    return int.from_bytes(body, "big"), end


def der_signature(data: bytes) -> bytes | None:
    """An ECDSA-Sig-Value (RFC 3279 section 2.2.3) in strict DER as raw r || s, else None."""
    if len(data) < 2 or data[0] != 0x30 or data[1] >= 0x80 or data[1] != len(data) - 2:
        return None
    first = _der_integer(data, 2)
    second = _der_integer(data, first[1]) if first else None
    if first is None or second is None or second[1] != len(data):
        return None
    r, s = first[0], second[0]
    if max(r, s) >= 2**_P256_ORDER_BITS:
        return None
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def verify_dsse_signature(alg: str, key: Any, message: bytes, signature: bytes) -> bool:
    """A DSSE signature: as JWS, and for ES256 also the strict DER form signers commonly write."""
    if verify_signature(alg, key, message, signature):
        return True
    raw = der_signature(signature) if alg == "ES256" else None
    return raw is not None and verify_signature(alg, key, message, raw)
