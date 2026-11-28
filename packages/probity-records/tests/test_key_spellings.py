"""One public key has one spelling: a respelled key member is refused, never read as a second key or a crash.

``identity.public_jwk`` reads x, y, n and e only in their canonical base64url, an EC coordinate only at the full size
of its curve (RFC 7518 section 6.2.1.2), an Ed25519 x only at 32 bytes and RSA n and e only without a leading zero
octet (RFC 7518 section 2). ``jwk_thumbprint`` exists only for such a key, so a trust bundle that pins a second
spelling is ``trust_bundle_malformed`` and a JWS check under one is False.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from key_spellings import (
    KEY_MEMBERS,
    NAME_EDITS,
    NAME_MEMBERS,
    TEXT_EDITS,
    b64u,
    key_edits,
)
from probity_records import identity, registry
from probity_records.identity import _verify_jws, jwk_thumbprint
from probity_records.verified_identities_vectors import judge

ROWS = json.loads((Path(__file__).parents[1] / "vectors" / "shared" / "verified_identities.json").read_text())
ACCEPTED = [r for r in ROWS if "refused" not in r["expected"]]
EDITED = [case for row in ACCEPTED for case in key_edits(row)]


def _keys_in(node: Any) -> list[dict[str, Any]]:
    """Every object with a ``kty`` anywhere under ``node``, found without key_edits' idea of where keys live."""
    if isinstance(node, dict):
        return ([node] if "kty" in node else []) + [k for v in node.values() for k in _keys_in(v)]
    if isinstance(node, list):
        return [k for v in node for k in _keys_in(v)]
    return []


def test_the_edits_reach_every_member_of_every_bundle_key_and_the_stamp_keys() -> None:
    """The count is derived from the rows: each string x, y, n or e of each key in an accepted row's bundle times the
    text spellings, plus each string kty or crv times the name spellings. A key the generator skips (an anchor key,
    a key outside ``issuers``) or a member it leaves out makes the two counts differ."""
    keys = [k for row in ACCEPTED for k in _keys_in(row.get("bundle"))]
    want = sum(len(TEXT_EDITS) * sum(isinstance(k.get(m), str) for m in KEY_MEMBERS)
               + len(NAME_EDITS) * sum(isinstance(k.get(m), str) for m in NAME_MEMBERS) for k in keys)
    assert len(EDITED) == want
    assert {(k.get("kty"), k.get("crv")) for k in keys} == {("OKP", "Ed25519"), ("EC", "P-256"), ("RSA", None)}
    names = {name.split("/key/")[1] for name, _ in EDITED}
    assert any(n.startswith("gateway.") for n in names)  # a stamp key
    for member in KEY_MEMBERS + NAME_MEMBERS:
        assert any(f"/{member}/" in n for n in names), member


@pytest.mark.parametrize(("name", "row"), EDITED, ids=[n for n, _ in EDITED])
def test_a_bundle_key_in_a_second_spelling_is_trust_bundle_malformed(name: str, row: dict[str, Any]) -> None:
    assert judge(row) == {"refused": "trust_bundle_malformed"}, name


OKP = {"crv": "Ed25519", "kty": "OKP", "x": "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w"}


def _public_jwk() -> Any:
    reader = getattr(identity, "public_jwk", None)
    assert reader is not None, "identity has no public_jwk: no reader holds a key to one spelling"
    return reader


@pytest.mark.parametrize("edit", sorted(TEXT_EDITS))
def test_public_jwk_and_the_thumbprint_refuse_a_second_spelling(edit: str) -> None:
    jwk = {**OKP, "x": TEXT_EDITS[edit](OKP["x"])}
    with pytest.raises(ValueError):
        _public_jwk()(jwk)
    with pytest.raises(ValueError):
        jwk_thumbprint(jwk)


@pytest.mark.parametrize("member", NAME_MEMBERS)
@pytest.mark.parametrize("edit", sorted(NAME_EDITS))
def test_a_key_name_in_another_type_is_a_value_error_not_a_raise(member: str, edit: str) -> None:
    """A crv given as ``["Ed25519"]`` once made the curve lookup raise TypeError (a list does not hash)."""
    jwk = {**OKP, member: NAME_EDITS[edit](OKP[member])}
    with pytest.raises(ValueError):
        _public_jwk()(jwk)
    with pytest.raises(ValueError):
        jwk_thumbprint(jwk)


def test_an_unknown_curve_has_no_thumbprint() -> None:
    with pytest.raises(ValueError):
        jwk_thumbprint({**OKP, "crv": "X25519"})


def _ec_key_with_a_leading_zero_x() -> ec.EllipticCurvePrivateKey:
    for seed in range(1, 100_000):
        key = ec.derive_private_key(seed, ec.SECP256R1())
        if key.public_key().public_numbers().x < 1 << 248:
            return key
    raise AssertionError("no key found")


def test_an_ec_coordinate_shorter_than_its_curve_does_not_verify() -> None:
    """The short x names the same point, so a reader that reads it as a number verifies the signature under it."""
    key = _ec_key_with_a_leading_zero_x()
    nums = key.public_key().public_numbers()
    full = {"crv": "P-256", "kty": "EC", "x": b64url32(nums.x), "y": b64url32(nums.y)}
    short = {**full, "x": b64u(nums.x.to_bytes(32, "big").lstrip(b"\0"))}
    data = b"header.claims"
    r, s = decode_dss_signature(key.sign(data, ec.ECDSA(hashes.SHA256())))
    s = min(s, _N - s)  # the low-s spelling the registry reads
    sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    assert _verify_jws("ES256", full, data, sig)
    assert not _verify_jws("ES256", short, data, sig)
    assert registry.verify_signature("ES256", full, data, sig)
    assert not registry.verify_signature("ES256", short, data, sig)
    with pytest.raises(ValueError):
        jwk_thumbprint(short)


_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def b64url32(value: int) -> str:
    return b64u(value.to_bytes(32, "big"))
