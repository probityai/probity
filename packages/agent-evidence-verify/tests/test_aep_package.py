"""aep_package/v1: every layer of an action evidence package, under keys the consumer admits.

Packages are built by aep_builder.py from keys generated for this test session. The four RSA rejection
classes (bytes before the digest, bytes after the legacy prefix, a SHA-512 OID, a short padding string) are
blocks that end in the right digest and must still be refused.
"""

from __future__ import annotations

import base64
import hashlib
import warnings
from pathlib import Path
from typing import Any

import aep_builder as ab
import pytest
from agent_evidence_verify import adjudicate
from agent_evidence_verify.adapters import aep_package as ap


def _judge(tmp_path: Path, package: bytes, **assessment: Any) -> dict:
    (tmp_path / "package.aep").write_bytes(package)
    case = {"schema_version": "probity-case/v1", "case_id": "c", "artifacts": {"package.aep": {
        "path": "package.aep", "length": len(package), "sha256": hashlib.sha256(package).hexdigest()}}}
    policy = {"schema_version": "probity-policy/v1", "assessments": {"c": {
        "claim_type": "aep_package/v1", "package": "package.aep", **assessment}}}
    return adjudicate(case, policy, tmp_path)


def _statuses(result: dict) -> dict[str, str]:
    return {c["id"]: c["status"] for c in result["checks"] if c["id"] in ap.CHECKS}


def _verdict(result: dict) -> tuple[str, str]:
    return result["decision"], result["reason"]


def test_complete_package_verifies(tmp_path: Path) -> None:
    result = _judge(tmp_path, ab.zip_bytes(ab.entries()), **ab.authorities())
    assert _verdict(result) == ("supported", "package_verifies")
    assert set(_statuses(result).values()) == {"pass", "absent"}


def test_hybrid_package_with_ml_dsa_verifies(tmp_path: Path) -> None:
    result = _judge(tmp_path, ab.zip_bytes(ab.entries(pqc=True)), **ab.authorities(pqc=True))
    assert _verdict(result) == ("supported", "package_verifies")
    assert _statuses(result)["pqc_signature"] == "pass"


def test_legacy_response_only_form_is_reported(tmp_path: Path) -> None:
    result = _judge(tmp_path, ab.zip_bytes(ab.entries(legacy=True)), **ab.authorities())
    assert _verdict(result) == ("supported", "package_verifies")
    assert [c["detail"] for c in result["checks"] if c["id"] == "canonical_form"] == ["legacy response-only form"]


def test_self_carried_key_without_authority_is_never_supported(tmp_path: Path) -> None:
    result = _judge(tmp_path, ab.zip_bytes(ab.entries()))
    assert _verdict(result) == ("not_established", "signer_not_established")


def test_untrusted_signer_is_refused(tmp_path: Path) -> None:
    other = ab.pin(b"some other key")
    result = _judge(tmp_path, ab.zip_bytes(ab.entries()), authority=other,
                    tsa_authority=ab.authorities()["tsa_authority"])
    assert _verdict(result) == ("contradicted", "signer_pinned")


def test_unanchored_time_stamp_authority_is_not_established(tmp_path: Path) -> None:
    result = _judge(tmp_path, ab.zip_bytes(ab.entries()), authority=ab.authorities()["authority"])
    assert _verdict(result) == ("not_established", "tsa_not_established")


def _mutated(name: str, change) -> bytes:
    items = ab.entries()
    items[name] = change(items[name])
    return ab.zip_bytes(items)


def _flip(raw: bytes) -> bytes:
    data = bytearray(raw)
    data[len(data) // 2] ^= 1
    return bytes(data)


def _flip_b64(raw: bytes) -> bytes:
    return base64.b64encode(_flip(base64.b64decode(raw)))


@pytest.mark.parametrize("entry,change,reason", [
    ("canonical.bin", _flip, "hash"),
    ("hash.sha256", lambda r: b"0" * 64, "hash"),
    ("signature.sig", _flip_b64, "rsa_signature"),
    ("overt_receipt.json", lambda r: r.replace(b"allow", b"deny"), "receipt"),
    ("overt_receipt.sig", _flip_b64, "receipt"),
    ("metadata.json", lambda r: b"[1, 2]", "package_shape"),
    ("metadata.json", lambda r: r.replace(b'"agent_id": "agent-7"', b'"agent_id": "agent-7", "agent_id": "x"'),
     "package_shape"),
])
def test_one_layer_tampered_fails_that_layer_and_the_rest_are_not_evaluated(
        tmp_path: Path, entry: str, change, reason: str) -> None:
    result = _judge(tmp_path, _mutated(entry, change), **ab.authorities())
    assert _verdict(result) == ("contradicted", reason)
    statuses = _statuses(result)
    after = ap.CHECKS[ap.CHECKS.index(reason) + 1:]
    assert all(statuses[c] == "not_evaluated" for c in after)


def test_canonical_form_mismatch_with_matching_hash_is_refused(tmp_path: Path) -> None:
    items = ab.entries()
    items["response.txt"] = b"a different response"
    assert _verdict(_judge(tmp_path, ab.zip_bytes(items), **ab.authorities())) == ("contradicted", "canonical_form")


def test_tampered_ml_dsa_signature_is_refused(tmp_path: Path) -> None:
    items = ab.entries(pqc=True)
    items["signature_pqc.sig"] = _flip_b64(items["signature_pqc.sig"])
    assert _verdict(_judge(tmp_path, ab.zip_bytes(items), **ab.authorities(pqc=True))) == \
        ("contradicted", "pqc_signature")


@pytest.mark.parametrize("kwargs,detail", [
    ({"status": 2}, "not granted"), ({"algorithm": "2.16.840.1.101.3.4.2.3"}, "imprint algorithm"),
    ({"tamper_digest": True}, "messageDigest")])
def test_bad_time_stamp_is_refused(tmp_path: Path, kwargs: dict, detail: str) -> None:
    items = ab.entries()
    items["timestamp.tsr"] = ab.timestamp_response(bytes.fromhex(items["hash.sha256"].decode().strip()), **kwargs)
    result = _judge(tmp_path, ab.zip_bytes(items), **ab.authorities())
    assert _verdict(result) == ("contradicted", "timestamp")
    assert detail in next(c for c in result["checks"] if c["id"] == "timestamp")["detail"]


def test_time_stamp_over_another_hash_or_signed_by_another_key_is_refused(tmp_path: Path) -> None:
    from cryptography.hazmat.primitives.asymmetric import ec
    items = ab.entries()
    items["timestamp.tsr"] = ab.timestamp_response(bytes(32))
    (tmp_path / "a").mkdir()
    assert _verdict(_judge(tmp_path / "a", ab.zip_bytes(items), **ab.authorities())) == ("contradicted", "timestamp")
    items["timestamp.tsr"] = ab.timestamp_response(bytes.fromhex(items["hash.sha256"].decode().strip()),
                                                   signer=ec.generate_private_key(ec.SECP256R1()))
    (tmp_path / "b").mkdir()
    assert _verdict(_judge(tmp_path / "b", ab.zip_bytes(items), **ab.authorities())) == ("contradicted", "timestamp")


def test_missing_entry_and_unreadable_archive_are_refused(tmp_path: Path) -> None:
    items = ab.entries()
    del items["canonical.bin"]
    (tmp_path / "a").mkdir()
    assert _verdict(_judge(tmp_path / "a", ab.zip_bytes(items), **ab.authorities())) == ("contradicted", "package_shape")
    (tmp_path / "b").mkdir()
    assert _verdict(_judge(tmp_path / "b", b"not a zip", **ab.authorities())) == ("contradicted", "package_shape")


def test_entry_named_twice_is_refused(tmp_path: Path) -> None:
    items = list(ab.entries().items())
    items.append(("response.txt", b"second copy"))
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        package = ab.zip_bytes(items)
    assert _verdict(_judge(tmp_path, package, **ab.authorities())) == ("contradicted", "package_shape")


# --- the four RSA rejection classes and the two exact encodings --------------------------------------

def _block_signed(t: bytes, pad_len: int | None = None, canonical_bin: bytes | None = None) -> bytes:
    key = ab.rsa_key()
    canonical_bin = canonical_bin or ab.entries()["canonical.bin"]
    full_t = t + hashlib.sha256(canonical_bin).digest()
    k = (key.key_size + 7) // 8
    if pad_len is None:
        block = ab.full_block(key, full_t)
    else:
        head = b"\x00\x01" + b"\xff" * pad_len + b"\x00"
        block = head + b"\x42" * (k - len(head) - len(full_t)) + full_t
    return ab.rsa_raw_sign(key, block)


RSA_NEGATIVES = {
    "garbage-prefix": (b"\x13" * 17, None),
    "garbage-after-legacy-prefix": (ap.SHA256_DIGEST_INFO_ABSENT_PARAMS + b"\x00" * 64, None),
    "sha512-oid": (bytes.fromhex("302f300b06096086480165030402030420"), None),
    "short-padding": (ap.SHA256_DIGEST_INFO_ABSENT_PARAMS, 0),
}


@pytest.mark.parametrize("label", sorted(RSA_NEGATIVES))
def test_rsa_block_ending_in_the_digest_is_still_refused(tmp_path: Path, label: str) -> None:
    t, pad = RSA_NEGATIVES[label]
    items = ab.entries()
    items["signature.sig"] = base64.b64encode(_block_signed(t, pad))
    assert _verdict(_judge(tmp_path, ab.zip_bytes(items), **ab.authorities())) == ("contradicted", "rsa_signature")


def test_exact_legacy_encoding_is_accepted_and_named(tmp_path: Path) -> None:
    items = ab.entries(receipt=False)
    items["signature.sig"] = base64.b64encode(_block_signed(ap.SHA256_DIGEST_INFO_ABSENT_PARAMS,
                                                            canonical_bin=items["canonical.bin"]))
    result = _judge(tmp_path, ab.zip_bytes(items), **ab.authorities())
    assert _verdict(result) == ("supported", "package_verifies")
    assert "legacy DigestInfo" in next(c for c in result["checks"] if c["id"] == "rsa_signature")["detail"]


def test_rfc8017_block_equals_the_library_signature() -> None:
    key = ab.rsa_key()
    data = b"bytes"
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    assert ab.rsa_raw_sign(key, ab.full_block(key, ap.SHA256_DIGEST_INFO + hashlib.sha256(data).digest())) == \
        key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    assert ap.rsa_encoding(key.public_key(), key.sign(data, padding.PKCS1v15(), hashes.SHA256()), data) == "rfc8017"
