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


def test_legacy_response_only_form_leaves_metadata_unbound(tmp_path: Path) -> None:
    result = _judge(tmp_path, ab.zip_bytes(ab.entries(legacy=True)), **ab.authorities())
    assert _verdict(result) == ("not_established", "metadata_unbound")
    assert _statuses(result)["canonical_form"] == "unavailable"
    assert _statuses(result)["timestamp"] == "pass"


def test_legacy_package_with_its_policy_decision_rewritten_is_never_supported(tmp_path: Path) -> None:
    """Every layer of a legacy package still verifies after metadata and an unsigned receipt are both rewritten."""
    import json
    items = ab.entries(legacy=True, sign_receipt=False)
    meta = json.loads(items["metadata.json"])
    receipt = json.loads(items["overt_receipt.json"])
    meta["policy_decision"] = receipt["policy"]["decision"] = "deny"
    items["metadata.json"], items["overt_receipt.json"] = json.dumps(meta).encode(), json.dumps(receipt).encode()
    result = _judge(tmp_path, ab.zip_bytes(items), **ab.authorities())
    assert _verdict(result) == ("not_established", "metadata_unbound")


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


# --- archives two readers read differently ------------------------------------------------------------

def test_archive_with_another_package_prepended_is_refused(tmp_path: Path) -> None:
    """A reader from the end record reads the second archive; a reader from byte 0 reads the first."""
    other = ab.entries()
    other["response.txt"] = b"a different response"
    package = ab.zip_bytes(other) + ab.zip_bytes(ab.entries())
    assert _verdict(_judge(tmp_path, package, **ab.authorities())) == ("contradicted", "package_shape")


@pytest.mark.parametrize("where", ["gap", "trailer", "comment"])
def test_bytes_outside_the_entries_are_refused(tmp_path: Path, where: str) -> None:
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in ab.entries().items():
            z.writestr(name, data)
        if where == "comment":
            z.comment = b"hidden"
    raw = buf.getvalue()
    if where == "trailer":
        raw += b"PK\x03\x04 trailing"
    if where == "gap":
        end = raw.rindex(b"PK\x05\x06")
        offset_cd = int.from_bytes(raw[end + 16:end + 20], "little")
        size_cd = int.from_bytes(raw[end + 12:end + 16], "little")
        hidden = b"PK\x03\x04hidden entry bytes"
        raw = (raw[:offset_cd] + hidden + raw[offset_cd:end + 16]
               + (offset_cd + len(hidden)).to_bytes(4, "little") + raw[end + 20:])
        assert size_cd
    assert _verdict(_judge(tmp_path, raw, **ab.authorities())) == ("contradicted", "package_shape")


@pytest.mark.parametrize("name", ["Metadata.json", "sub/metadata.json", "sub\\response.txt"])
def test_case_variant_or_path_entry_is_refused(tmp_path: Path, name: str) -> None:
    items = list(ab.entries().items()) + [(name, b'{"policy_decision": "deny"}')]
    assert _verdict(_judge(tmp_path, ab.zip_bytes(items), **ab.authorities())) == ("contradicted", "package_shape")


def test_receipt_field_of_another_type_disagrees(tmp_path: Path) -> None:
    import json
    items = ab.entries(sign_receipt=False)
    receipt = json.loads(items["overt_receipt.json"])
    receipt["policy"]["decision"] = ["deny"]
    items["overt_receipt.json"] = json.dumps(receipt).encode()
    assert _verdict(_judge(tmp_path, ab.zip_bytes(items), **ab.authorities())) == ("contradicted", "receipt")


def test_receipt_signature_present_but_unnamed_is_still_verified(tmp_path: Path) -> None:
    items = ab.entries(sign_receipt=False)
    items["overt_receipt.sig"] = base64.b64encode(b"\x00" * 256)
    assert _verdict(_judge(tmp_path, ab.zip_bytes(items), **ab.authorities())) == ("contradicted", "receipt")


def test_rsa_modulus_under_2048_bits_is_refused(tmp_path: Path) -> None:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    items = ab.entries(sign_receipt=False)
    items["signature.sig"] = base64.b64encode(weak.sign(items["canonical.bin"], padding.PKCS1v15(), hashes.SHA256()))
    items["public_key.pem"] = ab.spki_pem(weak.public_key())
    result = _judge(tmp_path, ab.zip_bytes(items), authority=ab.pin(ab.spki(weak.public_key())),
                    tsa_authority=ab.authorities()["tsa_authority"])
    assert _verdict(result) == ("contradicted", "rsa_signature")


# --- time-stamp tokens that verify cryptographically and are not time-stamps -----------------------

def _token(imprint: bytes, *, econtent: str = ap.TST_INFO_OID, content_type: str | None = ap.TST_INFO_OID,
           unsigned: bool = False, outer: str = ap.SIGNED_DATA_OID) -> bytes:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    key, cert = ab.tsa()
    tst = ab.seq(ab.integer(1), ab.oid("1.3.6.1.4.1.99999.1"),
                 ab.seq(ab.seq(ab.oid(ap.SHA256_OID), ab.tlv(0x05, b"")), ab.octets(imprint)),
                 ab.integer(42), ab.tlv(0x18, b"20261115120000Z"))
    attrs = ab.seq(ab.oid(ap.MESSAGE_DIGEST_OID), ab.tlv(0x31, ab.octets(hashlib.sha256(tst).digest())))
    if content_type is not None:
        attrs = ab.seq(ab.oid(ap.CONTENT_TYPE_OID), ab.tlv(0x31, ab.oid(content_type))) + attrs
    signature = key.sign(ab.tlv(0x31, attrs), ec.ECDSA(hashes.SHA256()))
    tail = ab.tlv(0xA1, ab.seq(ab.oid("1.2.840.113549.1.9.16.2.14"), ab.tlv(0x31, ab.seq(ab.integer(1))))) \
        if unsigned else b""
    signer_info = ab.seq(ab.integer(1), ab.seq(cert.issuer.public_bytes(), ab.integer(cert.serial_number)),
                         ab.seq(ab.oid(ap.SHA256_OID)), ab.tlv(0xA0, attrs), ab.seq(ab.oid("1.2.840.10045.4.3.2")),
                         ab.octets(signature), tail)
    signed_data = ab.seq(ab.integer(3), ab.tlv(0x31, ab.seq(ab.oid(ap.SHA256_OID))),
                         ab.seq(ab.oid(econtent), ab.tlv(0xA0, ab.octets(tst))),
                         ab.tlv(0xA0, cert.public_bytes(serialization.Encoding.DER)), ab.tlv(0x31, signer_info))
    return base64.b64encode(ab.seq(ab.seq(ab.integer(0)), ab.seq(ab.oid(outer), ab.tlv(0xA0, signed_data))))


def _with_token(**kwargs: Any) -> bytes:
    items = ab.entries()
    items["timestamp.tsr"] = _token(hashlib.sha256(items["canonical.bin"]).digest(), **kwargs)
    return ab.zip_bytes(items)


def test_hand_built_token_control_verifies(tmp_path: Path) -> None:
    assert _verdict(_judge(tmp_path, _with_token(), **ab.authorities())) == ("supported", "package_verifies")


def test_token_with_unsigned_attributes_still_verifies(tmp_path: Path) -> None:
    """The signature is the element after the signature algorithm, not the last element of SignerInfo."""
    assert _verdict(_judge(tmp_path, _with_token(unsigned=True), **ab.authorities())) == ("supported", "package_verifies")


@pytest.mark.parametrize("kwargs", [{"econtent": "1.2.840.113549.1.7.1", "content_type": "1.2.840.113549.1.7.1"},
                                    {"econtent": "1.2.840.113549.1.7.1"}, {"content_type": "1.2.840.113549.1.7.1"},
                                    {"content_type": None}, {"outer": "1.2.840.113549.1.7.3"}])
def test_tsa_key_signing_something_other_than_a_tstinfo_is_refused(tmp_path: Path, kwargs: dict) -> None:
    assert _verdict(_judge(tmp_path, _with_token(**kwargs), **ab.authorities())) == ("contradicted", "timestamp")
