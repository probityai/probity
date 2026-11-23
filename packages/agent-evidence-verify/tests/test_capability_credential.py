"""capability_credential/v1 (reader R1): five positives and every negative class, each with its own code.

Credentials are built here from neutral, deterministic keys. The seven constructed classes are the ways a
lenient reader of signed JSON credentials grants or keeps what the signature never covered: a case-variant
privilege member, a case-variant revoked flag, a time written with an escape, with non-ASCII digits or with a
trailing line feed, and -0 signed in either direction. The distinct-authority classes are the ways a required
count of signers is met without independence.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from agent_evidence_verify import adjudicate
from agent_evidence_verify.adapters import capability_credential as cc
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def _key(name: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"capability-credential-test/" + name.encode()).digest())


def _hex(name: str) -> str:
    return _key(name).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def _sign(name: str, message: bytes) -> str:
    return base64.urlsafe_b64encode(_key(name).sign(message)).rstrip(b"=").decode()


BASE = {"schema_version": cc.SCHEMA, "id": "cred-1", "issuer": "issuer-a", "subject": "agent-7",
        "capabilities": ["db:read", "db:write"], "issued_at": "2026-11-01T00:00:00Z",
        "not_after": "2026-12-01T00:00:00Z"}
STATE = {"trusted_issuers": {"issuer-a": _hex("issuer-a")}, "at": "2026-11-15T12:00:00Z", "revoked": [],
         "cosigners": {"cos-1": {"public_key": _hex("cos-1"), "authority": "org-1"},
                       "cos-2": {"public_key": _hex("cos-2"), "authority": "org-2"},
                       "cos-3": {"public_key": _hex("cos-3"), "authority": "org-1"},
                       "cos-1-alias": {"public_key": _hex("cos-1"), "authority": "org-1"},
                       "issuer-alias": {"public_key": _hex("issuer-a"), "authority": "org-9"}}}


def build(body: dict | None = None, signers: tuple[str, ...] = ("issuer-a",), key_of: dict | None = None) -> dict:
    body = copy.deepcopy(body or BASE)
    message = cc.signing_input(body)
    key_of = key_of or {}
    body["signatures"] = [{"kid": kid, "value": _sign(key_of.get(kid, kid.removesuffix("-alias")), message)}
                          for kid in signers]
    return body


def _judge(tmp_path: Path, raw: bytes | dict, **state: Any) -> dict:
    data = raw if isinstance(raw, bytes) else json.dumps(raw).encode()
    (tmp_path / "credential.json").write_bytes(data)
    case = {"schema_version": "probity-case/v1", "case_id": "c", "artifacts": {"credential.json": {
        "path": "credential.json", "length": len(data), "sha256": hashlib.sha256(data).hexdigest()}}}
    policy = {"schema_version": "probity-policy/v1", "assessments": {"c": {
        "claim_type": "capability_credential/v1", "credential": "credential.json", **STATE, **state}}}
    return adjudicate(case, policy, tmp_path)


def _reason(tmp_path: Path, raw: bytes | dict, **state: Any) -> str:
    return _judge(tmp_path, raw, **state)["reason"]


POSITIVES = {
    "issuer-only": (build(), {}),
    "two-cosigners-two-authorities": (build({**BASE, "cosigners_required": 2}, ("issuer-a", "cos-1", "cos-2")), {}),
    "with-revocation-ref-and-use-limit": (build({**BASE, "revocation_ref": "list-1", "max_uses": 5}),
                                          {"revocation_sources": ["list-1"], "uses_recorded": 4}),
    "one-cosigner-required": (build({**BASE, "cosigners_required": 1}, ("issuer-a", "cos-2")), {}),
    "unused-single-use": (build({**BASE, "max_uses": 1}), {"uses_recorded": 0}),
}


@pytest.mark.parametrize("name", sorted(POSITIVES))
def test_positive_passes(tmp_path: Path, name: str) -> None:
    credential, state = POSITIVES[name]
    result = _judge(tmp_path, credential, **state)
    assert (result["decision"], result["reason"]) == ("supported", "credential_valid")


# --- state the credential names that the consumer never consulted ---------------------------------------

@pytest.mark.parametrize(("body", "state", "verdict"), [
    ({"revocation_ref": "list-1"}, {}, ("not_established", "revocation_not_checked")),
    ({"revocation_ref": "list-1"}, {"revocation_sources": ["list-2"]}, ("not_established", "revocation_not_checked")),
    ({"max_uses": 5}, {}, ("not_established", "use_count_unknown")),
    ({"max_uses": 0}, {}, ("not_established", "use_count_unknown")),
    ({"max_uses": 0}, {"uses_recorded": 0}, ("contradicted", "uses_exhausted")),
    ({"max_uses": 5}, {"uses_recorded": 5}, ("contradicted", "uses_exhausted")),
    ({"max_uses": 5, "revocation_ref": "list-1"}, {"uses_recorded": 9}, ("contradicted", "uses_exhausted")),
])
def test_unconsulted_revocation_list_or_use_count_is_never_valid(tmp_path: Path, body: dict, state: dict,
                                                                 verdict: tuple[str, str]) -> None:
    result = _judge(tmp_path, build({**BASE, **body}), **state)
    assert (result["decision"], result["reason"]) == verdict


@pytest.mark.parametrize("state", [{"trusted_issuers": {"issuer-a": "zz" * 32}}, {"at": "2026-13-45T00:00:00Z"},
                                   {"at": "2026-02-30T00:00:00Z"}, {"uses_recorded": -1}, {"uses_recorded": True},
                                   {"revocation_sources": "list-1"},
                                   {"cosigners": {"cos-1": {"public_key": _hex("cos-1"), "authority": ""}}}])
def test_malformed_consumer_state_is_a_case_error_not_a_verdict(tmp_path: Path, state: dict) -> None:
    from agent_evidence_verify import CaseError
    with pytest.raises(CaseError):
        _judge(tmp_path, build(), **state)


def _text(credential: dict) -> str:
    return json.dumps(credential)


# --- the seven constructed classes ---------------------------------------------------------------------

def _case_variant_capabilities() -> bytes:
    signed = build({**BASE, "capabilities": []})
    signed["Capabilities"] = ["system:exec"]
    return json.dumps(signed).encode()


def _case_variant_revoked() -> bytes:
    signed = build()
    signed["Revoked"] = True
    return json.dumps(signed).encode()


def _time_variant(raw_value: str) -> bytes:
    signed = build()
    return _text(signed).replace('"not_after": "2026-12-01T00:00:00Z"', f'"not_after": {raw_value}').encode()


def _negzero(signed_as: str) -> bytes:
    body = {**BASE, "max_uses": 0}
    message = cc.signing_input(body)
    if signed_as == "-0":
        message = message.replace(b'"max_uses":0', b'"max_uses":-0')
    body["signatures"] = [{"kid": "issuer-a", "value": _sign("issuer-a", message)}]
    return _text(body).replace('"max_uses": 0', '"max_uses": -0').encode()


SEVEN = {
    "case-variant-capabilities-alone": (_case_variant_capabilities, "unknown_member"),
    "case-variant-revoked-alone": (_case_variant_revoked, "unknown_member"),
    "time-with-escaped-z": (lambda: _time_variant('"2026-12-01T00:00:00\\u005a"'), "timestamp_grammar"),
    "time-with-fullwidth-year": (lambda: _time_variant('"２０２６-12-01T00:00:00Z"'), "timestamp_grammar"),
    "time-with-trailing-newline": (lambda: _time_variant('"2026-12-01T00:00:00Z\\n"'), "timestamp_grammar"),
    "negzero-signed-as-zero": (lambda: _negzero("0"), "noncanonical_number"),
    "negzero-signed-as-negzero": (lambda: _negzero("-0"), "noncanonical_number"),
}


@pytest.mark.parametrize("name", sorted(SEVEN))
def test_constructed_class_fails_closed_with_its_code(tmp_path: Path, name: str) -> None:
    make, code = SEVEN[name]
    result = _judge(tmp_path, make())
    assert (result["decision"], result["reason"]) == ("contradicted", code)


# --- tamper, time, revocation, trust ---------------------------------------------------------------------

def test_tamper_after_signing(tmp_path: Path) -> None:
    signed = build()
    signed["capabilities"] = ["db:read", "db:write", "system:exec"]
    assert _reason(tmp_path, signed) == "signature_invalid"


def test_expired_and_not_yet_valid(tmp_path: Path) -> None:
    (tmp_path / "e").mkdir()
    (tmp_path / "n").mkdir()
    assert _reason(tmp_path / "e", build(), at="2026-12-01T00:00:00Z") == "expired"
    assert _reason(tmp_path / "n", build(), at="2026-10-31T23:59:59Z") == "not_yet_valid"


def test_revoked_by_the_consumer_list_only(tmp_path: Path) -> None:
    assert _reason(tmp_path, build(), revoked=["cred-1"]) == "revoked"


def test_untrusted_issuer(tmp_path: Path) -> None:
    assert _reason(tmp_path, build(), trusted_issuers={"issuer-b": _hex("issuer-b")}) == "issuer_untrusted"


def test_issuer_signature_by_another_key(tmp_path: Path) -> None:
    assert _reason(tmp_path, build(key_of={"issuer-a": "intruder"})) == "signature_invalid"


def test_repeated_privilege_member_one_level_down(tmp_path: Path) -> None:
    raw = _text(build()).replace('"capabilities": ["db:read", "db:write"]',
                                 '"capabilities": ["db:read"], "capabilities": ["system:exec"]').encode()
    assert _reason(tmp_path, raw) == "duplicate_member"


def test_fraction_token_is_refused(tmp_path: Path) -> None:
    raw = _text(build({**BASE, "max_uses": 5})).replace('"max_uses": 5', '"max_uses": 5.0').encode()
    assert _reason(tmp_path, raw) == "noncanonical_number"


def test_a_flag_inside_a_signature_entry_is_refused(tmp_path: Path) -> None:
    signed = build()
    signed["signatures"][0]["revoked"] = False
    assert _reason(tmp_path, signed) == "unknown_member"


# --- distinct authorities ----------------------------------------------------------------------------

DISTINCT = {
    "key-named-but-not-signing": (build({**BASE, "cosigners_required": 2}, ("issuer-a", "cos-1", "cos-2"),
                                        key_of={"cos-2": "intruder"}), "key_named_not_signing"),
    "two-signatures-under-one-kid": (lambda: _two_under_one(), "key_named_not_signing"),
    "one-key-under-two-ids": (build({**BASE, "cosigners_required": 2}, ("issuer-a", "cos-1", "cos-1-alias")),
                              "one_key_two_ids"),
    "own-key-as-cosigner": (build({**BASE, "cosigners_required": 1}, ("issuer-a", "issuer-alias"),
                                  key_of={"issuer-alias": "issuer-a"}),
                            "own_key_as_cosigner"),
    "own-key-as-cosigner-above-count": (build({**BASE, "cosigners_required": 1}, ("issuer-a", "cos-2", "issuer-alias"),
                                              key_of={"issuer-alias": "issuer-a"}),
                                        "own_key_as_cosigner"),
    "threshold-keys-from-one-authority": (build({**BASE, "cosigners_required": 2}, ("issuer-a", "cos-1", "cos-3")),
                                          "one_authority_threshold"),
    "below-threshold": (build({**BASE, "cosigners_required": 2}, ("issuer-a", "cos-1")), "below_threshold"),
    "unknown-cosigner": (build({**BASE, "cosigners_required": 1}, ("issuer-a", "cos-x"),
                               key_of={"cos-x": "cos-x"}), "cosigner_untrusted"),
}


def _two_under_one() -> dict:
    signed = build({**BASE, "cosigners_required": 1}, ("issuer-a", "cos-1"))
    signed["signatures"].append(dict(signed["signatures"][1]))
    return signed


@pytest.mark.parametrize("name", sorted(DISTINCT))
def test_distinct_authority_class(tmp_path: Path, name: str) -> None:
    credential, code = DISTINCT[name]
    result = _judge(tmp_path, credential() if callable(credential) else credential)
    assert (result["decision"], result["reason"]) == ("contradicted", code)


def test_zero_required_count_is_refused(tmp_path: Path) -> None:
    assert _reason(tmp_path, build({**BASE, "cosigners_required": 0})) == "record_shape"


def test_every_negative_has_its_own_code() -> None:
    codes = {code for _, code in SEVEN.values()} | {code for _, code in DISTINCT.values()}
    assert codes >= {"unknown_member", "timestamp_grammar", "noncanonical_number", "key_named_not_signing",
                     "one_key_two_ids", "own_key_as_cosigner", "one_authority_threshold", "below_threshold"}
