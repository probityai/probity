"""Received text that is not ASCII, or is a lone surrogate, is a refusal and never an exception.

Round r6d found two verifiers that ran ``str.encode("ascii")`` on received text before reading it. The class is every
place a verifier encodes, hashes or compares a ``str`` it was handed: ``encode`` raises on a lone surrogate, and
``hmac.compare_digest`` raises ``TypeError`` for a ``str`` outside ASCII. Each test below feeds one such place text it
must refuse. The segment cases pin the other half of the class: one token has one spelling, so a segment that is not
the canonical unpadded base64url of its bytes is malformed in every reader.
"""

from __future__ import annotations

import hashlib
from typing import Any

import pytest
from probity_records import witness as w
from probity_records.core import is_utf8_text, open_envelope, same_text
from probity_records.identity import b64url, unb64url, verify_token
from probity_records.identity_vectors import base
from probity_records.possession import CONTENT_DIGEST_CLAIM, check_dpop, possession_record_problem
from probity_records.receipt_map import MapError, check_key

TEXTS = ["é", "\ud800", "ÿ", "\U0001f600", "x\x00y"]
URL = "https://gw.example.com/x"
AT = "2026-11-27T00:00:00Z"
HEAD = b64url(b'{"alg":"EdDSA","typ":"dpop+jwt","jwk":{"kty":"OKP","crv":"Ed25519","x":"' + b"A" * 43 + b'"}}')


def _dpop(proof: str, access_token: Any = None) -> tuple[Any, str]:
    return check_dpop(proof, "POST", URL, AT, expected_jkt="jkt", access_token=access_token)


@pytest.mark.parametrize("text", TEXTS[:4])
@pytest.mark.parametrize("where", ["head", "claims", "signature"])
def test_a_dpop_proof_with_text_outside_ascii_in_any_segment_is_malformed(text: str, where: str) -> None:
    parts = {"head": HEAD, "claims": "e30", "signature": "AA"}
    parts[where] += text
    proof = f"{parts['head']}.{parts['claims']}.{parts['signature']}"
    assert _dpop(proof) == (None, "dpop_malformed")


def test_a_dpop_proof_past_the_size_bound_with_text_outside_ascii_is_malformed_in_both_readers() -> None:
    assert _dpop("é" * 9000) == (None, "dpop_malformed")


@pytest.mark.parametrize("text", TEXTS[:4])
def test_an_access_token_that_is_not_ascii_is_a_mismatch_not_a_raise(text: str) -> None:
    from probity_records.possession import _claims_problem

    claims = {"htm": "POST", "htu": URL, "iat": 1, "jti": "j", "ath": "x"}
    assert _claims_problem(claims, "POST", URL, 1, 60, text, b"", False) == "dpop_ath_mismatch"
    assert _claims_problem(claims, "POST", URL, 1, 60, 5, b"", False) == "dpop_ath_mismatch"


@pytest.mark.parametrize("value", ["é", "\ud800", 5, None, ["a"]])
def test_a_claim_compared_with_a_digest_is_a_mismatch_not_a_raise(value: Any) -> None:
    from probity_records.possession import _claims_problem

    base_claims = {"htm": "POST", "htu": URL, "iat": 1, "jti": "j"}
    assert _claims_problem({**base_claims, "ath": value}, "POST", URL, 1, 60, "tok", b"", False) == "dpop_ath_mismatch"
    if value is not None:  # an absent digest is "unbound", not a mismatch
        got = _claims_problem({**base_claims, CONTENT_DIGEST_CLAIM: value}, "POST", URL, 1, 60, None, b"", False)
        assert got == "dpop_content_mismatch"


@pytest.mark.parametrize("jti", ["\ud800" * 100, "", 7])
def test_a_jti_that_is_not_a_bounded_string_is_refused_not_raised(jti: Any) -> None:
    from probity_records.possession import _claims_problem

    claims = {"htm": "POST", "htu": URL, "iat": 1, "jti": jti}
    assert _claims_problem(claims, "POST", URL, 1, 60, None, b"", False) == "dpop_jti_invalid"
    record = {"method": "dpop", "iat": 1, "jkt": "k", "jti": jti}
    assert isinstance(possession_record_problem(record, {"jkt": "é"}), str)


@pytest.mark.parametrize("suffix", TEXTS)
def test_an_escrowed_token_that_is_not_ascii_is_token_malformed(suffix: str) -> None:
    v = base()
    token = v["tokens"]["user"] + suffix
    principal = {**v["principals"]["user"], "tokenDigest": hashlib.sha256(token.encode("utf-8", "surrogatepass")).hexdigest()}
    assert verify_token(principal, token, v["jwks"]) == "token_malformed"


def test_a_token_that_is_not_a_string_is_token_malformed() -> None:
    v = base()
    assert verify_token(v["principals"]["user"], 5, v["jwks"]) == "token_malformed"  # type: ignore[arg-type]


def _token_with(index: int, edit: Any) -> tuple[dict[str, Any], str, dict[str, Any]]:
    v = base()
    parts = v["tokens"]["user"].split(".")
    parts[index] = edit(parts[index])
    token = ".".join(parts)
    principal = {**v["principals"]["user"], "tokenDigest": hashlib.sha256(token.encode()).hexdigest()}
    return principal, token, v["jwks"]


@pytest.mark.parametrize("index", [0, 1, 2])
@pytest.mark.parametrize("edit", [lambda s: s[:4] + " " + s[4:], lambda s: s + "A", lambda s: s + "=", lambda s: s[:3] + "\n" + s[3:]])
def test_a_token_segment_that_is_not_canonical_base64url_is_token_malformed(index: int, edit: Any) -> None:
    principal, token, jwks = _token_with(index, edit)
    assert verify_token(principal, token, jwks) == "token_malformed"


@pytest.mark.parametrize("text", ["a b", "aaaaa", "aa==", "aé", "aa\n", "-_-", "Zh"])
def test_unb64url_reads_only_the_canonical_spelling(text: str) -> None:
    with pytest.raises(ValueError):
        unb64url(text)
    assert unb64url(b64url(b"abc")) == b"abc"


@pytest.mark.parametrize("permit", ["\ud800", "a\udfffb", "", "é" * 200, 5])
def test_a_permit_id_that_is_not_bounded_utf8_is_a_map_error(permit: Any) -> None:
    with pytest.raises(MapError):
        check_key(permit, "accept")


def test_an_envelope_payload_type_that_is_not_utf8_text_is_a_refusal() -> None:
    for kind in ("\ud800", 5, None):
        with pytest.raises(ValueError, match="envelope_shape"):
            open_envelope({"payload": "", "payloadType": kind, "signatures": [{"sig": ""}]}, [])


def test_same_text_never_raises() -> None:
    assert same_text("a", "a") and not same_text("é", "a") and not same_text("\ud800", "\ud800x")
    assert same_text("é", "é") and not same_text(1, 1) and not same_text(None, "a")
    assert is_utf8_text("é") and not is_utf8_text("\ud800") and not is_utf8_text(b"a")


@pytest.mark.parametrize("text", ["\ud800", "a\udfff"])
def test_a_note_checkpoint_or_policy_with_a_lone_surrogate_is_a_note_error(text: str) -> None:
    for parse in (w.parse_note, w.parse_checkpoint, w.parse_policy, w.parse_vkey):
        with pytest.raises(w.NoteError):
            parse(f"{text}\n\n")
    assert not w.valid_name(text)
