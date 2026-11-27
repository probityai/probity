"""The one judge, the one signer policy and the one card reader of agent-evidence-a2a.

:func:`judge_signature` decides each member of a card's ``signatures`` array (CARD-SIGN-001 to
-004), :func:`settle_signatures` applies the card's signer policy to those judgements, and
:func:`read_signed_card` decides what a card with nothing to judge means.  A verifier built on the
package (the a2a-tck, a product's compliance gate) calls the same three functions, so the cases
below fix the verdicts every such verifier reaches.
"""

from __future__ import annotations

import base64
import json
import warnings
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import pytest
import rfc8785
from agent_evidence_a2a import (
    DEFAULT_ALGORITHMS,
    MAX_CARD_BYTES,
    MAX_HEADER_BYTES,
    REFERENCE_SIGNER_FORM,
    SignedCard,
    TrustedKey,
    TrustStore,
    UnreadableCard,
    judge_signature,
    non_jcs_forms,
    read_signed_card,
    settle_signatures,
    signed_parts,
    verify_detached,
    verify_served_card,
)
from joserfc import jws
from joserfc.jwk import ECKey, OKPKey

NOW = datetime(2026, 9, 28, tzinfo=UTC)
KEY = ECKey.generate_key("P-256")
OLD = ECKey.generate_key("P-256")


def _card() -> dict[str, Any]:
    return {
        "name": "Atlas",
        "description": "Answers questions about the café menu.",
        "version": "1.0.0",
        "supportedInterfaces": [
            {"url": "https://agent.example.com/a2a", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}
        ],
        "capabilities": {"streaming": True},
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "skills": [{"id": "s1", "name": "Ask", "description": "Ask things", "tags": ["qa"]}],
    }


def _payload(card: dict[str, Any]) -> bytes:
    return rfc8785.dumps({k: v for k, v in card.items() if k != "signatures"})


def _jws(payload: bytes, key: Any, header: dict[str, Any]) -> dict[str, str]:
    out = cast("dict[str, Any]", jws.serialize_json({"protected": header}, payload, key, algorithms=[header["alg"]]))
    return {"protected": out["protected"], "signature": out["signature"]}


def _lenient_jws(payload: bytes, key: Any, header: dict[str, Any]) -> dict[str, str]:
    """A detached JWS over a header joserfc's default registry would refuse to write (long, or unregistered)."""
    registry = jws.JWSRegistry(algorithms=[header["alg"]], strict_check_header=False)
    registry.max_header_length = 1 << 20
    out = cast("dict[str, Any]", jws.serialize_json({"protected": header}, payload, key, registry=registry))
    return {"protected": out["protected"], "signature": out["signature"]}


def _raw_es256(payload: bytes, header: dict[str, Any]) -> dict[str, str]:
    """An ES256 signature by KEY over a header joserfc refuses to write (a non-string ``kid``, a bad ``jku``)."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    protected = b64(json.dumps(header, separators=(",", ":")).encode())
    signing_input = f"{protected}.{b64(payload)}".encode()
    r, s = decode_dss_signature(cast("Any", KEY.private_key).sign(signing_input, ec.ECDSA(hashes.SHA256())))
    return {"protected": protected, "signature": b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))}


def _store(keys: dict[str, tuple[Any, datetime | None]]) -> TrustStore:
    return TrustStore({kid: TrustedKey(key=k, not_after=end) for kid, (k, end) in keys.items()})


def _verdict(served: str, keys: dict[str, tuple[Any, datetime | None]], **policy: Any) -> list[tuple[str, str]]:
    """The sorted (check id, severity) pairs :func:`verify_served_card` reports for *served*."""
    return sorted((f.check_id, f.severity) for f in verify_served_card(served, _store(keys), now=NOW, **policy).findings)


def _messages(served: str, keys: dict[str, Any], **policy: Any) -> list[tuple[str, str, str]]:
    verdict = verify_served_card(served, _store(keys), now=NOW, **policy)
    return [(f.check_id, f.severity, f.message) for f in verdict.findings]


class TestEachSignature:
    def test_a_kid_that_is_not_a_string_is_structural(self) -> None:
        card = _card()
        card["signatures"] = [_raw_es256(_payload(card), {"alg": "ES256", "kid": 7})]
        assert _verdict(json.dumps(card), {"k1": (KEY, None)}) == [("CARD-SIGN-003", "error")]

    def test_an_expired_signer_beside_a_verifying_one_is_rotation(self) -> None:
        card = _card()
        payload = _payload(card)
        card["signatures"] = [
            _jws(payload, OLD, {"alg": "ES256", "kid": "k0"}),
            _jws(payload, KEY, {"alg": "ES256", "kid": "k1"}),
        ]
        keys = {"k0": (OLD, NOW - timedelta(days=1)), "k1": (KEY, None)}
        assert _verdict(json.dumps(card), keys) == [("CARD-SIGN-004", "info")]
        assert verify_served_card(json.dumps(card), _store(keys), now=NOW).accepted

    def test_an_expired_signer_alone_fails(self) -> None:
        card = _card()
        card["signatures"] = [_jws(_payload(card), OLD, {"alg": "ES256", "kid": "k0"})]
        assert _verdict(json.dumps(card), {"k0": (OLD, NOW - timedelta(days=1))}) == [("CARD-SIGN-004", "error")]

    def test_a_reference_signer_form_is_named(self) -> None:
        card = _card()
        served_unsigned = json.dumps(card)
        form = dict(non_jcs_forms(served_unsigned))[REFERENCE_SIGNER_FORM]
        assert form != signed_parts(served_unsigned).payload, "the card must tell the two forms apart"
        card["signatures"] = [_jws(form, KEY, {"alg": "ES256", "kid": "k1"})]
        findings = _messages(json.dumps(card), {"k1": (KEY, None)})
        assert [(c, s) for c, s, _ in findings] == [("CARD-SIGN-001", "error")]
        assert REFERENCE_SIGNER_FORM in findings[0][2]

    def test_a_bad_signature_is_card_sign_002(self) -> None:
        card = _card()
        card["signatures"] = [_jws(b"{}", KEY, {"alg": "ES256", "kid": "k1"})]
        assert _verdict(json.dumps(card), {"k1": (KEY, None)}) == [("CARD-SIGN-002", "error")]

    def test_a_padded_protected_header_is_structural(self) -> None:
        card = _card()
        sig = _jws(_payload(card), KEY, {"alg": "ES256", "kid": "k1"})
        sig["protected"] = base64.urlsafe_b64encode(base64.urlsafe_b64decode(sig["protected"] + "==")).decode()
        if "=" not in sig["protected"]:
            sig["protected"] += "="
        card["signatures"] = [sig]
        assert _verdict(json.dumps(card), {"k1": (KEY, None)}) == [("CARD-SIGN-003", "error")]

    @pytest.mark.parametrize("alg", ["PS384", "PS512", "Ed25519", "Ed448", "EdDSA"])
    def test_every_registered_asymmetric_algorithm_is_accepted(self, alg: str) -> None:
        assert alg in DEFAULT_ALGORITHMS

    def test_symmetric_and_none_algorithms_are_not_accepted(self) -> None:
        assert not {"none", "HS256", "HS384", "HS512"} & set(DEFAULT_ALGORITHMS)

    def test_an_ed25519_signature_verifies(self) -> None:
        key = OKPKey.generate_key("Ed25519")
        card = _card()
        card["signatures"] = [_jws(_payload(card), key, {"alg": "Ed25519", "kid": "k1"})]
        assert _verdict(json.dumps(card), {"k1": (key, None)}) == []

    def test_an_eddsa_signature_verifies_without_a_deprecation_warning(self) -> None:
        key = OKPKey.generate_key("Ed25519")
        card = _card()
        with warnings.catch_warnings():
            # Signing with the name is the producer's choice under test, so its own warning is not.
            warnings.filterwarnings("ignore", message="EdDSA is deprecated")
            card["signatures"] = [_jws(_payload(card), key, {"alg": "EdDSA", "kid": "k1"})]
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            verdict = verify_served_card(json.dumps(card), TrustStore({"k1": TrustedKey(key=key)}), now=NOW)
        assert verdict.accepted
        assert verdict.verified_kids == {"k1"}

    def test_an_eddsa_verify_leaves_the_global_warning_filters_alone(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """``warnings.catch_warnings`` swaps a process-global list and is not thread-safe on Python 3.12."""
        key = OKPKey.generate_key("Ed25519")
        card = _card()
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", message="EdDSA is deprecated")
            card["signatures"] = [_jws(_payload(card), key, {"alg": "EdDSA", "kid": "k1"})]
        calls: list[str] = []
        real = warnings.catch_warnings

        def _spy(*args: Any, **kwargs: Any) -> warnings.catch_warnings[Any]:
            calls.append("catch_warnings")
            return real(*args, **kwargs)

        # Scoped so the real function is back before any assertion: pytest's own failure report calls it.
        with monkeypatch.context() as scoped:
            scoped.setattr(warnings, "catch_warnings", _spy)
            found = _verdict(json.dumps(card), {"k1": (key, None)})
        assert calls == [], "a signature verify touched the process-wide warning filters"
        assert found == []


class TestTheJudgeAlone:
    def test_no_lookup_leaves_a_sound_signature_unanchored(self) -> None:
        payload = _payload(_card())
        judged = judge_signature(
            _jws(payload, KEY, {"alg": "ES256", "kid": "k1"}), index=0, payload=payload, lookup=None, now=NOW
        )
        assert judged.finding is None
        assert judged.unanchored
        assert judged.verified_kid is None

    def test_no_lookup_still_runs_the_structural_checks(self) -> None:
        judged = judge_signature({"protected": 1}, index=2, payload=b"{}", lookup=None, now=NOW)
        assert judged.finding is not None
        assert judged.finding.check_id == "CARD-SIGN-003"
        assert judged.finding.signature_index == 2
        assert not judged.unanchored

    def test_an_uncomparable_validity_window_is_an_error_not_rotation(self) -> None:
        payload = _payload(_card())
        naive = TrustedKey(key=KEY, not_after=datetime(2099, 1, 1))
        judged = judge_signature(
            _jws(payload, KEY, {"alg": "ES256", "kid": "k1"}), index=0, payload=payload, lookup={"k1": naive}.get, now=NOW
        )
        assert judged.finding is not None
        assert judged.finding.check_id == "CARD-SIGN-004"
        assert not judged.key_status

    def test_an_unknown_kid_is_a_key_status(self) -> None:
        payload = _payload(_card())
        judged = judge_signature(
            _jws(payload, KEY, {"alg": "ES256", "kid": "k9"}), index=0, payload=payload, lookup={}.get, now=NOW
        )
        assert judged.finding is not None
        assert judged.finding.check_id == "CARD-SIGN-004"
        assert judged.key_status

    def test_a_verifying_signature_names_its_kid(self) -> None:
        payload = _payload(_card())
        judged = judge_signature(
            _jws(payload, KEY, {"alg": "ES256", "kid": "k1"}),
            index=0,
            payload=payload,
            lookup={"k1": TrustedKey(key=KEY)}.get,
            now=NOW,
        )
        assert judged.finding is None
        assert judged.verified_kid == "k1"

    @pytest.mark.parametrize(
        "header",
        [
            {"alg": "ES256", "kid": 7},
            {"alg": "ES256", "kid": "k1", "jku": "not a url"},
            {"alg": "ES256", "kid": "k1", "crit": ["exp"]},
            {"alg": "HS256", "kid": "k1"},
            {"alg": "ES256"},
        ],
        ids=["kid-not-a-string", "jku-not-a-url", "crit", "symmetric-alg", "no-kid"],
    )
    def test_a_malformed_header_is_structural_with_or_without_keys(self, header: dict[str, Any]) -> None:
        payload = _payload(_card())
        sig = _raw_es256(payload, header)
        for lookup in (None, {"k1": TrustedKey(key=KEY)}.get):
            judged = judge_signature(sig, index=0, payload=payload, lookup=lookup, now=NOW)
            assert judged.finding is not None
            assert judged.finding.check_id == "CARD-SIGN-003"


class TestNoSizeOrHeaderRefusalReadsAsABadSignature:
    """joserfc's default caps (header 512 bytes, payload 128,000, signature 1,024) and its strict
    header check would make a correctly signed card read as CARD-SIGN-002."""

    def test_a_card_past_joserfcs_payload_cap_verifies(self) -> None:
        card = _card()
        card["description"] = "d" * 100_000
        card["signatures"] = [_jws(_payload(card), KEY, {"alg": "ES256", "kid": "k1"})]
        assert _verdict(json.dumps(card), {"k1": (KEY, None)}) == []

    def test_a_protected_header_past_512_bytes_verifies(self) -> None:
        card = _card()
        header = {"alg": "ES256", "kid": "k1", "jku": "https://agent.example.com/keys/" + "a" * 700}
        card["signatures"] = [_lenient_jws(_payload(card), KEY, header)]
        assert len(card["signatures"][0]["protected"]) > 512
        assert _verdict(json.dumps(card), {"k1": (KEY, None)}) == []

    def test_an_x5c_chain_in_the_header_verifies(self) -> None:
        card = _card()
        header = {"alg": "ES256", "kid": "k1", "x5c": ["MIIB" + "A" * 1200, "MIIB" + "B" * 1200]}
        card["signatures"] = [_lenient_jws(_payload(card), KEY, header)]
        assert _verdict(json.dumps(card), {"k1": (KEY, None)}) == []

    def test_an_unregistered_header_parameter_is_ignored(self) -> None:
        """RFC 7515 section 4: a parameter the verifier does not understand is ignored unless crit names it."""
        card = _card()
        card["signatures"] = [_lenient_jws(_payload(card), KEY, {"alg": "ES256", "kid": "k1", "x-key-note": "k"})]
        assert _verdict(json.dumps(card), {"k1": (KEY, None)}) == []

    def test_a_header_past_the_bound_is_structural_and_one_at_it_verifies(self) -> None:
        payload = _payload(_card())
        base = {"alg": "ES256", "kid": "k1", "x-pad": ""}
        filler = MAX_HEADER_BYTES - len(json.dumps(base, separators=(",", ":")).encode())
        at_bound = _lenient_jws(payload, KEY, {**base, "x-pad": "a" * filler})
        past_bound = _lenient_jws(payload, KEY, {**base, "x-pad": "a" * (filler + 1)})
        lookup = {"k1": TrustedKey(key=KEY)}.get
        assert judge_signature(at_bound, index=0, payload=payload, lookup=lookup, now=NOW).verified_kid == "k1"
        judged = judge_signature(past_bound, index=0, payload=payload, lookup=lookup, now=NOW)
        assert judged.finding is not None
        assert judged.finding.check_id == "CARD-SIGN-003"
        assert str(MAX_HEADER_BYTES) in judged.finding.message

    def test_a_signature_value_longer_than_a_served_card_is_structural(self) -> None:
        payload = _payload(_card())
        sig = _jws(payload, KEY, {"alg": "ES256", "kid": "k1"})
        sig["signature"] = "A" * (MAX_CARD_BYTES + 1)
        judged = judge_signature(sig, index=0, payload=payload, lookup={"k1": TrustedKey(key=KEY)}.get, now=NOW)
        assert judged.finding is not None
        assert judged.finding.check_id == "CARD-SIGN-003"
        assert str(MAX_CARD_BYTES) in judged.finding.message


class TestAHeaderTheVerifierRefusesIsNotABadSignature:
    """joserfc refuses some protected headers while verifying (RFC 7797 ``b64``, a missing ``crit``).
    A refusal of the header says nothing about the signature, so it is CARD-SIGN-003, never 002."""

    @pytest.mark.parametrize(
        "b64", [False, "true", 0, None, "false"], ids=["false", "string-true", "zero", "null", "string-false"]
    )
    def test_a_b64_value_other_than_true_is_structural(self, b64: object) -> None:
        card = _card()
        card["signatures"] = [_raw_es256(_payload(card), {"alg": "ES256", "kid": "k1", "b64": b64})]
        assert _verdict(json.dumps(card), {"k1": (KEY, None)}) == [("CARD-SIGN-003", "error")]

    def test_b64_false_with_crit_is_structural_too(self) -> None:
        card = _card()
        card["signatures"] = [_raw_es256(_payload(card), {"alg": "ES256", "kid": "k1", "b64": False, "crit": ["b64"]})]
        assert _verdict(json.dumps(card), {"k1": (KEY, None)}) == [("CARD-SIGN-003", "error")]

    def test_an_explicit_b64_true_still_verifies(self) -> None:
        card = _card()
        card["signatures"] = [_raw_es256(_payload(card), {"alg": "ES256", "kid": "k1", "b64": True})]
        assert _verdict(json.dumps(card), {"k1": (KEY, None)}) == []

    @pytest.mark.parametrize(
        "refusal",
        ["MissingCritHeaderError", "DecodeError", "InvalidHeaderValueError", "UnsupportedHeaderError", "ExceededSizeError"],
    )
    def test_a_header_refusal_from_joserfc_is_structural_whatever_the_cause(
        self, refusal: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from joserfc import errors

        def refuse(*_args: object, **_kwargs: object) -> None:
            raise getattr(errors, refusal)("the header is refused")

        monkeypatch.setattr(jws, "deserialize_compact", refuse)
        card = _card()
        card["signatures"] = [_jws(_payload(card), KEY, {"alg": "ES256", "kid": "k1"})]
        assert _verdict(json.dumps(card), {"k1": (KEY, None)}) == [("CARD-SIGN-003", "error")]

    @pytest.mark.parametrize("refusal", ["BadSignatureError", "InvalidKeyTypeError", "InvalidKeyLengthError"])
    def test_a_bad_signature_or_an_unusable_key_still_reads_as_does_not_verify(
        self, refusal: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from joserfc import errors

        def refuse(*_args: object, **_kwargs: object) -> None:
            raise getattr(errors, refusal)()

        monkeypatch.setattr(jws, "deserialize_compact", refuse)
        card = _card()
        card["signatures"] = [_jws(_payload(card), KEY, {"alg": "ES256", "kid": "k1"})]
        assert _verdict(json.dumps(card), {"k1": (KEY, None)}) == [("CARD-SIGN-002", "error")]

    def test_verify_detached_never_raises_on_a_refused_header(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from joserfc import errors

        def refuse(*_args: object, **_kwargs: object) -> None:
            raise errors.MissingCritHeaderError("b64")

        monkeypatch.setattr(jws, "deserialize_compact", refuse)
        sig = _jws(_payload(_card()), KEY, {"alg": "ES256", "kid": "k1"})
        assert verify_detached(sig["protected"], sig["signature"], b"x", KEY) is False

    def test_verify_detached_accepts_a_good_signature_and_refuses_another_payload(self) -> None:
        payload = _payload(_card())
        sig = _jws(payload, KEY, {"alg": "ES256", "kid": "k1"})
        assert verify_detached(sig["protected"], sig["signature"], payload, KEY) is True
        assert verify_detached(sig["protected"], sig["signature"], payload + b" ", KEY) is False
        assert verify_detached(sig["protected"], sig["signature"], payload, KEY, algorithms=("RS256",)) is False


class TestOneSignerPolicy:
    def test_a_required_signer_that_did_not_sign_is_named(self) -> None:
        card = _card()
        card["signatures"] = [_jws(_payload(card), KEY, {"alg": "ES256", "kid": "k1"})]
        keys = {"k1": (KEY, None), "k2": (OLD, None)}
        expected = "required signer(s) did not contribute a verifying signature: 'k2'"
        assert _messages(json.dumps(card), keys, required_kids=frozenset({"k2"})) == [
            ("CARD-SIGN-004", "error", expected)
        ]

    def test_a_threshold_shortfall_beside_a_verifying_signer_is_named(self) -> None:
        card = _card()
        card["signatures"] = [_jws(_payload(card), KEY, {"alg": "ES256", "kid": "k1"})]
        expected = "only 1 distinct signer kid(s) verified; the policy needs 2"
        assert _messages(json.dumps(card), {"k1": (KEY, None)}, threshold=2) == [("CARD-SIGN-004", "error", expected)]

    def test_rotation_with_the_policy_unmet_fails(self) -> None:
        card = _card()
        payload = _payload(card)
        card["signatures"] = [
            _jws(payload, OLD, {"alg": "ES256", "kid": "k0"}),
            _jws(payload, KEY, {"alg": "ES256", "kid": "k1"}),
        ]
        keys = {"k0": (OLD, NOW - timedelta(days=1)), "k1": (KEY, None)}
        found = _messages(json.dumps(card), keys, threshold=2)
        assert [(c, s) for c, s, _ in found] == [("CARD-SIGN-004", "error"), ("CARD-SIGN-004", "error")]

    def test_two_signatures_by_one_kid_count_once(self) -> None:
        card = _card()
        card["signatures"] = [_jws(_payload(card), KEY, {"alg": "ES256", "kid": "k1"})] * 2
        expected = "only 1 distinct signer kid(s) verified; the policy needs 2"
        assert _messages(json.dumps(card), {"k1": (KEY, None)}, threshold=2) == [("CARD-SIGN-004", "error", expected)]

    def test_a_threshold_below_one_is_refused(self) -> None:
        card = _card()
        card["signatures"] = [_jws(_payload(card), KEY, {"alg": "ES256", "kid": "k1"})]
        with pytest.raises(ValueError, match="at least 1"):
            verify_served_card(json.dumps(card), TrustStore({"k1": TrustedKey(key=KEY)}), now=NOW, threshold=0)

    def test_an_unanchored_judgement_has_no_policy_to_settle(self) -> None:
        payload = _payload(_card())
        judged = judge_signature(
            _jws(payload, KEY, {"alg": "ES256", "kid": "k1"}), index=0, payload=payload, lookup=None, now=NOW
        )
        with pytest.raises(ValueError, match="no trust store"):
            settle_signatures([judged])

    def test_a_lone_key_finding_fails_the_card_when_nothing_verifies(self) -> None:
        """Key rotation needs a signer that verified; with none, an unknown kid is the failure."""
        card = _card()
        card["signatures"] = [_jws(_payload(card), OLD, {"alg": "ES256", "kid": "k-gone"})]
        assert _verdict(json.dumps(card), {"k1": (KEY, None)}) == [("CARD-SIGN-004", "error")]
        assert not verify_served_card(json.dumps(card), _store({"k1": (KEY, None)}), now=NOW).accepted

    def test_no_judgement_at_all_is_a_shortfall_with_a_reason(self) -> None:
        verdict = settle_signatures([])
        assert not verdict.accepted
        assert [f.message for f in verdict.findings] == ["only 0 distinct signer kid(s) verified; the policy needs 1"]


class TestOneCardReader:
    @pytest.mark.parametrize(
        "member",
        [{}, {"protected": "x", "signature": "y"}, "x", 7, True],
        ids=["empty-object", "one-jws-object", "string", "number", "boolean"],
    )
    def test_a_signatures_member_that_is_not_an_array_is_named_as_such(self, member: object) -> None:
        card = _card()
        card["signatures"] = member
        read = read_signed_card(json.dumps(card))
        assert isinstance(read, UnreadableCard)
        assert read.kind == "malformed"
        found = _messages(json.dumps(card), {"k1": (KEY, None)})
        assert [(c, s) for c, s, _ in found] == [("CARD-SIGN-003", "error")]
        assert "is not an array" in found[0][2]
        assert "carries no signatures" not in found[0][2]

    def test_a_card_with_no_rfc_8785_form_is_card_sign_001(self) -> None:
        served = json.dumps({**_card(), "version": 2**60 + 1})
        read = read_signed_card(served)
        assert isinstance(read, UnreadableCard)
        assert read.kind == "uncanonicalizable"
        found = _messages(served, {"k1": (KEY, None)})
        assert [(c, s) for c, s, _ in found] == [("CARD-SIGN-001", "error")]
        assert "no RFC 8785 canonical form" in found[0][2]

    @pytest.mark.parametrize("member", [None, []], ids=["null", "empty-array"])
    def test_an_unsigned_card_is_one_kind_and_not_accepted(self, member: object) -> None:
        card = _card()
        card["signatures"] = member
        served = json.dumps(card)
        for text in (served, json.dumps(_card())):
            read = read_signed_card(text)
            assert isinstance(read, UnreadableCard)
            assert read.kind == "unsigned"
        assert not verify_served_card(served, TrustStore({"k1": TrustedKey(key=KEY)}), now=NOW).accepted

    def test_the_reader_hands_back_the_payload_the_signatures_are_judged_against(self) -> None:
        card = _card()
        card["signatures"] = [_jws(_payload(card), KEY, {"alg": "ES256", "kid": "k1"})]
        read = read_signed_card(json.dumps(card))
        assert isinstance(read, SignedCard)
        assert read.payload == _payload(card)
        assert list(read.signatures) == card["signatures"]
        assert all(form != read.payload for _, form in read.alternatives)

    def test_a_member_appended_after_signing_fails(self) -> None:
        card = _card()
        card["signatures"] = [_jws(_payload(card), KEY, {"alg": "ES256", "kid": "k1"})]
        card["x-appended"] = "after signing"
        assert _verdict(json.dumps(card), {"k1": (KEY, None)}) == [("CARD-SIGN-002", "error")]
