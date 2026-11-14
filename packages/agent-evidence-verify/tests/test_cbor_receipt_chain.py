"""cbor_receipt_chain/v1: every way a stream of valid receipts can fail to be the stream that was written.

Streams are built with the neutral format profiles in receipt_chain_builder.py and judged through the
kernel, as a consumer calls it. Every stream below passes a signature-only check except where the
case says otherwise; the claim type is what refuses it.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
import receipt_chain_builder as rb
from agent_evidence_verify import adjudicate
from agent_evidence_verify.adapters import cbor_receipt_chain as adapter
from agent_evidence_verify.common import CaseError

KEY = rb.seed_key("signer")
OTHER = rb.seed_key("other")


def _sha(receipt: bytes) -> bytes:
    return hashlib.sha256(receipt).digest()


def _judge(tmp_path: Path, receipts: list[bytes] | bytes, profile: dict | None = None,
           signers: list[str] | None = None, **assessment: Any) -> dict:
    profile = profile or rb.NEUTRAL
    data = receipts if isinstance(receipts, bytes) else rb.stream(profile, receipts)
    raw_profile = json.dumps(profile).encode()
    (tmp_path / "chain.jsonl").write_bytes(data)
    (tmp_path / "profile.json").write_bytes(raw_profile)

    def bind(name: str, blob: bytes) -> dict:
        return {"path": name, "length": len(blob), "sha256": hashlib.sha256(blob).hexdigest()}

    case = {"schema_version": "probity-case/v1", "case_id": "chain", "artifacts": {
        "chain.jsonl": bind("chain.jsonl", data), "profile.json": bind("profile.json", raw_profile)}}
    policy = {"schema_version": "probity-policy/v1", "assessments": {"chain": {
        "claim_type": "cbor_receipt_chain/v1", "records": "chain.jsonl", "profile": "profile.json",
        "signer_keys": [rb.public_hex(KEY)] if signers is None else signers, **assessment}}}
    return adjudicate(case, policy, tmp_path)


def _verdict(result: dict) -> tuple[str, str]:
    return result["decision"], result["reason"]


def _base(count: int = 6) -> list[bytes]:
    return rb.chain(rb.NEUTRAL, KEY, count)


def test_intact_chain_with_head_is_supported(tmp_path: Path) -> None:
    receipts = _base()
    result = _judge(tmp_path, receipts, **rb.head(receipts))
    assert _verdict(result) == ("supported", "receipt_chain_holds")
    assert result["scope"]["receipts"] == 6
    assert {c["id"]: c["status"] for c in result["checks"]}["head_anchor"] == "pass"


def test_intact_chain_without_head_is_not_established(tmp_path: Path) -> None:
    result = _judge(tmp_path, _base())
    assert _verdict(result) == ("not_established", "head_not_anchored")
    assert [c["status"] for c in result["checks"] if c["id"] == "head_anchor"] == ["unavailable"]


def test_flipped_signature_byte_is_refused(tmp_path: Path) -> None:
    receipts = _base()
    receipts[3] = receipts[3][:-1] + bytes([receipts[3][-1] ^ 1])
    assert _verdict(_judge(tmp_path, receipts)) == ("contradicted", "signature")


def test_record_re_signed_under_an_unpinned_key_is_refused(tmp_path: Path) -> None:
    receipts = _base()
    receipts[3] = rb.receipt(rb.NEUTRAL, OTHER, _sha(receipts[2]), request="r3", outcome="allow")
    assert _verdict(_judge(tmp_path, receipts)) == ("contradicted", "signer_pinned")


def test_foreign_key_appending_its_own_chained_records_is_refused(tmp_path: Path) -> None:
    receipts = _base() + rb.chain(rb.NEUTRAL, OTHER, 3, first_prev=_sha(_base()[-1]))
    assert _verdict(_judge(tmp_path, receipts)) == ("contradicted", "signer_pinned")


def test_embedded_key_alone_is_never_trust(tmp_path: Path) -> None:
    receipts = rb.chain(rb.NEUTRAL, OTHER, 4)
    assert _verdict(_judge(tmp_path, receipts)) == ("contradicted", "signer_pinned")
    pinned = _judge(tmp_path, receipts, signers=[rb.public_hex(OTHER)], **rb.head(receipts))
    assert _verdict(pinned) == ("supported", "receipt_chain_holds")


def test_duplicate_receipt_is_refused(tmp_path: Path) -> None:
    receipts = _base()
    receipts.insert(3, receipts[2])
    assert _verdict(_judge(tmp_path, receipts)) == ("contradicted", "no_duplicate_receipt")


def test_re_issued_authorization_is_refused(tmp_path: Path) -> None:
    receipts = _base()
    receipts.append(rb.receipt(rb.NEUTRAL, KEY, _sha(receipts[-1]), request="r0"))
    result = _judge(tmp_path, receipts, **rb.head(receipts))
    assert _verdict(result) == ("contradicted", "single_use")


def test_a_denied_request_may_repeat(tmp_path: Path) -> None:
    receipts = _base(3)
    receipts.append(rb.receipt(rb.NEUTRAL, KEY, _sha(receipts[-1]), request="r0", outcome="deny"))
    assert _verdict(_judge(tmp_path, receipts, **rb.head(receipts))) == ("supported", "receipt_chain_holds")


@pytest.mark.parametrize("drop", [0, 2, 4])
def test_dropped_head_or_middle_breaks_the_link(tmp_path: Path, drop: int) -> None:
    receipts = _base()
    del receipts[drop]
    assert _verdict(_judge(tmp_path, receipts)) == ("contradicted", "chain_order")


def test_swapped_receipts_break_the_link(tmp_path: Path) -> None:
    receipts = _base()
    receipts[2], receipts[3] = receipts[3], receipts[2]
    assert _verdict(_judge(tmp_path, receipts)) == ("contradicted", "chain_order")


def test_cut_tail_needs_the_pinned_head(tmp_path: Path) -> None:
    receipts = _base()
    pinned = rb.head(receipts)
    cut = receipts[:-1]
    assert _verdict(_judge(tmp_path, cut, **pinned)) == ("contradicted", "head_anchor")
    assert _verdict(_judge(tmp_path, cut)) == ("not_established", "head_not_anchored")


def test_first_receipt_must_link_to_the_pinned_predecessor(tmp_path: Path) -> None:
    anchor = hashlib.sha256(b"earlier run").digest()
    receipts = rb.chain(rb.NEUTRAL, KEY, 3, first_prev=anchor)
    held = _judge(tmp_path, receipts, first_prev=anchor.hex(), **rb.head(receipts))
    assert _verdict(held) == ("supported", "receipt_chain_holds")
    assert _verdict(_judge(tmp_path, receipts, **rb.head(receipts))) == ("contradicted", "chain_order")


def test_restart_is_reported_not_passed(tmp_path: Path) -> None:
    first, second = rb.chain(rb.NEUTRAL, KEY, 4), rb.chain(rb.NEUTRAL, KEY, 3)
    second = [rb.receipt(rb.NEUTRAL, KEY, None, request=f"s{i}") for i in range(3)]
    honest = first + second
    result = _judge(tmp_path, honest, **rb.head(honest))
    assert _verdict(result) == ("not_established", "chain_reset")
    assert {c["id"]: c["status"] for c in result["checks"]}["chain_order"] == "unavailable"


def test_restart_that_hides_a_lost_tail_is_caught_by_the_head(tmp_path: Path) -> None:
    first = _base(4)
    true_stream = first + [rb.receipt(rb.NEUTRAL, KEY, _sha(first[-1]), request="lost")]
    pinned = rb.head(true_stream + [rb.receipt(rb.NEUTRAL, KEY, None, request="s0")])
    shown = first + [rb.receipt(rb.NEUTRAL, KEY, None, request="s0")]
    assert _verdict(_judge(tmp_path, shown, **pinned)) == ("contradicted", "head_anchor")
    assert _verdict(_judge(tmp_path, shown)) == ("not_established", "chain_reset")


def test_format_without_an_effect_member_cannot_show_an_effect(tmp_path: Path) -> None:
    receipts = _base()
    result = _judge(tmp_path, receipts, require_effect=True, **rb.head(receipts))
    assert _verdict(result) == ("not_established", "effect_not_recorded")


def _wrapped(count: int, effects: dict[int, Any]) -> list[bytes]:
    out: list[bytes] = []
    prev = None
    for i in range(count):
        extra = {"effect": effects[i]} if i in effects else None
        out.append(rb.receipt(rb.WRAPPED, KEY, prev, request=f"w{i}", extra=extra))
        prev = _sha(out[-1])
    return out


def test_wrapped_profile_with_effects_is_supported(tmp_path: Path) -> None:
    receipts = _wrapped(3, {0: "done", 1: "done", 2: "done"})
    result = _judge(tmp_path, receipts, profile=rb.WRAPPED, require_effect=True, **rb.head(receipts))
    assert _verdict(result) == ("supported", "receipt_chain_holds")


def test_wrapped_profile_missing_one_effect_is_not_established(tmp_path: Path) -> None:
    receipts = _wrapped(3, {0: "done", 2: "done"})
    result = _judge(tmp_path, receipts, profile=rb.WRAPPED, require_effect=True, **rb.head(receipts))
    assert _verdict(result) == ("not_established", "effect_not_recorded")


def test_wrapped_profile_has_no_revocation_commitment(tmp_path: Path) -> None:
    receipts = _wrapped(2, {0: "done", 1: "done"})
    result = _judge(tmp_path, receipts, profile=rb.WRAPPED, require_revocation=True, **rb.head(receipts))
    assert _verdict(result) == ("not_established", "revocation_not_consulted")


def test_neutral_profile_revocation_commitment_is_checked(tmp_path: Path) -> None:
    receipts = _base(2)
    result = _judge(tmp_path, receipts, require_revocation=True, **rb.head(receipts))
    assert _verdict(result) == ("supported", "receipt_chain_holds")


def test_profile_without_a_proof_member_marks_single_use_unavailable(tmp_path: Path) -> None:
    profile = json.loads(json.dumps(rb.NEUTRAL))
    del profile["fields"]["proof"]
    receipts = rb.chain(profile, KEY, 3)
    result = _judge(tmp_path, receipts, profile=profile, **rb.head(receipts))
    assert _verdict(result) == ("supported", "receipt_chain_holds")
    assert {c["id"]: c["status"] for c in result["checks"]}["single_use"] == "unavailable"


@pytest.mark.parametrize("line", [
    b"not hex\n", b"zz\n", b"a1\n", b"a0\n", b"f6\n",
    (rb.encode({"v": 1, "p": b"", "k": b"x" * 31, "s": b"y" * 64}).hex() + "\n").encode(),
    (rb.encode({"v": 300, "p": b"", "k": b"x" * 32, "s": b"y" * 64}).hex() + "\n").encode(),
    (rb.encode({"v": 1, "p": b"", "k": b"x" * 32}).hex() + "\n").encode(),
])
def test_malformed_receipts_are_refused_with_a_reason(tmp_path: Path, line: bytes) -> None:
    result = _judge(tmp_path, line)
    assert _verdict(result) == ("contradicted", "receipt_shape")


def test_empty_stream_is_refused(tmp_path: Path) -> None:
    assert _verdict(_judge(tmp_path, b"\n")) == ("contradicted", "records_present")


def test_missing_records_artifact_is_not_established(tmp_path: Path) -> None:
    receipts = _base(2)
    result = _judge(tmp_path, receipts)
    (tmp_path / "chain.jsonl").unlink()
    case_policy = json.loads(json.dumps(result["scope"]))
    assert case_policy["records"]["status"] == "bound"
    # rebuild the case against the now missing file
    raw = rb.stream(rb.NEUTRAL, receipts)
    case = {"schema_version": "probity-case/v1", "case_id": "chain", "artifacts": {
        "chain.jsonl": {"path": "chain.jsonl", "length": len(raw), "sha256": hashlib.sha256(raw).hexdigest()},
        "profile.json": {"path": "profile.json", "length": (tmp_path / "profile.json").stat().st_size,
                         "sha256": hashlib.sha256((tmp_path / "profile.json").read_bytes()).hexdigest()}}}
    policy = {"schema_version": "probity-policy/v1", "assessments": {"chain": {
        "claim_type": "cbor_receipt_chain/v1", "records": "chain.jsonl", "profile": "profile.json",
        "signer_keys": [rb.public_hex(KEY)]}}}
    assert _verdict(adjudicate(case, policy, tmp_path)) == ("not_established", "records_unavailable")


def test_json_line_member_is_read(tmp_path: Path) -> None:
    receipts = _wrapped(2, {0: "done", 1: "done"})
    assert rb.stream(rb.WRAPPED, receipts).startswith(b'{"receipt": ')
    assert _verdict(_judge(tmp_path, receipts, profile=rb.WRAPPED, **rb.head(receipts))) == (
        "supported", "receipt_chain_holds")


def test_line_without_the_member_is_refused(tmp_path: Path) -> None:
    result = _judge(tmp_path, b'{"other": "00"}\n', profile=rb.WRAPPED)
    assert _verdict(result) == ("contradicted", "receipt_shape")


@pytest.mark.parametrize("mutate", [
    lambda p: p.update(schema_version="x"),
    lambda p: p["fields"].update(version=1),
    lambda p: p["fields"].pop("prev_hash"),
    lambda p: p["outer"].update(payload="v"),
    lambda p: p.update(key_form="hex"),
    lambda p: p.update(signature_context_hex="zz"),
    lambda p: p.update(allow_outcome=None),
    lambda p: p["fields"].update(version=True),
    lambda p: p.pop("profile_id"),
])
def test_malformed_profile_is_a_case_error_not_a_verdict(tmp_path: Path, mutate: Any) -> None:
    profile = json.loads(json.dumps(rb.NEUTRAL))
    mutate(profile)
    with pytest.raises(CaseError):
        _judge(tmp_path, _base(2), profile=profile)


@pytest.mark.parametrize("assessment", [
    {"signers": []}, {"signers": ["zz"]}, {"head": "a" * 64}, {"count": 3},
    {"head": "a" * 64, "count": 0}, {"head": "XYZ", "count": 1}, {"first_prev": "abc"},
    {"require_effect": "yes"},
])
def test_malformed_trust_inputs_are_case_errors(tmp_path: Path, assessment: dict) -> None:
    with pytest.raises(CaseError):
        _judge(tmp_path, _base(2), **assessment)


def test_decision_is_bound_to_the_consumer_policy(tmp_path: Path) -> None:
    receipts = _base(2)
    first = _judge(tmp_path, receipts, **rb.head(receipts))
    second = _judge(tmp_path, receipts)
    assert first["policy_sha256"] != second["policy_sha256"]
    assert first["claim_type"] == "cbor_receipt_chain/v1" and first["vantage"] == "independent"


@pytest.mark.parametrize("data", [
    b"\x5f\x41a\xff",  # indefinite byte string
    b"\xc1\x01",  # tag
    b"\xf9\x3c\x00",  # half-precision float
    b"\xa2\x01\x01\x01\x02",  # repeated map key
    b"\xa1\x41a\x01",  # byte-string map key
    b"\x01\x02",  # trailing bytes
    b"\x62\xff\xfe",  # text that is not UTF-8
    b"\x82\x01",  # truncated array
    b"\x58",  # truncated length
    b"\x1c",  # reserved additional information
    b"\xf7",  # undefined
    b"\x9b" + b"\xff" * 8,  # an array longer than its input
    b"",  # nothing
])
def test_decoder_refuses(data: bytes) -> None:
    with pytest.raises(adapter.Malformed):
        adapter.decode(data)


def test_decoder_refuses_deep_nesting() -> None:
    with pytest.raises(adapter.Malformed):
        adapter.decode(b"\x81" * 40 + b"\x01")


@pytest.mark.parametrize("value", [0, 23, 24, 255, 256, 65535, 65536, 2**32, 2**64 - 1, -1, -25, -(2**63),
                                   True, False, None, "", "é", b"", b"\x00" * 300,
                                   [1, [2, [3]]], {1: "a", "b": [None]}])
def test_decoder_round_trips_what_the_encoder_writes(value: Any) -> None:
    assert adapter.decode(rb.encode(value)) == value
