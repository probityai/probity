"""One signature, one number: the canonicalizer refuses numbers a double cannot hold exactly.

Counter-examples from the matrix break-it pass of 15 Nov 2026. Before this fix, target ``rfc8785``
canonicalized ``{"n":9007199254740993}`` to ``{"n":9007199254740992}``, so bytes signed over the
second record also verified the first.
"""

import hashlib
import json
from pathlib import Path

import pytest

from agent_evidence_verify import adjudicate
from agent_evidence_verify.adapters import jcs_canonical
from agent_evidence_verify.adapters.jcs_canonical import Refusal, canonical, canonical_bounded


def _judge(tmp_path: Path, text: str, claimed: bytes, target: str) -> dict:
    files = {"input.json": text.encode("utf-8"), "claimed.bin": claimed}
    artifacts = {}
    for name, body in files.items():
        (tmp_path / name).write_bytes(body)
        artifacts[name] = {"path": name, "length": len(body), "sha256": hashlib.sha256(body).hexdigest()}
    case = {"schema_version": "probity-case/v1", "case_id": "c", "artifacts": artifacts}
    policy = {"schema_version": "probity-policy/v1",
              "assessments": {"c": {"claim_type": "jcs_canonical/v1", "target": target,
                                    "input": "input.json", "claimed": "claimed.bin"}}}
    return adjudicate(case, policy, tmp_path)


UNSAFE_INTEGERS = ["9007199254740992", "9007199254740993", "-9007199254740993", "12345678901234568",
                   "100000000000000000000"]


@pytest.mark.parametrize("target", jcs_canonical.TARGETS)
@pytest.mark.parametrize("token", UNSAFE_INTEGERS)
def test_an_integer_past_the_exact_range_is_refused_under_every_target(target: str, token: str) -> None:
    with pytest.raises(Refusal, match="number_not_interoperable"):
        canonical(target, '{"n":' + token + "}")


@pytest.mark.parametrize("target", jcs_canonical.TARGETS)
def test_one_signature_no_longer_covers_two_integers(tmp_path: Path, target: str) -> None:
    signed = b'{"n":9007199254740992}'
    for text in ('{"n":9007199254740993}', '{"n":9007199254740992}'):
        result = _judge(tmp_path, text, signed, target)
        assert (result["decision"], result["reason"]) == ("contradicted", "no_canonical_form"), text


@pytest.mark.parametrize("target", jcs_canonical.TARGETS)
def test_the_largest_exact_integer_is_canonical(tmp_path: Path, target: str) -> None:
    for token in ("9007199254740991", "-9007199254740991"):
        text = '{"n":' + token + "}"
        assert canonical(target, text) == text.encode()
        result = _judge(tmp_path, text, text.encode(), target)
        assert result["decision"] == "supported"


FRACTIONS_PAST_THE_BOUND = ["12345678901234567.5", "9007199254740991.5", "-9007199254740991.5",
                            "9007199254740992.5", "9007199254740991.9", "1.00000000000000001e16"]


@pytest.mark.parametrize("token", FRACTIONS_PAST_THE_BOUND)
def test_the_bounded_profile_refuses_a_fraction_that_rounds_past_the_bound(token: str) -> None:
    text = '{"n":' + token + "}"
    with pytest.raises(Refusal, match="number_not_interoperable"):
        canonical_bounded(text)
    # RFC 8785 as written still rounds it; only the bounded profile is a signing input.
    assert canonical("rfc8785", text).startswith(b'{"n":')


def test_the_bounded_profile_keeps_a_fraction_that_rounds_into_range() -> None:
    assert canonical_bounded('{"n":9007199254740991.4}') == b'{"n":9007199254740991}'


@pytest.mark.parametrize("token,expected", [("1e20", b"100000000000000000000"), ("1e21", b"1e+21")])
def test_rfc8785_keeps_the_a2a_large_doubles(token: str, expected: bytes) -> None:
    # A2A vectors A5-002 and A5-012 are doubles, not integers: RFC 8785 as written accepts them.
    assert canonical("card-signing-input", '{"n":' + token + "}") == b'{"n":' + expected + b"}"
    with pytest.raises(Refusal):
        canonical_bounded('{"n":' + token + "}")


def test_the_refusal_reaches_nested_members() -> None:
    with pytest.raises(Refusal):
        canonical("rfc8785", json.dumps({"a": [{"b": 2**60}]}))
    with pytest.raises(Refusal):
        canonical_bounded(json.dumps({"a": [{"b": 2.0**60}]}))


def test_removing_the_integer_refusal_admits_two_pow_53(monkeypatch: pytest.MonkeyPatch) -> None:
    """Mutation control: without the bound, 2**53, which a double holds exactly, canonicalizes again."""
    monkeypatch.setattr(jcs_canonical, "MAX_EXACT_INTEGER", 10**400)
    assert canonical("rfc8785", '{"n":9007199254740992}') == b'{"n":9007199254740992}'
