"""The one strict I-JSON reader, and every adapter parse entry point that now goes through it.

The inputs are the parser-differential counter-examples of the 15 Nov 2026 matrix break-it pass
(row 21 CE1: duplicate members, a surrogate as UTF-8 bytes, a raw 0xFF byte; row 11 break vector 01:
a duplicate member that a last-member-wins reader accepts), plus the escape forms that defeat a
byte-level duplicate check.
"""

import base64
import json
from pathlib import Path

import pytest
from agent_evidence_verify import ijson
from agent_evidence_verify.adapters import (
    audit_principal,
    authority_anchor,
    cbor_receipt_chain,
    event_absence,
    observed_effect,
    operand_lineage,
    restoration,
    spend_reservation,
    token_grant_receipt,
    witnessed,
)
from agent_evidence_verify.common import CaseError
from agent_evidence_verify.ijson import IJSONError, parse_ijson, parse_lines
from agent_evidence_verify.json_input import parse_json

REFUSED = [
    (b'{"a":1,"a":2}', "duplicate-member"),
    (b'{"name":"Good","name":"Evil"}', "duplicate-member"),
    (b'{"x":{"a":1,"a":2}}', "duplicate-member"),
    (b'{"a":1,"\\u0061":2}', "duplicate-member"),
    (b'[{"k":[{"k":0,"k":1}]}]', "duplicate-member"),
    (b'{"a":"\xed\xa0\x80"}', "not-utf8"),
    (b'{"a":"\xff"}', "not-utf8"),
    (b'\xef\xbb\xbf{"a":1}', "not-utf8"),
    (b'{"a":"\\ud800"}', "lone-surrogate"),
    (b'{"\\udc00":1}', "lone-surrogate"),
    (b'{"a":9007199254740992}', "unsafe-integer"),
    (b'{"a":-9007199254740993}', "unsafe-integer"),
    (b'{"a":' + b"1" * 5000 + b"}", "unsafe-integer"),
    (b'{"a":1e400}', "value-not-representable"),
    (b'{"a":NaN}', "non-json-number"),
    (b'{"a":-Infinity}', "non-json-number"),
    (b'{"a":1,}', "not-parseable"),
    (b"[" * 129 + b"]" * 129, "nesting-too-deep"),
]


@pytest.mark.parametrize("raw,code", REFUSED)
def test_the_reader_refuses_each_differential_input_with_its_code(raw: bytes, code: str) -> None:
    with pytest.raises(IJSONError) as caught:
        parse_ijson(raw)
    assert caught.value.code == code


@pytest.mark.parametrize("raw,expected", [
    (b'{"a":9007199254740991,"b":-9007199254740991}', {"a": 2**53 - 1, "b": -(2**53 - 1)}),
    (b'{"emoji":"\\ud83d\\ude00"}', {"emoji": "\U0001F600"}),
    (b'{"a":1.5,"b":"x"}', {"a": 1.5, "b": "x"}),
    (b'{"\\"[{":"]}"}', {'"[{': "]}"}),
    (b"[" * 128 + b"]" * 128, None),
])
def test_the_reader_admits_what_i_json_allows(raw: bytes, expected) -> None:
    value = parse_ijson(raw)
    if expected is not None:
        assert value == expected


def test_integers_only_refuses_a_fraction() -> None:
    with pytest.raises(IJSONError) as caught:
        parse_ijson(b'{"a":1.0}', integers_only=True)
    assert caught.value.code == "value-not-representable"


def test_a_callers_own_hook_error_passes_through_unchanged() -> None:
    def no_fraction(text: str) -> float:
        raise CaseError("record number must be a safe integer")

    with pytest.raises(CaseError, match="safe integer"):
        parse_json(b'{"a":1.5}', max_bytes=64, max_depth=4, max_nodes=16, parse_float=no_fraction)


def test_parse_lines_names_the_line() -> None:
    assert parse_lines(b'{"a":1}\n\n{"b":2}\n') == [{"a": 1}, {"b": 2}]
    with pytest.raises(IJSONError, match="line 2"):
        parse_lines(b'{"a":1}\n{"b":1,"b":2}\n')


def test_an_unregistered_code_is_a_programming_error() -> None:
    with pytest.raises(AssertionError):
        IJSONError("made-up", "x")


def _envelope(statement: bytes) -> bytes:
    return json.dumps({"payloadType": "application/vnd.in-toto+json",
                       "payload": base64.b64encode(statement).decode("ascii"),
                       "signatures": []}).encode()


def _raises(call, raw: bytes) -> None:
    with pytest.raises((CaseError, IJSONError, ValueError)):
        call(raw)


#: Every adapter parse entry point that reads carried bytes. Each must refuse every REFUSED input
#: at the parse layer, never read past it.
ENTRY_POINTS = {
    "json_input.parse_json": lambda raw: parse_json(raw, max_bytes=1 << 20, max_depth=128,
                                                    max_nodes=1 << 20),
    "restoration.strict_json": restoration.strict_json,
    "token_grant_receipt._strict_json": lambda raw: token_grant_receipt._strict_json(raw, "r"),
    "spend_reservation._json": lambda raw: spend_reservation._json(raw, "r"),
    "operand_lineage._json_object": lambda raw: operand_lineage._json_object(raw, "r"),
    "authority_anchor._capture": authority_anchor._capture,
    "event_absence._record": lambda raw: event_absence._record(raw, "r", {"a"}),
    "cbor_receipt_chain._profile": cbor_receipt_chain._profile,
}


@pytest.mark.parametrize("name", sorted(ENTRY_POINTS))
@pytest.mark.parametrize("raw,code", REFUSED)
def test_every_adapter_entry_point_refuses_at_the_parse_layer(name: str, raw: bytes, code: str) -> None:
    _raises(ENTRY_POINTS[name], raw)


@pytest.mark.parametrize("raw,code", REFUSED)
def test_signed_record_readers_refuse_the_statement_as_malformed(raw: bytes, code: str) -> None:
    with pytest.raises(audit_principal.Malformed):
        audit_principal._parse(_envelope(raw))
    report = observed_effect.verify(_envelope(raw), None)
    assert report.verdict == "malformed", report


@pytest.mark.parametrize("raw,code", REFUSED)
def test_the_witness_reader_reads_nothing_from_a_refused_input(raw: bytes, code: str) -> None:
    assert witnessed._json(raw) is None


def test_audit_principal_keeps_its_pinned_codes() -> None:
    cases = {b'{"a":1,"a":2}': "duplicate-member", b'{"a":9007199254740992}': "unsafe-integer",
             b'{"a":1.5}': "value-not-representable", b'{"a":"\\ud800"}': "not-parseable",
             b'{"a":NaN}': "not-parseable"}
    for raw, code in cases.items():
        with pytest.raises(audit_principal.Malformed) as caught:
            audit_principal._parse(_envelope(raw))
        assert caught.value.code == code, raw


#: Parsers that stay private, each for a stated reason. jcs_canonical.py is the RFC 8785 adapter
#: whose own reader refuses duplicates and whose canonicalizer refuses lone surrogates and unsafe
#: numbers under the target's codes (the bounded profile is in the 0.6.0 release); proof_of_control's
#: ``parse`` feeds a token check that reports ``duplicate-key`` and ``parse`` codes the PoC corpus pins
#: and runs its own surrogate and canonical-number scan; verdict_codes.py reads the package's own file.
PRIVATE_PARSERS = {"jcs_canonical.py": 1, "proof_of_control.py": 1, "verdict_codes.py": 1}


def test_no_adapter_keeps_a_private_last_member_wins_parser() -> None:
    """Mutation control: a new ``json.loads`` anywhere in the package turns this red."""
    root = Path(ijson.__file__).parent
    counts = {}
    for path in sorted(root.rglob("*.py")):
        if path.name == "ijson.py":
            continue
        found = path.read_text(encoding="utf-8").count("json.loads(")
        if found:
            counts[path.name] = found
    assert counts == PRIVATE_PARSERS
