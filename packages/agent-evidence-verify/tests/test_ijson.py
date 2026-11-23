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


#: Break-it counter-examples against ``str.splitlines``: a record whose string carries a separator
#: Python treats as a line break, and one line that holds two values behind a non-JSON separator.
VALID_LINES = [
    ('{"a":"x\u2028y"}\n'.encode(), [{"a": "x\u2028y"}]),
    ('{"a":"x\u0085y"}\n'.encode(), [{"a": "x\u0085y"}]),
    (b'{"a":1}\r\n{"b":2}\r\n', [{"a": 1}, {"b": 2}]),
    (b' \t{"a":1}\t \n', [{"a": 1}]),
]
INVALID_LINES = [b'{"a":1}\x1c{"b":2}\n', b'{"a":1}\r{"b":2}\n', '{"a":1}\u2028{"b":2}\n'.encode(),
                 '\u00a0{"a":1}\n'.encode(), b'{"a":1}\x0b\n']


@pytest.mark.parametrize("raw,records", VALID_LINES)
def test_parse_lines_splits_on_line_feed_alone(raw: bytes, records: list) -> None:
    assert parse_lines(raw) == records


@pytest.mark.parametrize("raw", INVALID_LINES)
def test_parse_lines_never_splits_one_line_into_two_records(raw: bytes) -> None:
    with pytest.raises(IJSONError):
        parse_lines(raw)


def test_an_idp_export_behind_a_non_json_blank_is_refused() -> None:
    from agent_evidence_verify.adapters import idp_log_witness

    with pytest.raises(CaseError):
        idp_log_witness._auth0_events('\u00a0[{"type":"seacft"}]'.encode())
    with pytest.raises(CaseError):
        idp_log_witness._auth0_events(b'{"type":"seacft"}\x1c{"type":"seacft"}\n')


def test_receipt_lines_that_are_not_utf8_are_refused_not_replaced() -> None:
    profile = {"line_member": "receipt"}
    with pytest.raises(cbor_receipt_chain.Malformed, match="not-utf8"):
        cbor_receipt_chain._lines(b'{"receipt":"oA","note":"\xff"}\n', profile)
    assert cbor_receipt_chain._lines(b'{"receipt":"oA"}\r\n\n{"receipt":"oB"}\n',
                                     profile) == ["oA", "oB"]


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
    if code == "nesting-too-deep":  # too deep to walk: no verdict, the kernel's recursion answer
        with pytest.raises(CaseError, match="nested too deeply"):
            observed_effect.verify(_envelope(raw), None)
        return
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
#: _audit_record_reader.py is a rule-for-rule port of the agent audit record corpus's reference reader,
#: whose parse order and refusal codes the corpus pins member by member; its Statement parser refuses a
#: repeated name, an unsafe integer, a non-integer number, NaN and Infinity, a lone surrogate and nesting
#: past 128 under that corpus's codes, which tests/test_audit_record.py holds it to.
PRIVATE_PARSERS = {"jcs_canonical.py": 1, "proof_of_control.py": 1, "verdict_codes.py": 1,
                   "_audit_record_reader.py": 4}


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


#: Break-it counter-examples: numbers a double reader and a decimal reader read apart.
DOUBLE_LOSSY = [
    b'{"a":1e-400}',  # nonzero, reads as 0.0 and so as false (corpusreaders number-truth class)
    b'{"a":-2e-324}',  # rounds to -0.0
    b'{"a":3.141592653589793238462643383279}',  # RFC 7493 section 2.2's own example
    b'{"a":123456789012345678.0}',  # 18 significant digits
    # Round 3: within 17 digits, the double is still another number.
    b'{"a":9007199254740993.0}',  # the unsafe integer 2**53 + 1, written as a float
    b'{"a":9.007199254740993e15}',  # the same, in exponent form
    b'{"a":9007199254740993.5}',  # 17 digits, reads as 9007199254740994.0
    b'{"a":0.10000000000000001}',  # printf %.17g of 0.1; a decimal reader keeps the trailing 1
]


@pytest.mark.parametrize("raw", DOUBLE_LOSSY)
def test_a_number_a_double_cannot_hold_is_refused(raw: bytes) -> None:
    with pytest.raises(IJSONError) as caught:
        parse_ijson(raw)
    assert caught.value.code == "value-not-representable"
    _raises(ENTRY_POINTS["json_input.parse_json"], raw)


@pytest.mark.parametrize("raw,expected", [
    (b'{"a":5e-324}', 5e-324), (b'{"a":0.0e-999}', 0.0), (b'{"a":-0.0}', -0.0),
    (b'{"a":0.30000000000000004}', 0.30000000000000004), (b'{"a":1.10000000000000000000}', 1.1),
    (b'{"a":9007199254740992.0}', 9007199254740992.0), (b'{"a":1.7976931348623157e308}', 1.7976931348623157e308),
    (b'{"a":2.5E-3}', 0.0025), (b'{"a":-1e2}', -100.0),
])
def test_a_number_a_double_holds_is_read(raw: bytes, expected: float) -> None:
    assert parse_ijson(raw)["a"] == expected


def test_a_lone_surrogate_is_kept_only_when_the_caller_refuses_it_later() -> None:
    """``lone_surrogates`` keeps the string for an adapter whose profile refuses it at a later step
    (catalog_trust_manifest/v1, in the signed bytes only); every other rule still runs."""
    raw = b'{"a":"\\ud800"}'
    assert parse_ijson(raw, lone_surrogates=True) == {"a": "\ud800"}
    with pytest.raises(IJSONError) as caught:
        parse_ijson(b'{"a":"\\ud800","a":1}', lone_surrogates=True)
    assert caught.value.code == "duplicate-member"
    with pytest.raises(IJSONError) as caught:
        parse_ijson(raw)
    assert caught.value.code == "lone-surrogate"
