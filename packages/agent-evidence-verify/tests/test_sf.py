"""The Structured Field reader the signature adapters share: RFC 8941 shapes, and the refusals that go further."""

from __future__ import annotations

from decimal import Decimal

import pytest
from agent_evidence_verify import structured_fields as sf


def test_dictionary_of_inner_list_and_items_round_trips() -> None:
    text = 'sig1=("@authority" "signature-agent";key="agent1");created=1735689600;tag="web-bot-auth"'
    parsed = sf.parse_dictionary(text)
    inner = parsed["sig1"]
    assert isinstance(inner, sf.InnerList)
    assert [i.value for i in inner.items] == ["@authority", "signature-agent"]
    assert inner.items[1].params == {"key": "agent1"}
    assert inner.params == {"created": 1735689600, "tag": "web-bot-auth"}
    assert sf.serialize_member(inner) == text.split("=", 1)[1]


def test_every_bare_item_type_is_read_with_its_type() -> None:
    parsed = sf.parse_dictionary('a=1, b=-2.5, c="x", d=tok, e=:AQID:, f=?1, g=?0, h')
    values = {k: v.value for k, v in parsed.items() if isinstance(v, sf.Item)}
    assert values == {"a": 1, "b": Decimal("-2.5"), "c": "x", "d": "tok", "e": b"\x01\x02\x03", "f": True,
                      "g": False, "h": True}
    assert isinstance(values["d"], sf.Token) and not isinstance(values["c"], sf.Token)


def test_string_escapes_and_serialisation() -> None:
    item = sf.parse_item(r'"a\"b\\c"')
    assert item.value == 'a"b\\c'
    assert sf.serialize_item(item) == r'"a\"b\\c"'


@pytest.mark.parametrize("text", [
    "a=1, a=2",                  # repeated key: RFC 8941 keeps the last, a verifier must not
    "a=1;p=1;p=2",               # repeated parameter
    "a=1,",                      # trailing comma
    "a=(1 2",                    # unterminated inner list
    'a="unterminated',
    "a=:AQID",                   # unterminated byte sequence
    "a=:A:",                     # a length no base64 text can have
    "a=:AQ=I:",                  # padding before the end
    "a=:AQID!:",                 # outside the alphabet
    "a=?2",
    "a=1x",
    "a=1234567890123456",        # sixteen digits
    "a=1.1234",                  # four fractional digits
    'a="é"',                # non-ASCII in a String
    "A=1",                       # uppercase key
    "a=٣",                  # an Arabic-Indic digit three
    "a=-٣",
    "a=(1)(2)",
    "a=1 b=2",
])
def test_malformed_dictionary_is_refused(text: str) -> None:
    with pytest.raises(sf.SFError):
        sf.parse_dictionary(text)


@pytest.mark.parametrize(("text", "raw"), [("a=:AQI:", b"\x01\x02"), ("a=:AR==:", b"\x01"), ("a=:AQI=:", b"\x01\x02")])
def test_byte_sequences_follow_rfc_8941_section_4_2_7(text: str, raw: bytes) -> None:
    # Missing padding and non-zero pad bits are read, as RFC 8941 says a parser SHOULD; the value is re-serialised
    # in the one canonical spelling, so the spelling never reaches a signature base.
    member = sf.parse_dictionary(text)["a"]
    assert isinstance(member, sf.Item) and member.value == raw
    assert sf.serialize_member(member) == sf.serialize_bare_item(raw)


@pytest.mark.parametrize(("text", "strict"), [("(a  b);p=1", "(a b);p=1"), ("x  ;  y", None), ("a=1,   b", "a=1, b"),
                                               ("tok", "tok")])
def test_reserialize_is_the_strict_form(text: str, strict: str | None) -> None:
    if strict is None:
        with pytest.raises(sf.SFError):
            sf.reserialize(text)
    else:
        assert sf.reserialize(text) == strict


def test_digits_outside_ascii_are_never_numbers() -> None:
    # int("٣") is 3 in Python; the reader must not hand that to a verifier as an Integer.
    with pytest.raises(sf.SFError):
        sf.parse_item("٣")


def test_whitespace_rules() -> None:
    assert list(sf.parse_dictionary("a=1 ,\t b=2")) == ["a", "b"]
    assert sf.parse_dictionary("") == {}
    with pytest.raises(sf.SFError):
        sf.parse_dictionary("a=1,\n b=2")


def test_decimal_serialises_to_three_places_without_trailing_zeros() -> None:
    assert sf.serialize_bare_item(Decimal("1.5000")) == "1.5"
    assert sf.serialize_bare_item(Decimal(2)) == "2.0"
    assert sf.serialize_bare_item(Decimal("0.0005")) == "0.0"


def test_string_serialisation_refuses_non_ascii() -> None:
    with pytest.raises(sf.SFError):
        sf.serialize_bare_item("café")
