"""The grammar files (``grammar/*.json``) are what the readers implement: each pattern and bound in a file is the one in
the reader's code, and each accepted and refused text is judged as the file says. The TypeScript twin has the same test
(``test/r10-grammar.test.ts``), and the differential generator (``tests/parity_r6c/grammar_cases.py``) reads the same
files, so a rule changed in one place and not the others fails here.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from agent_evidence_verify import structured_fields as sf
from probity_records import (
    certificate,
    core,
    grants,
    possession,
    stamp,
    trust_bundle,
    verified_identities,
)

GRAMMAR = Path(__file__).resolve().parents[1] / "grammar"
FILES = ("compact-jws", "integer", "stamp", "target-uri", "timestamp", "trust-bundle", "x509")


def rules(name: str) -> dict[str, Any]:
    return json.loads((GRAMMAR / f"{name}.json").read_text())["productions"]


def test_every_grammar_file_is_listed_and_names_its_readers() -> None:
    assert sorted(p.stem for p in GRAMMAR.glob("*.json")) == sorted(FILES)
    for name in FILES:
        doc = json.loads((GRAMMAR / f"{name}.json").read_text())
        assert doc["spec"] and doc["readers"]["python"] and doc["readers"]["typescript"], name


def test_the_timestamp_reader_is_the_grammar() -> None:
    rule = rules("timestamp")["date-time"]
    assert grants.TIMESTAMP.pattern == rule["pattern"]
    for text, micros in rule["accept"]:
        assert f"{grants.micros(text):d}" == micros, text
    for text, code in rule["refuse"]:
        with pytest.raises(ValueError, match=f"^{code}$"):
            grants.micros(text)


def test_the_integer_reader_is_the_grammar() -> None:
    doc = rules("integer")
    rule = doc["exact-integer"]
    assert (rule["bounds"]["min"], rule["bounds"]["max"]) == (-core.MAX_EXACT_INT, core.MAX_EXACT_INT)
    assert all(core.exact_int(value) for value in rule["accept"])
    assert not any(core.exact_int(value) for value in rule["refuse"])
    assert grants._DECIMAL.pattern == doc["decimal-digits"]["pattern"]
    for text in ("", "1" * 16, "\u0661", "\uff11", "+1", "-1", " 1", "1 ", "1_0", "1.0"):
        with pytest.raises(ValueError, match="not_decimal_digits"):
            grants.decimal(text)


def test_the_target_uri_reader_is_the_grammar() -> None:
    doc = rules("target-uri")
    port, alphabet = doc["port"], doc["uri-text"]["alphabet"]
    assert possession.PORT.pattern == port["pattern"]
    for text, value in port["accept"]:
        assert possession.http_uri_parts(f"https://a.example:{text}/x")[2] == value, text
    for text in port["refuse"]:
        with pytest.raises(ValueError):
            possession.http_uri_parts(f"https://a.example:{text}/x")
    for zeros in port["long"]["zeros"]:
        assert possession.http_uri_parts("https://a.example:" + "0" * zeros + "443/x")[2] == 443
    for code in [*range(0x100), 0x3002, 0xFF0F, 0x2028]:
        ch = chr(code)
        if ch != "%":
            assert bool(possession._URI_TEXT.fullmatch(ch)) == (ch in alphabet), hex(code)


def test_the_certificate_reader_is_the_grammar() -> None:
    doc = rules("x509")
    assert certificate.UTC_TIME.pattern == doc["time"]["utcTime"]["pattern"]
    assert certificate.GENERALIZED_TIME.pattern == doc["time"]["generalizedTime"]["pattern"]
    assert certificate.SPKI_ED25519.hex() == doc["spki"]["ed25519"] and certificate.SPKI_P256.hex() == doc["spki"]["p256"]
    assert [f"{tag:02x}" for tag in certificate._OUTLINE] == doc["tbs"]["outline"]
    assert [f"{tag:02x}" for tag in certificate._OPTIONAL] == doc["tbs"]["optional"]


def test_the_stamp_reader_is_the_grammar_and_the_structured_field_reader_keeps_its_rule() -> None:
    """The byte-sequence rule is the released structured-fields reader's own; these vectors pin its answers, so a new
    release of that dependency cannot move the rule without this test failing."""
    doc = rules("stamp")
    assert doc["field-value"]["ows"] == stamp.OWS
    assert list(doc["order"]["fields"]) == [stamp.SIGNATURE_INPUT_HEADER, stamp.SIGNATURE_HEADER, stamp.CONTENT_DIGEST_HEADER]
    seq = doc["byte-sequence"]
    assert sf._B64.pattern == seq["pattern"]
    for text, hexed in seq["accept"]:
        assert sf.parse_dictionary(f"a=:{text}:")["a"].value.hex() == hexed, text
    for text in seq["refuse"]:
        with pytest.raises(sf.SFError):
            sf.parse_dictionary(f"a=:{text}:")
    for ch in doc["field-value"]["notOws"]:
        assert f"{ch}x{ch}".strip(stamp.OWS) == f"{ch}x{ch}"


def test_the_bundle_reader_is_the_grammar() -> None:
    doc = rules("trust-bundle")
    assert sorted(verified_identities.BUNDLE_MEMBERS) == doc["bundle"]["members"]
    assert sorted(trust_bundle.ANCHOR_MEMBERS) == doc["anchor"]["members"]
