"""Canonical bytes and received records: the typed refusals both twins report, and the shared vectors.

The TypeScript twin (node/probity-records-verify) reads vectors/shared/canonical.json and
received.json and must report the same bytes or refusal for every case; these tests hold the files
to this package's own output and pin each refusal that was once a twin disagreement.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
from probity_records import admitted_loads, canonical, canonical_of_received

ROOT = Path(__file__).resolve().parents[1]
SHARED = ROOT / "vectors" / "shared"


def _generator():
    spec = importlib.util.spec_from_file_location(
        "gen_shared_vectors", ROOT / "scripts" / "gen_shared_vectors.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("family", ["canonical", "received"])
def test_shared_family_is_this_packages_output(family: str) -> None:
    gen = _generator()
    rows = gen.canonical_rows() if family == "canonical" else gen.received_rows()
    assert rows == json.loads((SHARED / f"{family}.json").read_text())


@pytest.mark.parametrize(
    "raw",
    [
        b'{"b\\ud800key": 1, "a": 2}',
        b'{"name": "\\ud800x"}',
        b'{"a":"\xed\xa0\x80"}',
        b'{"a":"\xff"}',
    ],
)
def test_lone_surrogates_and_invalid_utf8_are_a_typed_refusal(raw: bytes) -> None:
    with pytest.raises(ValueError, match="^jcs_refused:StringNotScalar$"):
        canonical_of_received(raw)


def test_a_lone_surrogate_in_a_value_is_the_same_refusal_not_a_codec_error() -> None:
    with pytest.raises(ValueError, match="^jcs_refused:StringNotScalar$"):
        canonical({"name": "x\udc00"})


@pytest.mark.parametrize("raw", [b'{"a":1,"a":2}', b'{"name":"Good","name":"Evil"}'])
def test_a_duplicate_member_is_refused_before_a_parser_keeps_the_last(
    raw: bytes,
) -> None:
    with pytest.raises(ValueError, match="^jcs_refused:DuplicateMember$"):
        admitted_loads(raw)


def test_an_integer_past_2_53_is_refused_with_its_exact_text() -> None:
    with pytest.raises(
        ValueError, match="^integer_beyond_exact_json_range:9007199254740993$"
    ):
        canonical_of_received(b'{"n":9007199254740993}')


def test_ascii_escaping_does_not_change_canonical_bytes() -> None:
    assert (
        canonical({"b": 1, "a": "é\U0001f600"}) == '{"a":"é\U0001f600","b":1}'.encode()
    )
