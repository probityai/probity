"""Vectors for the RFC 8785 canonical JSON profile behind every signed record."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from probity_observer.crypto import SigningKey, VerificationError, canonical, digest, strict_loads, verify_signature

VECTORS = json.loads((Path(__file__).parent / "fixtures" / "canonical-profile-v1" / "vectors.json").read_text(encoding="ascii"))
ACCEPT = VECTORS["accept"]
REJECT = VECTORS["reject"]


@pytest.mark.parametrize("case", ACCEPT, ids=[case["name"] for case in ACCEPT])
def test_accept_vector_has_exact_canonical_bytes(case: dict[str, Any]) -> None:
    """Unicode string values serialize to the hand-built RFC 8785 bytes."""
    expected = bytes.fromhex(case["canonical_hex"])
    assert canonical(case["value"]) == expected
    assert strict_loads(expected) == case["value"]


@pytest.mark.parametrize("case", ACCEPT, ids=[case["name"] for case in ACCEPT])
def test_accept_vector_signs_and_verifies(case: dict[str, Any]) -> None:
    """A record carrying model text signs, verifies, and hashes."""
    key = SigningKey.generate()
    signature = key.sign("probity-test-v1", case["value"])
    verify_signature(key.public_hex, "probity-test-v1", case["value"], signature)
    assert len(digest("probity-test-v1", case["value"])) == 64


@pytest.mark.parametrize("case", REJECT, ids=[case["name"] for case in REJECT])
def test_reject_vector_is_refused(case: dict[str, Any]) -> None:
    """Values with no single portable form stay outside the profile."""
    with pytest.raises(VerificationError, match=case["error"]):
        canonical(case["value"])


def test_normalization_variants_are_distinct_records() -> None:
    """NFC and NFD spellings are different values, never silently merged."""
    assert canonical({"t": "é"}) != canonical({"t": "é"})


def test_ascii_records_keep_their_previous_bytes() -> None:
    """Records signed before the change verify unchanged."""
    value = {"b": ["x", 1, True, None], "a": {"z": "q\n\u001f\\\"/", "y": -3}}
    previous = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("ascii")
    assert canonical(value) == previous


@pytest.mark.parametrize(
    "data",
    [
        '{"t":"é"}'.encode("utf-16"),
        b'{"t":"\\u00e9"}',
        b'{"t":"\\ud800"}',
        b'{"t":"\xff"}',
    ],
    ids=["utf-16", "escaped-non-ascii", "escaped-lone-surrogate", "invalid-utf-8"],
)
def test_strict_loads_refuses_other_spellings(data: bytes) -> None:
    """Only the raw UTF-8 RFC 8785 spelling of a value parses."""
    with pytest.raises(VerificationError):
        strict_loads(data)
