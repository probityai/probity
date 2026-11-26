"""The identity digests: one definition, held to the shared vectors and to the spec page."""

from __future__ import annotations

import hashlib
import json
import random
import re
from pathlib import Path
from typing import Any

import jcs_admit
import pytest
from probity_records.digests import (
    CODES,
    MAX_SAFE_INT,
    REASONS,
    IdentityDigestError,
    act_chain_digest,
    admit,
    grant_chain_digest,
    grant_chain_digest_of,
    principals_digest,
    stamp_digest,
    stamp_digest_of,
)
from probity_records.digests_vectors import block, check, links, vectors
from probity_records.grants import grant_digest

PACKAGE = Path(__file__).resolve().parents[1]
SHARED = PACKAGE / "vectors" / "shared" / "identity_digests.json"
SPEC = PACKAGE / "docs" / "identity-digests.md"


def _expected(vid: str) -> dict[str, Any]:
    return next(v["expected"] for v in vectors() if v["id"] == vid)


def test_every_vector_judges_as_expected_and_the_shared_file_is_current() -> None:
    rows = vectors()
    assert rows == vectors()
    assert json.loads(SHARED.read_text()) == json.loads(json.dumps(rows))
    assert check(json.loads(SHARED.read_text())) == []
    assert {v["expected"].get("refused") for v in rows} - {None} == set(CODES)
    assert {v["expected"].get("reason") for v in rows} - {None} == set(REASONS) - {
        "unsupported_type",
        "no_canonical_form",
    }


def test_the_same_value_in_another_member_order_digests_the_same() -> None:
    assert _expected("PD1") == _expected("PD2")
    assert _expected("AC2") == _expected("AC3")


def test_the_chain_digest_from_links_equals_the_one_from_grant_digests() -> None:
    chain = links()
    assert _expected("GC1") == _expected("GC2")
    assert grant_chain_digest(chain) == grant_chain_digest_of(
        [grant_digest(link["body"]) for link in chain]
    )
    assert _expected("GC1") != _expected("GC4")


def test_the_stamp_of_a_block_is_the_stamp_of_its_three_digests() -> None:
    b, chain = block(), links()
    whole = stamp_digest(
        principals_digest(b),
        act_chain_digest(b["user"]["act"]),
        grant_chain_digest(chain),
    )
    assert stamp_digest_of(b, chain) == whole == _expected("SS1")["digest"]
    del b["user"]["act"]
    assert (
        stamp_digest_of(b)
        == stamp_digest(principals_digest(b), None, None)
        == _expected("SS2")["digest"]
    )


def test_a_digest_is_sha256_over_the_rfc8785_bytes() -> None:
    b = block()
    data = jcs_admit.admit(json.dumps(b).encode())
    assert principals_digest(b) == "sha256:" + hashlib.sha256(data).hexdigest()


def _random_value(rng: random.Random, depth: int = 0) -> Any:
    kind = rng.randrange(7 if depth < 4 else 4)
    if kind == 0:
        return rng.choice([None, True, False])
    if kind == 1:
        return rng.randint(-MAX_SAFE_INT, MAX_SAFE_INT)
    if kind == 2:
        return "".join(
            rng.choice(["a", "é", "\U0001f600", '"', "\\", "\n", "z"])
            for _ in range(rng.randrange(6))
        )
    if kind == 3:
        return rng.choice([0, -1, MAX_SAFE_INT, -MAX_SAFE_INT])
    if kind in (4, 5):
        names = [
            "".join(rng.choice("abcXYZ_-. ~") for _ in range(rng.randrange(1, 5)))
            for _ in range(rng.randrange(4))
        ]
        return {n: _random_value(rng, depth + 1) for n in names}
    return [_random_value(rng, depth + 1) for _ in range(rng.randrange(4))]


def _shuffled(value: Any, rng: random.Random) -> Any:
    if isinstance(value, dict):
        items = list(value.items())
        rng.shuffle(items)
        return {k: _shuffled(v, rng) for k, v in items}
    if isinstance(value, list):
        return [_shuffled(v, rng) for v in value]
    return value


def test_admission_never_changes_a_value_in_the_domain_and_member_order_never_changes_its_digest() -> (
    None
):
    rng = random.Random(30)
    for _ in range(400):
        value = {"user": {"extra": _random_value(rng)}}
        assert admit(value) == value
        assert principals_digest(value) == principals_digest(_shuffled(value, rng))
        reparsed = json.loads(json.dumps(value))
        assert principals_digest(reparsed) == principals_digest(value)


@pytest.mark.parametrize(
    "value,reason",
    [
        (1.0, "float"),
        (float("nan"), "float"),
        (2**53, "integer_out_of_range"),
        ({1: "x"}, "unsupported_type"),
        (b"bytes", "unsupported_type"),
        ({"é": 1}, "member_name_not_ascii"),
        ("\udc00", "lone_surrogate"),
    ],
)
def test_a_value_outside_the_domain_is_refused_with_one_code(
    value: Any, reason: str
) -> None:
    with pytest.raises(IdentityDigestError) as caught:
        principals_digest({"user": {"extra": value}})
    assert (caught.value.code, caught.value.reason) == (
        "identity_out_of_domain",
        reason,
    )


def test_a_bool_is_never_read_as_an_integer() -> None:
    assert principals_digest({"user": {"x": True}}) != principals_digest(
        {"user": {"x": 1}}
    )


def test_the_spec_lists_exactly_the_codes_and_reasons_the_module_raises() -> None:
    text = SPEC.read_text()
    named = set(re.findall(r"`(identity_[a-z_]+)`", text))
    assert named == set(CODES)
    reasons = set(re.findall(r"^\| `([a-z_]+)` \|", text, re.MULTILINE))
    assert reasons == set(REASONS)
