"""The receipt map format against its shared vectors (vectors/shared/receipt-map.json).

Each case is a proof and a root with the verdict another implementation must reach: member (and which entry),
absent, refused (the proof does not reproduce the root, or ends off the key's path), or malformed (refused
before any hashing). The file must also be exactly what scripts/make_receipt_map_vectors.py writes, so a
hand edit of a vector fails here.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest
from probity_records import receipt_map as rm

ROOT = Path(__file__).resolve().parents[1]
VECTORS = json.loads((ROOT / "vectors" / "shared" / "receipt-map.json").read_text())


def _verdict(case: dict[str, Any]) -> tuple[str, rm.Entry | None]:
    try:
        proof = rm.Proof.from_doc(case["proof"])
    except rm.MapError:
        return "malformed", None
    try:
        held = proof.holds(bytes.fromhex(case["root"]))
    except rm.MapError:
        return "refused", None
    return ("member", held) if held is not None else ("absent", None)


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda c: c["name"])
def test_each_vector_reaches_its_verdict(case: dict[str, Any]) -> None:
    verdict, held = _verdict(case)
    assert verdict == case["expect"]
    if verdict == "member":
        assert held is not None and {"index": held.index, "leafHash": held.leaf.hex()} == case["holds"]


def test_the_vector_set_covers_every_verdict() -> None:
    assert {c["expect"] for c in VECTORS["cases"]} == {"member", "absent", "refused", "malformed"}


def test_the_root_is_the_root_of_the_listed_entries() -> None:
    m = rm.ReceiptMap()
    for e in VECTORS["entries"]:
        m.insert(rm.map_key(e["issuer"], e["permit"], e["stage"]), e["index"], bytes.fromhex(e["leafHash"]))
    assert m.root().hex() == VECTORS["root"]
    with pytest.raises(rm.MapError, match="already holds"):
        e = VECTORS["entries"][0]
        m.insert(rm.map_key(e["issuer"], e["permit"], e["stage"]), 99, bytes(32))


@pytest.mark.parametrize("k", VECTORS["keys"], ids=lambda k: k["permit"])
def test_map_keys(k: dict[str, str]) -> None:
    assert rm.map_key(k["issuer"], k["permit"], k["stage"]).hex() == k["key"]


@pytest.mark.parametrize("k", VECTORS["badKeys"], ids=lambda k: k["why"])
def test_bad_keys_are_refused(k: dict[str, str]) -> None:
    with pytest.raises(rm.MapError):
        rm.map_key(k["issuer"], k["permit"], k["stage"])


def test_the_vector_file_is_what_the_generator_writes() -> None:
    spec = importlib.util.spec_from_file_location("make_receipt_map_vectors", ROOT / "scripts" / "make_receipt_map_vectors.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.render() == (ROOT / "vectors" / "shared" / "receipt-map.json").read_text()
