"""Write vectors/shared/receipt-map.json: the receipt map format as cases another implementation must pass.

Deterministic: every key, leaf hash and map comes from fixed labels, so running this again writes the same
bytes, and tests/test_receipt_map.py checks both the cases and that the file is what this script writes.

Run from packages/probity-records:  python scripts/make_receipt_map_vectors.py
"""

from __future__ import annotations

import hashlib
import importlib
import json
import sys
import types
from pathlib import Path
from typing import Any

# receipt_map reads its base64 through core.unb64, so it loads as a member of the package, from this checkout's
# source tree. The package's __init__ is not run (it imports every optional dependency); a bare package object
# with the source directory as its path is enough for the relative import, and the vectors build in the
# package's own environment.
_SRC = Path(__file__).resolve().parents[1] / "src" / "probity_records"
_PACKAGE = types.ModuleType("probity_records")
_PACKAGE.__path__ = [str(_SRC)]
sys.modules.setdefault("probity_records", _PACKAGE)
rm = importlib.import_module("probity_records.receipt_map")

OUT = Path(__file__).resolve().parents[1] / "vectors" / "shared" / "receipt-map.json"


def h(label: str) -> bytes:
    return hashlib.sha256(label.encode()).digest()


def issuer(label: str) -> str:
    return h(f"issuer {label}").hex()


def build() -> dict[str, Any]:
    entries = [(issuer("a" if i % 3 else "b"), f"permit.{i:03d}", rm.STAGES[i % 4]) for i in range(24)]
    m = rm.ReceiptMap()
    for index, (iss, permit, stage) in enumerate(entries):
        m.insert(rm.map_key(iss, permit, stage), index * 2, h(f"leaf {index}"))
    root = m.root()
    cases: list[dict[str, Any]] = []

    def case(name: str, proof: dict[str, Any], expect: str, holds: dict[str, Any] | None = None,
             at_root: bytes = root) -> None:
        cases.append({"name": name, "root": at_root.hex(), "proof": proof, "expect": expect, "holds": holds})

    for i in (0, 7, 23):
        key = rm.map_key(*entries[i])
        p = m.prove(key)
        case(f"member {i}", p.to_doc(), "member", {"index": i * 2, "leafHash": h(f"leaf {i}").hex()})
    absent_empty = absent_other = None
    for n in range(10_000):
        key = rm.map_key(issuer("a"), f"absent.{n}", "execute")
        p = m.prove(key)
        if p.terminal is None and absent_empty is None:
            absent_empty = p
        if p.terminal is not None and absent_other is None:
            absent_other = p
        if absent_empty and absent_other:
            break
    assert absent_empty and absent_other
    case("absent, path ends in an empty subtree", absent_empty.to_doc(), "absent")
    case("absent, path ends in another key's entry", absent_other.to_doc(), "absent")
    case("absent from the empty map", rm.ReceiptMap().prove(h("anything")).to_doc(), "absent", at_root=rm.EMPTY)
    case("another issuer's receipt for the same permit and stage is another key",
         m.prove(rm.map_key(issuer("c"), *entries[7][1:])).to_doc(), "absent")

    member = m.prove(rm.map_key(*entries[7]))
    doc = member.to_doc()
    case("refused: path extended with an empty sibling", {**doc, "siblings": [*doc["siblings"], None]}, "refused")
    case("refused: path cut one level short", {**doc, "siblings": doc["siblings"][:-1]}, "refused")
    case("refused: proof for another root", doc, "refused", at_root=h("another root"))
    other = m.get(rm.map_key(*entries[0]))
    assert other is not None
    off_path = {**doc, "terminal": {"key": other.key.hex(), "index": other.index, "leafHash": other.leaf.hex()}}
    case("refused: terminal entry not on the key's path", off_path, "refused")
    case("refused: membership claimed for an absent key",
         {**absent_empty.to_doc(), "terminal": {"key": absent_empty.key.hex(), "index": 0, "leafHash": "00" * 32}},
         "refused")
    case("refused: empty-path proof presented for a present key",
         {**doc, "siblings": doc["siblings"], "terminal": None}, "refused")
    case("malformed: a sibling of 31 bytes", {**doc, "siblings": [*doc["siblings"][:-1], "AAAA"]}, "malformed")
    case("malformed: 257 siblings", {**doc, "siblings": [None] * 257}, "malformed")
    case("malformed: leaf index is not an integer",
         {**doc, "terminal": {**doc["terminal"], "index": True}}, "malformed")

    keys = [{"issuer": iss, "permit": permit, "stage": stage, "key": rm.map_key(iss, permit, stage).hex()}
            for iss, permit, stage in entries[:4]]
    bad_keys = [
        {"issuer": issuer("a"), "permit": "", "stage": "execute", "why": "empty permit id"},
        {"issuer": issuer("a"), "permit": "p" * 257, "stage": "execute", "why": "permit id over 256 bytes"},
        {"issuer": issuer("a"), "permit": "p\n1", "stage": "execute", "why": "control character in permit id"},
        {"issuer": issuer("a"), "permit": "p1", "stage": "refund", "why": "stage outside the four"},
        {"issuer": "ab" * 31, "permit": "p1", "stage": "execute", "why": "issuer is not a 32-byte key id"},
    ]
    return {
        "format": "probity-receipt-map/v1 vectors",
        "stages": list(rm.STAGES),
        "entries": [{"issuer": iss, "permit": permit, "stage": stage, "index": i * 2, "leafHash": h(f"leaf {i}").hex()}
                    for i, (iss, permit, stage) in enumerate(entries)],
        "root": root.hex(),
        "keys": keys,
        "badKeys": bad_keys,
        "cases": cases,
    }


def render() -> str:
    return json.dumps(build(), indent=1, sort_keys=True) + "\n"


if __name__ == "__main__":
    OUT.write_text(render())
    print(f"wrote {OUT}")
