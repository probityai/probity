"""Round r8 verifier attacks: base64 readers outside ``core.unb64`` that still read a second spelling.

``core.unb64`` says every reader of received base64 goes through its one canonical rule. The record bundle reader
(``bundle._unb64`` and ``read_evaluator``) and the receipt map proof reader (``Proof.from_doc``) decode with
``base64.b64decode(validate=True)``, which keeps the stray low bits of the last digit: ``AB==`` reads as ``AA==``.
Each test below respells one base64 member of an otherwise valid document and expects the reader to refuse it.
"""

from __future__ import annotations

import base64
import copy
import json
from typing import Any

import pytest
from probity_records.bundle import BundleRefused, verify_bundle
from probity_records.receipt_map import MapError, Proof, ReceiptMap, map_key
from test_bundle import NOW, World

_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def respelled(text: str) -> str:
    """The same bytes in a second base64 spelling: the last digit before the padding with a stray low bit set."""
    pad = len(text) - len(text.rstrip("="))
    assert pad in (1, 2), "only padded text has stray bits"
    i = len(text) - pad - 1
    digit = _ALPHABET.index(text[i])
    other = _ALPHABET[digit | 1] if digit % 2 == 0 else _ALPHABET[digit & ~1]
    out = text[:i] + other + text[i + 1:]
    assert out != text and base64.b64decode(out, validate=True) == base64.b64decode(text, validate=True)
    return out


def _padded_world() -> World:
    """A world whose record bytes need base64 padding: JSON whitespace after the envelope changes only the bytes'
    length, never the record (its identity is the SHA-256 of the signed payload)."""
    world = World()
    while len(world.raw) % 3 == 0:
        world.raw += b" "
    assert verify_bundle(world.bundle(), world.trust(), NOW).grade == "I"
    return world


def test_the_respelling_helper_keeps_the_bytes() -> None:
    assert respelled("AA==") == "AB=="
    assert base64.b64decode("AB==", validate=True) == b"\x00"


def test_a_bundle_whose_inclusion_hash_is_respelled_is_malformed() -> None:
    world = World()
    bundle = world.bundle()
    assert verify_bundle(bundle, world.trust(), NOW).grade == "I"
    bad = copy.deepcopy(bundle)
    bad["leaf"]["inclusion"][0] = respelled(bad["leaf"]["inclusion"][0])  # 32 bytes: one "=", two stray bits
    with pytest.raises(BundleRefused) as exc:
        verify_bundle(bad, world.trust(), NOW)
    assert exc.value.code == "bundle_malformed"


def test_a_bundle_whose_record_bytes_are_respelled_is_malformed() -> None:
    world = _padded_world()
    bad = world.bundle()
    bad["record"]["bytes"] = respelled(bad["record"]["bytes"])
    with pytest.raises(BundleRefused) as exc:
        verify_bundle(bad, world.trust(), NOW)
    assert exc.value.code == "bundle_malformed"


@pytest.mark.parametrize("member", ["payload", "sig"])
def test_a_record_envelope_member_respelled_is_not_admissible(member: str) -> None:
    world = World()
    envelope: dict[str, Any] = json.loads(world.raw)
    holder = envelope if member == "payload" else envelope["signatures"][0]
    if not holder[member].endswith("="):
        pytest.skip("this envelope member needs no padding")  # the sig is 64 bytes: always one "="
    holder[member] = respelled(holder[member])
    bad = world.bundle()
    bad["record"]["bytes"] = base64.b64encode(json.dumps(envelope).encode()).decode()
    with pytest.raises(BundleRefused) as exc:
        verify_bundle(bad, world.trust(), NOW)
    assert exc.value.code == "bundle_record_invalid"


def test_a_receipt_map_proof_whose_sibling_is_respelled_is_malformed() -> None:
    m = ReceiptMap()
    keys = [map_key("00" * 32, f"p-{i}", "execute") for i in range(4)]
    for i, k in enumerate(keys):
        m.insert(k, i, bytes([i]) * 32)
    proof = m.prove(keys[0])
    assert proof.holds(m.root()) is not None
    doc = proof.to_doc()
    siblings = [i for i, s in enumerate(doc["siblings"]) if s is not None]
    assert siblings, "the proof has a non-empty sibling"
    bad = copy.deepcopy(doc)
    bad["siblings"][siblings[0]] = respelled(bad["siblings"][siblings[0]])
    with pytest.raises(MapError):
        Proof.from_doc(bad)
