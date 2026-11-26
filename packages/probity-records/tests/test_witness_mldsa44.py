"""ML-DSA-44 checkpoint cosignatures (c2sp.org/tlog-cosignature, type 0x06), held to an independent
implementation.

vectors/shared/mldsa44-xcheck.json was written by running filippo.io/torchwood (a c2sp.org/tlog-cosignature
implementation by a C2SP maintainer) on Go's crypto/mldsa: keys derived from fixed seeds, checkpoints torchwood
cosigned, and torchwood's verdict on notes another implementation signed, including tampered ones. This module
must derive the same vkeys and key ids, accept every cosignature torchwood made, and reach torchwood's verdict
on every other note.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA44PrivateKey
from probity_records import witness as w

VECTORS = json.loads((Path(__file__).resolve().parents[1] / "vectors" / "shared" / "mldsa44-xcheck.json").read_text())
ORIGIN = "example.com/log"


def test_the_vectors_come_from_torchwood() -> None:
    assert VECTORS["source"].startswith("filippo.io/torchwood@")
    assert len(VECTORS["torchwood_signed"]) == 9 and len(VECTORS["ours_checked_by_torchwood"]) == 5


@pytest.mark.parametrize("key", VECTORS["keys"], ids=lambda k: k["name"])
def test_vkeys_and_key_ids_equal_torchwoods(key: dict[str, object]) -> None:
    seed = bytes.fromhex(str(key["seed_hex"]))
    private = MLDSA44PrivateKey.from_seed_bytes(seed) if key["type"] == 6 else Ed25519PrivateKey.from_private_bytes(seed)
    assert w.vkey(str(key["name"]), int(str(key["type"])), private.public_key()).encode() == key["vkey"]
    assert w.parse_vkey(str(key["vkey"])).sig_type == key["type"]


@pytest.mark.parametrize("signed", VECTORS["torchwood_signed"], ids=lambda s: f"{s['cosigner']}:{s['text'][-12:-1]}")
def test_every_cosignature_torchwood_made_verifies(signed: dict[str, str]) -> None:
    keys = {k["name"]: w.parse_vkey(k["vkey"]) for k in VECTORS["keys"]}
    parsed = w.parse_note(signed["note"])
    assert parsed.text == signed["text"] and len(parsed.sigs) == 1
    key = keys[signed["cosigner"]]
    assert parsed.sigs[0].key_id == key.id
    assert isinstance(w.verify_line(key, parsed.text, parsed.sigs[0]), int)


@pytest.mark.parametrize("entry", VECTORS["ours_checked_by_torchwood"], ids=lambda e: e["label"])
def test_torchwoods_verdict_on_every_other_note(entry: dict[str, object]) -> None:
    assert entry["torchwood_accepts"] is entry["expected"]
    key = w.parse_vkey(str(entry["vkey"]))
    parsed = w.parse_note(str(entry["note"]))
    if entry["expected"]:
        assert isinstance(w.verify_line(key, parsed.text, parsed.sigs[0]), int)
    else:
        with pytest.raises(w.NoteError):
            w.verify_line(key, parsed.text, parsed.sigs[0])


def test_an_ml_dsa_cosignature_covers_no_extension_line() -> None:
    assert "extension" in VECTORS["torchwood_refuses_to_sign"][0]
    with pytest.raises(w.NoteError, match="^checkpoint_extensions_unsigned"):
        w.cosign_mldsa(f"{ORIGIN}\n7\n" + "A" * 43 + "=\nextension line\n", "w", MLDSA44PrivateKey.generate(), 1)


def test_a_line_of_one_type_never_verifies_under_the_other() -> None:
    text = w.Checkpoint(ORIGIN, 3, w.leaf_hash(b"x")).text()
    pq, ed = MLDSA44PrivateKey.generate(), Ed25519PrivateKey.generate()
    with pytest.raises(w.NoteError):
        w.verify_line(w.vkey("w", w.SIG_COSIGNATURE_V1, ed.public_key()), text, w.cosign_mldsa(text, "w", pq, 5))
    with pytest.raises(w.NoteError):
        w.verify_line(w.vkey("w", w.SIG_MLDSA44, pq.public_key()), text, w.cosign(text, "w", ed, 5))
    with pytest.raises(w.NoteError, match="^vkey_type_mismatch"):
        w.vkey("w", w.SIG_MLDSA44, ed.public_key())
    with pytest.raises(w.NoteError, match="^vkey_type_mismatch"):
        w.vkey("w", w.SIG_COSIGNATURE_V1, pq.public_key())


def _hybrid(now: int) -> tuple[str, str, str, MLDSA44PrivateKey]:
    """A checkpoint signed by the log (Ed25519 and its own ML-DSA-44 line) and cosigned by an ML-DSA-44 witness
    and an Ed25519 witness; returns the note, the policy and the witness's ML-DSA-44 vkey."""
    log_ed, log_pq = Ed25519PrivateKey.generate(), MLDSA44PrivateKey.generate()
    wit_pq, wit_ed = MLDSA44PrivateKey.generate(), Ed25519PrivateKey.generate()
    text = w.Checkpoint(ORIGIN, 3, w.leaf_hash(b"x")).text()
    lines = (w.SigLine(ORIGIN, w.note_key_id(ORIGIN, w.SIG_ED25519, w._raw(log_ed.public_key())),
                       log_ed.sign(text.encode())),
             w.cosign_mldsa(text, ORIGIN, log_pq, now),
             w.cosign_mldsa(text, "w.example/pq", wit_pq, now),
             w.cosign(text, "w.example/ed", wit_ed, now))
    pq_vkey = w.vkey("w.example/pq", w.SIG_MLDSA44, wit_pq.public_key()).encode()
    policy = "\n".join([
        f"log {w.vkey(ORIGIN, w.SIG_ED25519, log_ed.public_key()).encode()}",
        f"log {w.vkey(ORIGIN, w.SIG_MLDSA44, log_pq.public_key()).encode()}",
        f"witness pq {pq_vkey}",
        f"witness ed {w.vkey('w.example/ed', w.SIG_COSIGNATURE_V1, wit_ed.public_key()).encode()}",
        "group both all pq ed", "quorum both", ""])
    return w.Note(text, lines).encode(), policy, pq_vkey, log_pq


def test_a_hybrid_checkpoint_verifies_and_reports_its_post_quantum_lines() -> None:
    note, policy_text, _, _ = _hybrid(1_800_000_000)
    policy = w.parse_policy(policy_text)
    verified = w.verify_note(note, policy, 1_800_000_000, 3600)
    assert verified.log_types == frozenset({w.SIG_ED25519, w.SIG_MLDSA44})
    assert set(verified.cosigned_at) == {"pq", "ed"} and verified.post_quantum(policy) == {"pq"}


def test_a_tampered_ml_dsa_line_under_a_pinned_key_rejects_the_note() -> None:
    note, policy_text, _, _ = _hybrid(1_800_000_000)
    parsed = w.parse_note(note)
    pq_line = parsed.sigs[2]
    flipped = w.SigLine(pq_line.name, pq_line.key_id, pq_line.sig[:-1] + bytes([pq_line.sig[-1] ^ 1]))
    tampered = w.Note(parsed.text, (*parsed.sigs[:2], flipped, parsed.sigs[3])).encode()
    with pytest.raises(w.NoteError, match="^note_signature_invalid"):
        w.verify_note(tampered, w.parse_policy(policy_text), 1_800_000_000, 3600)


def test_the_log_ml_dsa_line_alone_authenticates_the_log_but_never_counts_as_a_witness() -> None:
    note, policy_text, _, _ = _hybrid(1_800_000_000)
    parsed = w.parse_note(note)
    pq_only = w.Note(parsed.text, parsed.sigs[1:]).encode()  # the Ed25519 log line removed
    verified = w.verify_note(pq_only, w.parse_policy(policy_text), 1_800_000_000, 3600)
    assert verified.log_types == frozenset({w.SIG_MLDSA44}) and set(verified.cosigned_at) == {"pq", "ed"}
    without_pq_witness = w.Note(parsed.text, (parsed.sigs[0], parsed.sigs[1], parsed.sigs[3])).encode()
    with pytest.raises(w.NoteError, match="^witness_quorum_not_met"):
        w.verify_note(without_pq_witness, w.parse_policy(policy_text), 1_800_000_000, 3600)


def test_policy_types_by_role() -> None:
    ed = Ed25519PrivateKey.generate()
    pq = MLDSA44PrivateKey.generate()
    with pytest.raises(w.NoteError, match="^policy_key_type"):
        w.parse_policy(f"witness a {w.vkey('a', w.SIG_ED25519, ed.public_key()).encode()}\nquorum a\n")
    with pytest.raises(w.NoteError, match="^policy_key_type"):
        w.parse_policy(f"log {w.vkey(ORIGIN, w.SIG_COSIGNATURE_V1, ed.public_key()).encode()}\nquorum none\n")
    assert w.parse_policy(f"witness a {w.vkey('a', w.SIG_MLDSA44, pq.public_key()).encode()}\nquorum a\n")
    bad = base64.b64encode(bytes([w.SIG_MLDSA44]) + bytes(32)).decode()
    with pytest.raises(w.NoteError, match="^vkey_key_length:type 0x06 carries a 1312-byte key"):
        w.parse_vkey(f"a+00000000+{bad}")
