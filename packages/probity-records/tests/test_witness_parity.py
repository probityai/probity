"""C2SP reading rules held by the one implementation every consumer imports: a future-dated cosignature is not
counted (it neither vetoes nor completes a quorum), a tlog policy carries no control byte but tab and newline, and a
cosignature timestamp is a uint64 below 2**63."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from probity_records import witness as w

NOW = 1_800_000_000
ORIGIN = "example.com/log"

def _two_witness_note(late: int) -> tuple[str, w.Policy]:
    log, w1, w2 = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    cp = w.Checkpoint(ORIGIN, 3, b"\x11" * 32)
    text = cp.text()
    log_line = w.SigLine(ORIGIN, w.note_key_id(ORIGIN, w.SIG_ED25519, log.public_key().public_bytes_raw()),
                         log.sign(text.encode()))
    lines = (log_line, w.cosign(text, "w1", w1, NOW), w.cosign(text, "w2", w2, NOW + late))
    policy = w.parse_policy("\n".join([
        f"log {w.vkey(ORIGIN, w.SIG_ED25519, log.public_key()).encode()}",
        f"witness w1 {w.vkey('w1', w.SIG_COSIGNATURE_V1, w1.public_key()).encode()}",
        f"witness w2 {w.vkey('w2', w.SIG_COSIGNATURE_V1, w2.public_key()).encode()}",
        "group any1 any w1 w2", "quorum any1",
    ]) + "\n")  # fmt: skip
    return w.Note(text, lines).encode(), policy


def test_a_future_dated_cosignature_neither_vetoes_nor_completes_a_quorum() -> None:
    """A witness whose clock runs ahead is not counted, so it cannot veto the quorum the other witness meets."""
    note, policy = _two_witness_note(late=301)
    verified = w.verify_note(note, policy, now=NOW, max_age=3600)
    assert set(verified.cosigned_at) == {"w1"}


@pytest.mark.parametrize("byte", ["\x0b", "\x0c", "\r", "\x00", "\x7f"])
def test_a_policy_with_a_control_byte_is_refused(byte: str) -> None:
    with pytest.raises(w.NoteError):
        w.parse_policy(f"# a comment{byte}\nquorum none\n")


@pytest.mark.parametrize("timestamp", [-1, 2**63])
def test_a_cosignature_timestamp_out_of_range_is_refused(timestamp: int) -> None:
    with pytest.raises(w.NoteError):
        w.cosignature_message(timestamp, w.Checkpoint(ORIGIN, 1, b"\x22" * 32).text())
