"""Witness ledger checks across broker intervals, over committed records."""

from __future__ import annotations

from pathlib import Path

import pytest
from fixture_records import load, materialize, pinned_keys, signing_keys
from probity_observer import LedgerWitness, VerificationError, verify_ledger_receipts, verify_packet
from probity_observer.history import append_history
from probity_observer.ledger import read_ledger


def test_two_intervals_share_one_checkable_history(tmp_path: Path) -> None:
    record = materialize("ledger-two-intervals", tmp_path)
    observer, witness = pinned_keys(record)
    packet_a, packet_b = (load(record / interval / "packet.json") for interval in ("a", "b"))
    for interval, packet in (("a", packet_a), ("b", packet_b)):
        assert verify_packet(packet, record / interval / "history.jsonl", observer, witness)["witnessScope"] == "PEER"
    ledger = record / "ledger.jsonl"
    first_head = packet_a["checkpoint"]["ledgerReceipt"]["hash"]
    assert verify_ledger_receipts(ledger, packet_a["startCheckpoint"], packet_a["checkpoint"], witness) == {
        "count": 4, "head": packet_b["checkpoint"]["ledgerReceipt"]["hash"],
    }
    assert verify_ledger_receipts(ledger, packet_b["startCheckpoint"], packet_b["checkpoint"], witness, first_head)["count"] == 4
    assert {receipt["intervalId"] for receipt in read_ledger(ledger, witness)} == {"a", "b"}


def test_terminal_fork_is_refused(tmp_path: Path) -> None:
    record = materialize("ledger-one-write", tmp_path)
    observer_key, witness_key = signing_keys(record)
    fork = tmp_path / "fork.jsonl"
    fork.write_bytes((record / "history.jsonl").read_bytes().splitlines(keepends=True)[0])
    append_history(fork, {"kind": "denied", "requestId": "x", "path": "/work/x", "reason": "test"})
    append_history(fork, {"kind": "seal", "claimDigest": "0" * 64})
    witness = LedgerWitness(record / "ledger.jsonl", witness_key, observer_key.public_hex)
    with pytest.raises(VerificationError, match="already has a terminal head"):
        witness.checkpoint(fork)


def test_truncation_and_wrong_receipt_fail_against_pinned_head(tmp_path: Path) -> None:
    record = materialize("ledger-one-interval", tmp_path)
    _, witness = pinned_keys(record)
    packet = load(record / "packet.json")
    ledger = record / "ledger.jsonl"
    published_head = packet["checkpoint"]["ledgerReceipt"]["hash"]
    original = ledger.read_bytes()
    ledger.write_bytes(original.splitlines()[0] + b"\n")
    with pytest.raises(VerificationError, match="absent from the ledger"):
        verify_ledger_receipts(ledger, packet["startCheckpoint"], packet["checkpoint"], witness)
    with pytest.raises(VerificationError, match="pinned head"):
        verify_ledger_receipts(ledger, packet["startCheckpoint"], packet["startCheckpoint"], witness, published_head)
    ledger.write_bytes(original.replace(b'"phase":"terminal"', b'"phase":"begin"', 1))
    with pytest.raises(VerificationError, match="digest differs"):
        read_ledger(ledger, witness)


def test_interrupted_write_retains_ledger_receipts(tmp_path: Path) -> None:
    record = materialize("ledger-recovered", tmp_path)
    _, witness = pinned_keys(record)
    recovered = load(record / "incomplete.json")
    assert recovered["status"] == "incomplete"
    assert verify_ledger_receipts(record / "ledger.jsonl", recovered["startCheckpoint"], recovered["checkpoint"], witness)["count"] == 2
