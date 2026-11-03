"""Offline checks of retained boundary runs, over committed records."""

from __future__ import annotations

from pathlib import Path

import pytest
from fixture_records import load, materialize, pinned_keys
from probity_observer import SigningKey, VerificationError, verify_packet
from probity_observer.history import read_history
from probity_observer.isolation import verify_boundary_bundle
from probity_observer.verify import verify_incomplete


class TestBoundaryRecords:
    class TestPassingCases:
        def test_host_checks_broker_events_and_retains_peer(self, tmp_path: Path) -> None:
            record = materialize("boundary-passed", tmp_path)
            observer, witness = pinned_keys(record)
            report = load(record / "boundary-report.json")
            claim = verify_packet(load(record / "packet.json"), record / "history.jsonl", observer, witness, record / "workspace")
            assert report["status"] == "probe-passed"
            assert report["evidence_vantage"] == "artifact"
            assert claim["witnessScope"] == report["witnessScope"] == "PEER"
            assert claim["authorityDigest"] == read_history(record / "history.jsonl")[0]["event"]["commitment"]["preimage"]["authorityDigest"]
            assert verify_boundary_bundle(record, observer, witness)["status"] == "probe-passed"

    class TestFailingCases:
        def test_failed_socket_setup_is_a_witnessed_incomplete_interval(self, tmp_path: Path) -> None:
            record = materialize("boundary-socket-failed", tmp_path)
            observer, witness = pinned_keys(record)
            report = load(record / "boundary-report.json")
            incomplete = load(record / "incomplete.json")
            event = verify_incomplete(record / "history.jsonl", incomplete["startCheckpoint"], incomplete["checkpoint"], observer, witness)
            assert report["status"] == "incomplete"
            assert report["evidence_vantage"] == "artifact"
            assert report["witnessScope"] == "PEER"
            assert event["reason"] == "isolation setup failed"
            assert b"socket denied" in (record / "probe-stderr.bin").read_bytes()
            assert not (record / "packet.json").exists()
            assert verify_boundary_bundle(record, observer, witness)["status"] == "incomplete"

        def test_pinned_reader_rejects_changed_probe_and_result(self, tmp_path: Path) -> None:
            record = materialize("boundary-passed", tmp_path)
            observer, witness = pinned_keys(record)
            with pytest.raises(VerificationError, match="boundary attestation differs"):
                verify_boundary_bundle(record, SigningKey.generate().public_hex, witness)
            script = record / "agent-probe.py"
            original = script.read_bytes()
            script.write_bytes(original + b"\n")
            with pytest.raises(VerificationError, match="probe bytes differ"):
                verify_boundary_bundle(record, observer, witness)
            script.write_bytes(original)
            stdout = record / "probe-stdout.bin"
            stdout.write_bytes(stdout.read_bytes() + b"x")
            with pytest.raises(VerificationError, match="raw probe output differs"):
                verify_boundary_bundle(record, observer, witness)

        def test_incomplete_reader_rejects_unknown_intermediate_event(self, tmp_path: Path) -> None:
            record = materialize("abort-unknown-event", tmp_path)
            incomplete = load(record / "incomplete.json")
            with pytest.raises(VerificationError, match="unknown event kind"):
                verify_incomplete(record / "history.jsonl", incomplete["startCheckpoint"], incomplete["checkpoint"], *pinned_keys(record))

        @pytest.mark.parametrize("name", ["boundary-missing-event", "boundary-network-open"])
        def test_missing_broker_event_or_refusal_aborts(self, tmp_path: Path, name: str) -> None:
            record = materialize(name, tmp_path)
            observer, witness = pinned_keys(record)
            incomplete = load(record / "incomplete.json")
            assert load(record / "boundary-report.json")["status"] == "incomplete"
            assert incomplete["event"]["reason"] == "boundary probes failed"
            assert not (record / "packet.json").exists()
            verify_incomplete(record / "history.jsonl", incomplete["startCheckpoint"], incomplete["checkpoint"], observer, witness)
            assert verify_boundary_bundle(record, observer, witness)["status"] == "incomplete"
