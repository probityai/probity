"""Mutation controls for the public protected-action reader over a copy of the retained packet."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from probity_observer.crypto import VerificationError

from probity_protected_operator import reader

NATIVE = Path(__file__).resolve().parent / "retained" / "native"


@pytest.fixture
def packet(tmp_path: Path) -> Path:
    """A private copy of the retained protected-action packet."""
    destination = tmp_path / "native"
    shutil.copytree(NATIVE, destination)
    return destination


class TestProtectedReader:
    class TestPassingCases:
        def test_retained_packet_replays_to_the_retained_report(self) -> None:
            expected = (NATIVE.parent / "protected-reader-report.json").read_bytes()
            assert reader.encode(reader.read(NATIVE)) == expected

        def test_only_admitted_cases_replay_the_dispatch_relation(self) -> None:
            cases = reader.read(NATIVE)["cases"]
            verified = {name for name, case in cases.items() if any(b["dispatchBundleVerified"] for b in case["bundles"])}
            assert verified == {"completion", "first-workload-reply-lost"}

    class TestFailingCases:
        @pytest.mark.parametrize("name", ["authorization.jsonl", "witness-ledger.jsonl", "packet.json"])
        def test_changed_bundle_file_refuses(self, packet: Path, name: str) -> None:
            path = packet / "cases" / "completion" / "bundle" / name
            path.write_bytes(path.read_bytes() + b"\n")
            with pytest.raises(VerificationError):
                reader.read(packet)

        def test_missing_case_refuses(self, packet: Path) -> None:
            shutil.rmtree(packet / "cases" / "target-crash-after-effect")
            with pytest.raises(VerificationError, match="case population differs"):
                reader.read(packet)

        def test_changed_candidate_head_refuses(self, packet: Path) -> None:
            path = packet / "cases" / "completion" / "candidate-heads.json"
            path.write_bytes(path.read_bytes().replace(b'"count":2', b'"count":1', 1))
            with pytest.raises(VerificationError):
                reader.read(packet)

        def test_failed_run_report_refuses(self, packet: Path) -> None:
            path = packet / "report.json"
            path.write_bytes(path.read_bytes().replace(b'"status":"passed"', b'"status":"failed"', 1))
            with pytest.raises(VerificationError, match="run report differs"):
                reader.read(packet)
