"""Offline checks of retained workload runs, over committed records."""

from __future__ import annotations

from pathlib import Path

import pytest
from fixture_records import load, materialize, pinned_keys
from probity_observer import VerificationError
from probity_observer.crypto import canonical, strict_loads
from probity_observer.workload import verify_workload_bundle


def checked(name: str, tmp_path: Path) -> tuple[Path, dict]:
    record = materialize(name, tmp_path)
    report = verify_workload_bundle(record, *pinned_keys(record))
    assert report == load(record / "workload-report.json")
    return record, report


def test_host_counts_effects_without_trusting_stdout(tmp_path: Path) -> None:
    record, report = checked("workload-completed", tmp_path)
    assert report["status"] == "completed"
    assert report["channelCounts"] == {"accepted": 1, "replayed": 1, "denied": 1, "knownGaps": 0}
    assert (record / "workspace/result").read_bytes() == b"effect"
    assert b"I did nothing" in (record / "workload-stdout.bin").read_bytes()


@pytest.mark.parametrize("name", ["workload-no-effect", "workload-failed-child"])
def test_no_effect_or_failed_child_is_incomplete(tmp_path: Path, name: str) -> None:
    record, report = checked(name, tmp_path)
    assert report["status"] == "incomplete"
    assert not (record / "packet.json").exists()


def test_gap_after_an_effect_keeps_the_interval_incomplete(tmp_path: Path) -> None:
    _, report = checked("workload-gap", tmp_path)
    assert report["status"] == "incomplete"
    assert report["channelCounts"]["accepted"] == 1
    assert report["channelCounts"]["knownGaps"] == 1


def test_direct_workspace_change_keeps_the_interval_incomplete(tmp_path: Path) -> None:
    _, report = checked("workload-direct-change", tmp_path)
    assert report["status"] == "incomplete"
    assert report["channelCounts"]["knownGaps"] == 1


def test_report_and_script_tampering_are_refused(tmp_path: Path) -> None:
    record = materialize("workload-completed", tmp_path)
    pinned = pinned_keys(record)
    recorded = (record / "workload.py").read_bytes()
    (record / "workload.py").write_bytes(recorded + b"# change\n")
    with pytest.raises(VerificationError, match="workload bytes differ"):
        verify_workload_bundle(record, *pinned)
    (record / "workload.py").write_bytes(recorded)
    report_path = record / "workload-report.json"
    report = strict_loads(report_path.read_bytes())
    report["channelCounts"]["accepted"] = 2
    report_path.write_bytes(canonical(report))
    with pytest.raises(VerificationError, match="channel counts differ"):
        verify_workload_bundle(record, *pinned)
