"""The committed original packet verifies with public code and refuses changed copies."""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from probity_observer.crypto import VerificationError, canonical, strict_loads

from probity_pydantic_recovery.common import absent_members, load, sha, withheld_sources, write
from probity_pydantic_recovery.reader import verify_saved

RETAINED = Path(__file__).resolve().parents[1] / "retained"
WITHHELD = withheld_sources(RETAINED / "WITHHELD-SOURCES.json")


@pytest.fixture
def copied(tmp_path: Path) -> tuple[Path, dict]:
    """Copy the retained packet so one control mutates only its own bytes."""
    root = tmp_path / "packet"
    shutil.copytree(RETAINED / "fresh-run", root)
    return root, load(root / "consumer-pins.json")


def reselect(root: Path, pins: dict) -> None:
    """Pin changed bytes again so a control cannot pass on hash drift alone."""
    manifest = load(root / "artifact-manifest.json")
    for name in manifest:
        if (root / name).exists():
            manifest[name] = sha((root / name).read_bytes())
    (root / "artifact-manifest.json").unlink()
    write(root / "artifact-manifest.json", manifest)
    pins["planSha256"] = sha((root / "plan-before-run.json").read_bytes())
    pins["artifactManifestSha256"] = sha((root / "artifact-manifest.json").read_bytes())


def test_retained_report_equals_retained_reader_output() -> None:
    packet = RETAINED / "fresh-run"
    report = verify_saved(packet, load(packet / "consumer-pins.json"), WITHHELD)
    assert canonical(report) + b"\n" == (RETAINED / "host-receipts/reader.stdout").read_bytes()
    assert report["status"] == "verified" and report["providerCalls"] == 0
    assert strict_loads((RETAINED / "host-repeat/reader.stdout").read_bytes()) == report


def test_every_withheld_member_is_pinned_by_the_manifest_and_absent() -> None:
    manifest = load(RETAINED / "fresh-run/artifact-manifest.json")
    assert WITHHELD and all(manifest[name] == digest for name, digest in WITHHELD.items())
    assert all(not (RETAINED / "fresh-run" / name).exists() for name in WITHHELD)


def test_absence_without_a_withheld_record_refuses(copied: tuple[Path, dict]) -> None:
    root, pins = copied
    with pytest.raises(VerificationError, match="^artifact-population$"):
        verify_saved(root, pins, {})


def test_withheld_digest_must_equal_the_manifest_pin(copied: tuple[Path, dict]) -> None:
    root, pins = copied
    name = sorted(WITHHELD)[0]
    with pytest.raises(VerificationError, match="^artifact-population$"):
        verify_saved(root, pins, {**WITHHELD, name: "0" * 64})


def test_present_member_still_matches_byte_for_byte(copied: tuple[Path, dict]) -> None:
    root, pins = copied
    target = root / "permit/processes.json"
    target.write_bytes(target.read_bytes() + b" ")
    with pytest.raises(VerificationError, match="^artifact-hash$"):
        verify_saved(root, pins, WITHHELD)


def test_reselected_semantic_change_is_refused(copied: tuple[Path, dict]) -> None:
    root, pins = copied
    record = load(root / "permit/processes.json")
    record["workers"][0]["returncode"] = 0
    (root / "permit/processes.json").unlink()
    write(root / "permit/processes.json", record)
    reselect(root, pins)
    with pytest.raises(VerificationError, match="^worker-exits$"):
        verify_saved(root, pins, WITHHELD)


def test_absent_members_helper_requires_exact_digest() -> None:
    assert absent_members({"a": "1" * 64}, set(), {"a": "1" * 64}) == {"a"}
    assert absent_members({"a": "1" * 64}, set(), {"a": "2" * 64}) == set()
    assert absent_members({"a": "1" * 64}, {"a"}, {"a": "1" * 64}) == set()
