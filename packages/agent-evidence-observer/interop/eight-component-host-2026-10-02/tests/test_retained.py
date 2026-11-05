"""Controls over the retained host run, read with public observer code only."""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest
from probity_observer.crypto import VerificationError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import verify_retained  # noqa: E402


@pytest.fixture
def copied(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the verifier at a private copy so one mutation never reaches the retained bytes."""
    root = tmp_path / "fresh-completed"
    shutil.copytree(verify_retained.RETAINED, root)
    monkeypatch.setattr(verify_retained, "RETAINED", root)
    return root


def edit(root: Path, name: str, change) -> None:
    """Rewrite one retained JSON member after applying a change."""
    value = json.loads((root / name).read_bytes())
    change(value)
    (root / name).write_text(json.dumps(value))


def test_retained_run_verifies() -> None:
    """The committed run passes both checks."""
    assert verify_retained.main() == 0


def test_every_gate_stream_is_pinned_by_its_process_record(copied: Path) -> None:
    """A changed stream byte is reported with the stream's name."""
    (copied / "atlas.stdout").write_bytes((copied / "atlas.stdout").read_bytes() + b" ")
    assert verify_retained.stream_failures() == ["atlas.stdout"]


def test_native_effect_report_equals_retained_gate_output() -> None:
    """The public reader reproduces the retained effect gate output exactly."""
    assert verify_retained.effect_report() == (verify_retained.RETAINED / "verify-effect.stdout").read_bytes()


@pytest.mark.parametrize("member", ["contentHex", "revision"])
def test_changed_readback_is_refused(copied: Path, member: str) -> None:
    """Native bytes outside the signed receipt cannot be altered."""
    def change(config: dict) -> None:
        config["readback"][member] = "00" if member == "contentHex" else 2
    edit(copied, "verify-effect.config.json", change)
    with pytest.raises(VerificationError):
        verify_retained.effect_report()


def test_wrong_service_key_is_refused(copied: Path) -> None:
    """The receipt is authenticated under the host-selected service key only."""
    def change(config: dict) -> None:
        config["policy"]["publicKeys"]["service"] = config["policy"]["publicKeys"]["issuer"]
    edit(copied, "verify-effect.config.json", change)
    with pytest.raises(VerificationError):
        verify_retained.effect_report()


def test_expired_grant_is_refused(copied: Path) -> None:
    """The grant is read at the host clock, so a later clock refuses the effect."""
    edit(copied, "verify-effect.config.json", lambda config: config.update(currentTime="2026-10-03T12:00:10Z"))
    with pytest.raises(VerificationError):
        verify_retained.effect_report()
