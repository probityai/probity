"""Native signal cleanup and exclusive publication before ready-file visibility."""
from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from probity_pydantic_recovery import common


def test_ready_publication_exposes_only_complete_private_bytes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The target's readiness poll cannot see the intermediate JSON write."""
    ready = tmp_path / "ready.json"
    original = os.link
    publication = []

    def before_publish(source: str, destination: Path) -> None:
        assert not ready.exists()
        assert common.load(Path(source)) == {"ready": True, "payload": "x" * 65536}
        assert stat.S_IMODE(Path(source).stat().st_mode) == 0o600
        publication.append(source)
        original(source, destination)

    monkeypatch.setattr(common.os, "link", before_publish)
    common.write(ready, {"ready": True, "payload": "x" * 65536})
    assert len(publication) == 1 and common.load(ready)["ready"] is True
    assert list(tmp_path.iterdir()) == [ready]


def test_exclusive_publication_preserves_existing_bytes_and_cleans_temp(tmp_path: Path) -> None:
    ready = tmp_path / "ready.json"
    ready.write_bytes(b"retained original")
    with pytest.raises(FileExistsError):
        common.write(ready, {"changed": True})
    assert ready.read_bytes() == b"retained original"
    assert list(tmp_path.iterdir()) == [ready]
