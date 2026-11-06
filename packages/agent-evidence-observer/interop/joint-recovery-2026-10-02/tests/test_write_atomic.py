"""A polling reader must never observe a partially written readiness file."""
from __future__ import annotations

import threading
from pathlib import Path

import pytest
from probity_observer.crypto import strict_loads

from joint_common import write_atomic


def test_member_is_complete_the_moment_it_exists(tmp_path: Path) -> None:
    """Poll while a large member is published; every observation parses whole."""
    path = tmp_path / "ready-1.json"
    value = {"pid": 1, "url": "http://127.0.0.1:1", "initial": ["x" * 64] * 20000}
    stop = threading.Event()
    seen: list[bytes] = []

    def poll() -> None:
        while not stop.is_set():
            if path.exists():
                seen.append(path.read_bytes())
                return

    reader = threading.Thread(target=poll)
    reader.start()
    write_atomic(path, value)
    stop.set()
    reader.join(timeout=10)
    assert seen, "reader never observed the member"
    assert strict_loads(seen[0]) == value


def test_no_temporary_left_and_existing_member_refused(tmp_path: Path) -> None:
    path = tmp_path / "refusal-1.json"
    write_atomic(path, {"a": 1})
    assert sorted(p.name for p in tmp_path.iterdir()) == ["refusal-1.json"]
    with pytest.raises(FileExistsError):
        write_atomic(path, {"a": 2})
    assert strict_loads(path.read_bytes()) == {"a": 1}


def test_target_publishes_readiness_atomically() -> None:
    source = Path(__file__).resolve().parent.parent.joinpath("joint_target.py").read_text()
    assert 'write_atomic(Path(selected["readyFile"])' in source
    assert 'write_atomic(Path(selected["refusalFile"])' in source
