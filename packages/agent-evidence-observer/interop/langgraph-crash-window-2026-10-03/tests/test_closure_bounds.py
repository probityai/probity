"""The host's closure node bound sits above the measured closure of the locked reader install."""
from __future__ import annotations

import pytest

import consume_installed as consumer
from probity_observer.crypto import VerificationError, canonical

# Measured 26 Nov 2026: CPython 3.13 ``python -m venv`` plus
# ``pip install --require-hashes`` of the joint reader lock, the steps CI runs.
# Re-measure and update these when the reader lock gains a dependency.
MEASURED_NODES = 67927
MEASURED_BYTES = 3849504
HEADROOM = 1.5


def closure(files: int) -> dict:
    """Shape of a reader closure: each file is a dict of four scalars."""
    entry = {"bytes": 1, "sha256": "0" * 64, "mode": 33188, "symlink": None}
    return {"environment": "e", "files": {f"f{n}": dict(entry) for n in range(files)}}


def test_node_bound_admits_the_locked_reader_closure_with_headroom() -> None:
    assert consumer.MAX_CLOSURE_NODES >= HEADROOM * MEASURED_NODES


def test_load_closure_accepts_a_closure_at_headroom_times_the_measurement(tmp_path) -> None:
    files = int(HEADROOM * MEASURED_NODES / 6)
    (tmp_path / "c.json").write_bytes(canonical(closure(files)))
    assert len(consumer.load_closure(tmp_path, "c.json")["files"]) == files
    assert HEADROOM * MEASURED_BYTES < 16 * 1024 * 1024


def test_load_closure_refuses_a_closure_over_the_bound(tmp_path) -> None:
    (tmp_path / "c.json").write_bytes(canonical(closure(consumer.MAX_CLOSURE_NODES // 5)))
    with pytest.raises(VerificationError, match="closure-json-bound"):
        consumer.load_closure(tmp_path, "c.json")
