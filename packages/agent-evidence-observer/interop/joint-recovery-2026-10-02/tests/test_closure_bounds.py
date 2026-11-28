"""The walk bounds sit above the measured closure of the locked reader install."""
from __future__ import annotations

import joint_host_gate as host

# Measured 26 Nov 2026: CPython 3.13 ``python -m venv`` plus
# ``pip install --require-hashes`` of this directory's reader lock, the steps CI
# runs. Re-measure and update these when the reader lock gains a dependency.
MEASURED_FILES = 17002
MEASURED_ENTRIES = 20425
MEASURED_BYTES = 180 * 1024 * 1024
HEADROOM = 1.5


def test_bounds_admit_the_locked_reader_closure_with_headroom() -> None:
    assert host.MAX_INSTALL_FILES >= HEADROOM * MEASURED_FILES
    assert host.MAX_INSTALL_ENTRIES >= HEADROOM * MEASURED_ENTRIES
    assert host.MAX_INSTALL_BYTES >= HEADROOM * MEASURED_BYTES


def test_entry_bound_covers_directories_beside_the_file_bound() -> None:
    assert host.MAX_INSTALL_ENTRIES > host.MAX_INSTALL_FILES
