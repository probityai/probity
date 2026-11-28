"""The walk bounds sit above the measured closure of the locked reader install."""
from __future__ import annotations

import recovery_host as host

# Measured 26 Nov 2026: CPython 3.13 ``python -m venv`` plus
# ``pip install --require-hashes`` of this directory's reader lock, the steps CI
# runs. Re-measure and update these when the reader lock gains a dependency.
MEASURED_FILES = 15197
MEASURED_ENTRIES = 18452
MEASURED_BYTES = 127 * 1024 * 1024
HEADROOM = 1.5


def test_bounds_admit_the_locked_reader_closure_with_headroom() -> None:
    assert host.MAX_INSTALL_FILES >= HEADROOM * MEASURED_FILES
    assert host.MAX_INSTALL_ENTRIES >= HEADROOM * MEASURED_ENTRIES
    assert host.MAX_INSTALL_BYTES >= HEADROOM * MEASURED_BYTES


def test_entry_bound_covers_directories_beside_the_file_bound() -> None:
    assert host.MAX_INSTALL_ENTRIES > host.MAX_INSTALL_FILES


# Measured 26 Nov 2026, same install: the canonical host policy file is 3,524,852 bytes.
MEASURED_POLICY_BYTES = 3524852


def test_policy_file_bound_admits_the_measured_policy_with_headroom() -> None:
    assert host.MAX_POLICY_FILE >= HEADROOM * MEASURED_POLICY_BYTES


def test_read_policy_accepts_headroom_and_refuses_over_the_bound(tmp_path) -> None:
    import pytest
    from probity_observer.crypto import VerificationError

    ok = tmp_path / "ok.json"
    ok.write_bytes(b"x" * int(HEADROOM * MEASURED_POLICY_BYTES))
    assert len(host.read_policy(ok)) == int(HEADROOM * MEASURED_POLICY_BYTES)
    big = tmp_path / "big.json"
    big.write_bytes(b"x" * (host.MAX_POLICY_FILE + 1))
    with pytest.raises(VerificationError, match="policy-file-bound"):
        host.read_policy(big)
