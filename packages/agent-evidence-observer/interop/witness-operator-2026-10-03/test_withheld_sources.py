"""Source-population rules for a retained copy whose listed source bytes were removed."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from probity_observer.crypto import VerificationError, strict_loads

import verify_retained
from begin_support import RETAINED
from probity_witness_operator import reader
from probity_witness_operator.protocol import sha
from probity_witness_operator.sources import load_withheld, verify_sources

POLICY = strict_loads((RETAINED / "host-policy.json").read_bytes())
RECORD = RETAINED.parent / "WITHHELD-SOURCES.json"


@pytest.fixture
def copy(tmp_path: Path) -> Path:
    """A private copy of the retained tree for mutation controls."""
    destination = tmp_path / "retained"
    shutil.copytree(RETAINED.parent, destination)
    return destination


def _read(root: Path, withheld_path: Path | None = None) -> dict:
    packet = root / "native" / "packet"
    withheld = load_withheld(withheld_path or root / "WITHHELD-SOURCES.json", packet / "source")
    return reader.read(packet, POLICY, withheld)


class TestRetainedCopy:
    class TestPassingCases:
        def test_driver_reproduces_the_retained_report(self) -> None:
            assert verify_retained.main() == 0

        def test_withheld_names_are_selected_and_absent(self) -> None:
            withheld = load_withheld(RECORD, RETAINED / "packet" / "source")
            assert "probity_observer/broker.py" in withheld and "probity_witness_operator/worker.py" in withheld
            assert all(name in POLICY["source"] and not (RETAINED / "packet/source" / name).exists() for name in withheld)
            assert all(POLICY["source"][name] == digest for name, digest in withheld.items())

    class TestFailingCases:
        def test_absent_source_without_a_record_refuses(self, copy: Path) -> None:
            record = json.loads((copy / "WITHHELD-SOURCES.json").read_text())
            del record["native/packet/source/probity_observer/broker.py"]
            (copy / "WITHHELD-SOURCES.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
            with pytest.raises(VerificationError, match="absent without a matching withheld digest"):
                _read(copy)

        def test_absent_source_with_another_digest_refuses(self, copy: Path) -> None:
            record = json.loads((copy / "WITHHELD-SOURCES.json").read_text())
            record["native/packet/source/probity_observer/broker.py"] = "0" * 64
            (copy / "WITHHELD-SOURCES.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
            with pytest.raises(VerificationError, match="absent without a matching withheld digest"):
                _read(copy)

        def test_present_source_must_still_match_when_listed(self, copy: Path) -> None:
            source = copy / "native/packet/source/probity_observer/crypto.py"
            source.write_bytes(source.read_bytes() + b"# changed\n")
            record = json.loads((copy / "WITHHELD-SOURCES.json").read_text())
            record["native/packet/source/probity_observer/crypto.py"] = sha(source.read_bytes())
            (copy / "WITHHELD-SOURCES.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
            with pytest.raises(VerificationError, match="retained source bytes differ"):
                _read(copy)

        def test_extra_source_refuses(self, copy: Path) -> None:
            (copy / "native/packet/source/probity_observer/added.py").write_bytes(b"x = 1\n")
            with pytest.raises(VerificationError, match="retained source population differs"):
                _read(copy)

        def test_unsorted_record_refuses(self, tmp_path: Path) -> None:
            path = tmp_path / "record.json"
            path.write_text(json.dumps({"b/x": "0" * 64, "a/y": "0" * 64}))
            with pytest.raises(VerificationError, match="sorted object"):
                load_withheld(path, tmp_path / "a")

        def test_without_a_record_the_retained_copy_refuses(self) -> None:
            with pytest.raises(VerificationError, match="absent without a matching withheld digest"):
                reader.read(RETAINED / "packet", POLICY)

        def test_changed_case_bytes_refuse(self, copy: Path) -> None:
            ledger = copy / "native/packet/permit/ledger.jsonl"
            ledger.write_bytes(ledger.read_bytes() + b"\n")
            with pytest.raises(VerificationError):
                _read(copy)
