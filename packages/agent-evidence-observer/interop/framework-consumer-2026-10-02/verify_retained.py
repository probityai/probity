"""Verify the retained framework packets with public code only.

Extracts each retained archive, runs the framework-free readers over its packets with the
retained pins and the withheld-source list, and exits 0 only if every reader report equals
the report bytes the producing run retained and no archive holds a producer source that
``WITHHELD-SOURCES.json`` lists as omitted.
"""

from __future__ import annotations

import json
import sys
import tempfile
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
INTEROP = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(INTEROP / "langgraph-ticket-2026-10-02"))
sys.path.insert(0, str(INTEROP / "pydantic-ai-native-2026-10-02" / "src"))

from durable_reader import verify_saved as verify_durable  # noqa: E402
from lg_common import decode, withheld_in  # noqa: E402
from lg_reader import verify_saved as verify_langgraph  # noqa: E402
from probity_pydantic import reader as pydantic_reader  # noqa: E402
from probity_pydantic_historical_cli import RETAINED_FRAMEWORK_VERSION  # noqa: E402

RETAINED = HERE / "retained"
WITHHELD = RETAINED / "WITHHELD-SOURCES.json"
def verify_pydantic(packet: Path, pins: dict, withheld: dict[str, str]) -> dict:
    """Read the retained Pydantic AI packet as the installed command does."""
    pydantic_reader.VERSION = RETAINED_FRAMEWORK_VERSION
    return pydantic_reader.verify_saved(packet, pins, withheld)


PACKETS = (
    ("langgraph.zip", "fresh-run", verify_langgraph),
    ("langgraph-durable.zip", "fresh-run", verify_langgraph),
    ("langgraph-durable.zip", "durable-run", verify_durable),
    ("pydantic.zip", "fresh-run/packet", verify_pydantic),
)


def withheld_present(archive: Path, listed: dict[str, str]) -> list[str]:
    """Names inside an archive that the withheld-source list says were omitted."""
    with zipfile.ZipFile(archive) as bundle:
        names = set(bundle.namelist())
    return sorted(name for name in listed if name.removeprefix(archive.name + "/") in names)


def check(archive: Path, packet_dir: str, verify, scratch: Path) -> bool:
    """Replay one packet; true when the report equals the retained report bytes."""
    root = scratch / archive.name
    if not root.exists():
        with zipfile.ZipFile(archive) as bundle:
            bundle.extractall(root)
    packet = root / packet_dir
    withheld = withheld_in(WITHHELD, archive.name + "/" + packet_dir + "/")
    report = verify(packet, decode((packet / "consumer-pins.json").read_bytes()), withheld)
    return report == json.loads((packet / "report.json").read_bytes())


def main() -> int:
    listed = withheld_in(WITHHELD, "")
    kept = [name for archive in sorted({a for a, _, _ in PACKETS}) for name in withheld_present(RETAINED / archive, listed)]
    ok = not kept
    with tempfile.TemporaryDirectory() as scratch:
        for archive, packet_dir, verify in PACKETS:
            ok = check(RETAINED / archive, packet_dir, verify, Path(scratch)) and ok
    print("retained reports " + ("match" if ok else "DIFFER"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
