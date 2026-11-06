"""Re-record the source selections of both reader builders from a package checkout.

Run ``python record_contracts.py PACKAGE_DIR`` after any change to a selected file. It rewrites
the ``source_files`` digests of ``FRAMEWORK-CONSUMER-CONTRACT-2026-10-02.json`` and
``FRAMEWORK-DURABLE-CONSUMER-CONTRACT-2026-10-02.json`` and leaves every other field alone.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
LANGGRAPH = "interop/langgraph-ticket-2026-10-02/"
PYDANTIC = "interop/pydantic-ai-native-2026-10-02/src/probity_pydantic/"
PROFILE = "interop/framework-consumer-2026-10-02/"
OBSERVER_FILES = ("LICENSE", "README.md", "pyproject.toml")
LOCK = PROFILE + "FRAMEWORK-CONSUMER-REQUIREMENTS-2026-10-02.lock"

SELECTIONS = {
    "FRAMEWORK-CONSUMER-CONTRACT-2026-10-02.json": (
        LANGGRAPH + "lg_common.py",
        LANGGRAPH + "lg_reader.py",
        PYDANTIC + "__init__.py",
        PYDANTIC + "contract.py",
        PYDANTIC + "reader.py",
        PROFILE + "FRAMEWORK-LANGGRAPH-READER-2026-10-02.toml",
        PROFILE + "FRAMEWORK-PYDANTIC-READER-2026-10-02.toml",
        PROFILE + "probity_langgraph_reader_cli.py",
        PROFILE + "probity_pydantic_historical_cli.py",
        LOCK,
    ),
    "FRAMEWORK-DURABLE-CONSUMER-CONTRACT-2026-10-02.json": (
        LANGGRAPH + "lg_common.py",
        LANGGRAPH + "lg_reader.py",
        LANGGRAPH + "durable_reader.py",
        PROFILE + "FRAMEWORK-LANGGRAPH-DURABLE-READER-2026-10-02.toml",
        PROFILE + "probity_langgraph_reader_cli.py",
        PROFILE + "probity_langgraph_durable_reader_cli.py",
        PROFILE + "FRAMEWORK-DURABLE-CONSUMER-BUILD-2026-10-02.sh",
        LOCK,
    ),
}


def observer_sources(package: Path) -> list[str]:
    """Every file of the observer package that a wheel is built from."""
    tree = (package / "src/probity_observer").rglob("*")
    return sorted(p.relative_to(package).as_posix() for p in tree if p.is_file() and "__pycache__" not in p.parts)


def pin(raw: bytes) -> dict[str, str]:
    """Digests recorded for one selected file."""
    blob = b"blob " + str(len(raw)).encode() + b"\0" + raw
    return {"git_blob_sha1": hashlib.sha1(blob).hexdigest(), "sha256": hashlib.sha256(raw).hexdigest()}  # noqa: S324


def main() -> int:
    """Rewrite both contracts' ``source_files`` from the package at ``argv[1]``."""
    package = Path(sys.argv[1]).resolve(strict=True)
    for name, extra in SELECTIONS.items():
        contract = json.loads((HERE / name).read_bytes())
        names = [*OBSERVER_FILES, *observer_sources(package), *extra]
        contract["source_files"] = {n: pin((package / n).read_bytes()) for n in sorted(names)}
        (HERE / name).write_text(json.dumps(contract, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
