"""Committed observer records for tests that check public verifiers without a producer.

Each directory under ``fixtures/records`` was written once by the producer the operator's
runtime runs; ``MANIFEST.json`` names the source commit and what each record holds. A test
copies a record into its own temporary directory before mutating it.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from probity_observer.crypto import SigningKey, strict_loads

RECORDS = Path(__file__).resolve().parent / "fixtures" / "records"


def materialize(name: str, destination: Path) -> Path:
    """Copy one record and restore the empty workspaces git cannot retain."""
    target = destination / name
    shutil.copytree(RECORDS / name, target)
    for history in (target, *(child for child in target.iterdir() if child.is_dir())):
        if (history / "history.jsonl").is_file():
            (history / "workspace").mkdir(exist_ok=True)
    return target


def load(path: Path) -> Any:
    """Read one canonical record file."""
    return strict_loads(path.read_bytes())


def pinned_keys(directory: Path) -> tuple[str, str]:
    """Return the observer and witness public keys a consumer pins for a record."""
    keys = load(directory / "trusted-keys.json")
    return keys["observer"], keys["witness"]


def signing_keys(directory: Path) -> tuple[SigningKey, SigningKey]:
    """Return the record's test-only observer and witness signers for refusal controls."""
    seeds = load(directory / "test-signing-seeds.json")
    return tuple(SigningKey(Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seeds[role]))) for role in ("observer", "witness"))


def manifest() -> dict[str, Any]:
    """Return the record manifest."""
    return json.loads((RECORDS / "MANIFEST.json").read_text(encoding="ascii"))
