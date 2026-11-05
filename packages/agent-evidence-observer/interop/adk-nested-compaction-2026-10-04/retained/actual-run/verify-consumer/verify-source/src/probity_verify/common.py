"""Shared validation and artifact binding for every claim adapter."""

from __future__ import annotations

import hashlib
import re
import unicodedata
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class CaseError(ValueError):
    """The case or consumer policy is malformed; no verdict was reached."""


def _object(value: Any, label: str, required: set[str], optional: set[str] = frozenset()) -> dict:
    if not isinstance(value, dict) or required - value.keys() or value.keys() - required - optional:
        raise CaseError(f"{label}: expected fields {sorted(required)}, optional {sorted(optional)}")
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise CaseError(f"{label}: expected nonempty string")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or not HEX64.fullmatch(value):
        raise CaseError(f"{label}: expected lowercase SHA-256")
    return value


def _instant(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value
    ):
        raise CaseError(f"{label}: expected UTC RFC 3339 seconds (ending Z)")
    try:
        instant = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise CaseError(f"{label}: invalid UTC instant") from exc
    return instant


def _artifact(root: Path, metadata: Any, label: str) -> tuple[bytes | None, dict]:
    meta = _object(metadata, label, {"path", "sha256", "length"})
    name = _string(meta["path"], f"{label}.path")
    path = PurePosixPath(name)
    if path.is_absolute() or name != str(path) or any(p in (".", "..") for p in name.split("/")):
        raise CaseError(f"{label}.path: must be a normalized relative path")
    digest = _digest(meta["sha256"], f"{label}.sha256")
    length = meta["length"]
    if type(length) is not int or not 0 <= length <= MAX_ARTIFACT_BYTES:
        raise CaseError(f"{label}.length: expected integer from 0 to {MAX_ARTIFACT_BYTES}")

    current = root
    for component in path.parts:
        current = current / component
        if current.is_symlink():
            raise CaseError(f"{label}.path: symlink traversal refused")
    try:
        if not current.is_file() or current.stat().st_size > MAX_ARTIFACT_BYTES:
            raise OSError("missing, not a file, or exceeds size limit")
        with current.open("rb") as stream:
            data = stream.read(MAX_ARTIFACT_BYTES + 1)
    except OSError:
        return None, {"status": "unavailable", "path": name}
    actual = hashlib.sha256(data).hexdigest()
    if len(data) != length or actual != digest:
        return None, {"status": "binding_mismatch", "path": name, "actual_sha256": actual}
    return data, {"status": "bound", "path": name, "sha256": actual, "length": length}


def _normalized(data: bytes, label: str) -> str:
    try:
        decoded = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise CaseError(f"{label}: expected UTF-8 text") from exc
    return " ".join(unicodedata.normalize("NFC", decoded).split())
