"""Record shapes and workspace digests shared by every observer packet reader.

These helpers define the content-tree root and the literal scope rule that a
packet claim carries. They read files and validate paths; they never write a
workspace or decide whether a write may happen.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .crypto import digest


class CoverageError(ValueError):
    """A requested write or workspace state falls outside the declared scope."""

@dataclass(frozen=True)
class WriteResult:
    """One broker request's observed durable state transition.

    Attributes
    ----------
    request_id : str
        Caller-supplied idempotency key for this interval.
    path : str
        Normalized path beneath the authority's literal scope.
    before_root, after_root : str
        Content-tree roots on either side of the accepted write.
    replayed : bool
        True if this result was returned for a repeated, identical request.
    """

    request_id: str
    path: str
    before_root: str
    after_root: str
    replayed: bool = False

def utc_now() -> str:
    """Return a UTC timestamp in one lexically ordered second-resolution form."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

def tree_manifest(workspace: Path) -> dict[str, str]:
    """Hash every regular file under a workspace, refusing symlinks.

    Parameters
    ----------
    workspace : Path
        Root whose final durable file contents are the coverage population.

    Returns
    -------
    dict[str, str]
        Relative POSIX file paths mapped to SHA-256 content digests.

    Raises
    ------
    CoverageError
        If a symbolic link or non-regular file prevents a complete walk.

    Notes
    -----
    This snapshots file bytes at call boundaries. It cannot report transient
    intermediate writes, reads, file modes, network traffic, or open handles.
    """
    manifest: dict[str, str] = {}
    for parent, directories, files in os.walk(workspace, followlinks=False):
        parent_path = Path(parent)
        for name in directories + files:
            candidate = parent_path / name
            if candidate.is_symlink():
                raise CoverageError("workspace contains a symbolic link")
        for name in files:
            candidate = parent_path / name
            if not candidate.is_file():
                raise CoverageError("workspace contains a non-regular file")
            relative = candidate.relative_to(workspace).as_posix()
            if not relative.isascii():
                raise CoverageError("workspace path is outside the ASCII profile")
            manifest[relative] = hashlib.sha256(candidate.read_bytes()).hexdigest()
    return manifest

def tree_root(workspace: Path) -> str:
    """Return the domain-separated root of :func:`tree_manifest`."""
    return digest("probity-file-tree-v0", tree_manifest(workspace))

def path_under_scope(scope: str, path: str) -> str:
    """Validate a literal path and return its workspace-relative spelling."""
    if not path.isascii() or not path.startswith("/") or "\x00" in path:
        raise CoverageError("write path must be an ASCII absolute path")
    if any(part in ("", ".", "..") for part in path[1:].split("/")):
        raise CoverageError("write path is not normalized")
    prefix = scope.rstrip("/") + "/"
    if not path.startswith(prefix):
        raise CoverageError("write path is outside the authorized scope")
    return path[len(prefix):]
