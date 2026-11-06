"""Native code: compiled binaries the Python-level layers cannot see into, and their sources."""

from __future__ import annotations

from pathlib import Path

NATIVE_SUFFIXES = (".so", ".pyd", ".dll", ".dylib")
NATIVE_SOURCES = (".c", ".h", ".cc", ".cpp", ".pyx", ".pxd", ".rs")


ELF_MAGIC = b"\x7fELF"


def native_name(name: str) -> bool:
    """A name that marks a compiled binary: ``.so``/``.pyd``/``.dll``/``.dylib`` or ``.so.N``."""
    return name.endswith(NATIVE_SUFFIXES) or ".so." in name


def native(path: Path) -> bool:
    """A compiled binary: a ``.so``/``.pyd``/``.dll``/``.dylib`` name or an ELF file."""
    if native_name(path.name):
        return True
    with open(path, "rb") as handle:
        return handle.read(4) == ELF_MAGIC
