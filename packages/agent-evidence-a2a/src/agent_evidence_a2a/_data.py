"""Access to the corpora shipped inside the package."""

from __future__ import annotations

from importlib.resources import files
from typing import Any, Final

from agent_evidence_a2a._ijson import MAX_DOCUMENT_BYTES, parse_i_json

#: The most a shipped data file, or one row of a shipped rows file, may hold.
_MAX_DATA_BYTES: Final = MAX_DOCUMENT_BYTES


def data_text(name: str) -> str:
    """Return the text of a shipped data file."""
    return files("agent_evidence_a2a").joinpath("data", name).read_text(encoding="utf-8")


def data_json(name: str) -> Any:
    """Return the parsed JSON of a shipped data file."""
    return parse_i_json(data_text(name), max_bytes=_MAX_DATA_BYTES)


def data_jsonl(name: str) -> list[dict[str, Any]]:
    """Return the rows of a shipped JSON-lines file."""
    return [parse_i_json(line, max_bytes=_MAX_DATA_BYTES) for line in data_text(name).splitlines() if line.strip()]
