"""The refusal-code registry: every code a check reports when it refuses an identity, an authority or a record.

A refusal is the string ``<code>`` or ``<code>:<detail>``. The code is a registered snake-case name with a stable
identifier ``REGISTRY/<code>`` that never moves once published; the detail (a link index, a field name, the code of
an inner check) is for the producer's own log and is never part of the code. A record that publishes a refusal
carries the code alone, so a reader can name it without learning anything the detail holds.

``refusal_codes.json`` beside this module is the registry; ``refusal_lint`` refuses a refusal string in source that
it does not hold.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from importlib import resources
from types import MappingProxyType
from typing import Any

REGISTRY = "https://probityai.github.io/agent-evidence-vectors/refusal-code/v1"
#: A code: lowercase words joined by single underscores, at least two words.
CODE = re.compile(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)+")
_MEMBERS = frozenset({"code", "check", "meaning", "uri"})
_CHECK = re.compile(r"[a-z]+(?:\.[a-z]+)+")


@dataclass(frozen=True)
class RefusalCode:
    """One registered code: what it means and which check reports it."""

    code: str
    check: str
    meaning: str

    @property
    def uri(self) -> str:
        return f"{REGISTRY}/{self.code}"


class RegistryError(ValueError):
    """The registry file is not exactly the registry format."""


def parse(data: Any) -> Mapping[str, RefusalCode]:
    """The codes of a registry document; ``RegistryError`` unless it is exactly the format, sorted and unique."""
    if not isinstance(data, dict) or set(data) != {"registry", "version", "codes"}:
        raise RegistryError("a registry has exactly registry, version and codes")
    if data["registry"] != REGISTRY or data["version"] != 1:
        raise RegistryError("a registry names this registry, version 1")
    entries = data["codes"]
    if not isinstance(entries, list) or not entries:
        raise RegistryError("codes is a non-empty list")
    out: dict[str, RefusalCode] = {}
    previous = ""
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != _MEMBERS or not all(isinstance(v, str) for v in entry.values()):
            raise RegistryError(f"an entry has exactly the string members {sorted(_MEMBERS)}: {entry!r}")
        code = entry["code"]
        if not CODE.fullmatch(code):
            raise RegistryError(f"{code!r} is not a snake-case code of two or more words")
        if code <= previous:
            raise RegistryError(f"{code!r} is out of order or repeated")
        if entry["uri"] != f"{REGISTRY}/{code}":
            raise RegistryError(f"{code!r} has the identifier {entry['uri']!r}, not {REGISTRY}/{code}")
        if not _CHECK.fullmatch(entry["check"]):
            raise RegistryError(f"{code!r} names the check {entry['check']!r}, not a dotted lowercase name")
        meaning = entry["meaning"]
        if not meaning or not meaning.isascii() or not meaning.isprintable():
            raise RegistryError(f"{code!r} has no printable ASCII meaning")
        out[code] = RefusalCode(code, entry["check"], meaning)
        previous = code
    return MappingProxyType(out)


def _load() -> Mapping[str, RefusalCode]:
    text = resources.files(__package__).joinpath("refusal_codes.json").read_text(encoding="utf-8")
    return parse(json.loads(text))


#: Every registered code, by name.
CODES: Mapping[str, RefusalCode] = _load()


def code_of(refusal: str) -> str:
    """The code of a refusal string: the text before the first ``:``."""
    return refusal.split(":", 1)[0]


def is_registered(refusal: str) -> bool:
    """Whether the code of ``refusal`` is registered."""
    return code_of(refusal) in CODES


def lookup(refusal: str) -> RefusalCode:
    """The registered code of ``refusal``; ``KeyError`` naming it when the code is not registered."""
    code = code_of(refusal)
    try:
        return CODES[code]
    except KeyError:
        raise KeyError(f"unregistered refusal code {code!r}") from None
