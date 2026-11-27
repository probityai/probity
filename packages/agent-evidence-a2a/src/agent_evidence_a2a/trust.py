"""The pinned trust store: ``kid`` to public key, with an optional validity window."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, Protocol

from joserfc.jwk import Key, import_key

from agent_evidence_a2a._ijson import MAX_DOCUMENT_BYTES, read_i_json

#: The most a trust store file may hold: a few pinned keys.
_MAX_TRUST_STORE_BYTES: Final = MAX_DOCUMENT_BYTES


def _instant(value: str | None) -> datetime | None:
    if value is None:
        return None
    parsed = datetime.fromisoformat(value)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


class PinnedKey(Protocol):
    """What a signature judge reads from a pinned key: the public key and its validity window.

    :class:`TrustedKey` is one; a caller with its own key record (a compliance gate's own trust store) passes
    that record unchanged, so every verifier judges a signature against the same three fields.
    """

    @property
    def key(self) -> Key: ...

    @property
    def not_before(self) -> datetime | None: ...

    @property
    def not_after(self) -> datetime | None: ...


#: Resolves a signature's ``kid`` to its pinned key, or ``None`` for an unknown or revoked ``kid``.
type KeyLookup = Callable[[str], PinnedKey | None]


@dataclass(frozen=True, kw_only=True, slots=True)
class TrustedKey:
    """A pinned public key; outside ``not_before`` and ``not_after`` it verifies nothing."""

    key: Key
    not_before: datetime | None = None
    not_after: datetime | None = None


def outside_window(pinned: PinnedKey, now: datetime) -> str | None:
    """Return why *pinned* is outside its validity window at *now*, else ``None``.

    Raises:
        TypeError: A bound and *now* cannot be compared (one is naive, the other aware); the
            caller decides what an undecidable window means, and a judge refuses the key.
    """
    if pinned.not_before is not None and now < pinned.not_before:
        return f"is not valid before {pinned.not_before.isoformat()}"
    if pinned.not_after is not None and now > pinned.not_after:
        return f"expired at {pinned.not_after.isoformat()}"
    return None


class TrustStore:
    """Resolves a signature's ``kid`` to a pinned key; an unknown or revoked ``kid`` resolves to nothing."""

    def __init__(self, keys: Mapping[str, TrustedKey]) -> None:
        self._keys = dict(keys)

    def get(self, kid: str) -> TrustedKey | None:
        """Return the pinned key for *kid*, or ``None``."""
        return self._keys.get(kid)

    def items(self) -> list[tuple[str, TrustedKey]]:
        """Return every pinned ``(kid, key)`` pair, so another verifier can load the same trust store."""
        return sorted(self._keys.items())

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> TrustStore:
        """Build a store from ``{kid: {"jwk": {...}, "not_before": iso?, "not_after": iso?}}``."""
        keys = {
            kid: TrustedKey(
                key=import_key(entry["jwk"]),
                not_before=_instant(entry.get("not_before")),
                not_after=_instant(entry.get("not_after")),
            )
            for kid, entry in raw.items()
        }
        return cls(keys)

    @classmethod
    def from_file(cls, path: str | Path) -> TrustStore:
        """Load a store from a JSON file in the shape :meth:`from_mapping` reads."""
        return cls.from_mapping(read_i_json(path, max_bytes=_MAX_TRUST_STORE_BYTES))
