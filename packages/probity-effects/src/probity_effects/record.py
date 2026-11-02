"""Operation identity and the uncertain-effect/v1 contract the journal exports."""

from __future__ import annotations

import dataclasses
import enum
import hashlib
import json
import threading
from collections.abc import Mapping
from datetime import date, datetime, timezone
from typing import Any

import jcs_admit

#: The contract a record names, and the predicate type a producer writes when it signs one.
CONTRACT_ID = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/uncertain-effect"
OUTCOMES = ("committed", "not_run", "unknown")


def jsonable(value: Any) -> Any:
    """Plain JSON data from tool arguments: pydantic models, dataclasses, enums and dates included."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Mapping):
        return {str(key): jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [jsonable(item) for item in value]
    dump = getattr(value, "model_dump", None)
    if callable(dump):
        return jsonable(dump(mode="json"))
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return jsonable(dataclasses.asdict(value))
    if isinstance(value, enum.Enum):
        return jsonable(value.value)
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    raise TypeError(f"an argument of type {type(value).__name__} has no JSON form")


def canonical(value: Any) -> bytes:
    """The RFC 8785 bytes of a JSON value, which verifiers in any language recompute."""
    raw = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
    return jcs_admit.admit(raw.encode("utf-8"))


def args_digest(args: Mapping[str, Any]) -> str:
    """``sha256:`` over the RFC 8785 bytes of the arguments, as the record's ``argsDigest``."""
    return "sha256:" + hashlib.sha256(canonical(dict(args))).hexdigest()


def derive_key(action: str, args: Mapping[str, Any], scope: str = "") -> str:
    """A stable idempotency key: the same scope, action and arguments always give the same key."""
    material = canonical({"action": action, "args": dict(args), "scope": scope})
    return "pe-" + hashlib.sha256(material).hexdigest()[:32]


def stamp(moment: datetime) -> str:
    return moment.isoformat(timespec="microseconds").replace("+00:00", "Z")


def parse(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


class Clock:
    """UTC stamps that never go backwards, so the journal's order and its times agree."""

    def __init__(self) -> None:
        self._last: datetime | None = None
        self._lock = threading.Lock()

    def advance_to(self, moment: datetime) -> None:
        with self._lock:
            if self._last is None or moment > self._last:
                self._last = moment

    def now(self) -> datetime:
        with self._lock:
            current = datetime.now(timezone.utc)
            if self._last is not None and current < self._last:
                current = self._last
            self._last = current
            return current
