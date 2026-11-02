"""The journal: the guard's memory, and the uncertain-effect/v1 record it exports."""

from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from probity_effects.record import CONTRACT_ID, Clock, parse, stamp

UNKNOWN_REPLIES = ("timeout", "connection_lost")


@dataclass(frozen=True)
class Attempt:
    number: int
    key: str
    args_digest: str
    dispatched_at: str
    fencing_token: int | None = None
    reply: str | None = None  # None: dispatched, and no reply was recorded

    @property
    def unknown(self) -> bool:
        return self.reply is None or self.reply in UNKNOWN_REPLIES


@dataclass
class History:
    """Everything the journal holds about one idempotency key."""

    key: str
    operation: dict[str, Any] | None = None
    attempts: list[Attempt] = field(default_factory=list)
    reconciliations: list[dict[str, Any]] = field(default_factory=list)
    lookups: int = 0
    outcome: str | None = None

    @property
    def committed(self) -> bool:
        return (any(item.reply == "confirmed" for item in self.attempts)
                or any(item["result"] == "present" for item in self.reconciliations))

    def unresolved(self) -> Attempt | None:
        """The earliest lost-reply attempt, unless a final absent answer came after the last one."""
        unknown = [item for item in self.attempts if item.unknown]
        if not unknown:
            return None
        last = max(parse(item.dispatched_at) for item in unknown)
        if any(item["result"] == "absent" and item["final"] and parse(item["at"]) >= last
               for item in self.reconciliations):
            return None
        return min(unknown, key=lambda item: parse(item.dispatched_at))

    def settled(self) -> str:
        """The outcome the owner's answers settle, as the record's reader computes it."""
        if self.committed:
            return "committed"
        return "unknown" if self.unresolved() is not None else "not_run"


class Journal:
    """Append-only events per idempotency key, in memory or in a JSON-lines file.

    A file journal writes each event before the guard acts on it, so a process that stops mid-call
    leaves the dispatch behind, and the next process that opens the file reconciles it before sending
    again. Pass ``fsync=True`` to force every line to disk.
    """

    def __init__(self, path: str | os.PathLike[str] | None = None, *, fsync: bool = False) -> None:
        self._path = Path(path) if path is not None else None
        self._fsync = fsync
        self._events: list[dict[str, Any]] = []
        self._lock = threading.RLock()
        self.clock = Clock()
        if self._path is not None and self._path.exists():
            self._load(self._path)

    @classmethod
    def open(cls, path: str | os.PathLike[str], *, fsync: bool = False) -> Journal:
        return cls(path, fsync=fsync)

    @property
    def path(self) -> Path | None:
        return self._path

    def _load(self, path: Path) -> None:
        lines = path.read_text(encoding="utf-8").splitlines()
        for number, line in enumerate(lines, start=1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except ValueError:
                if number == len(lines):
                    break  # a line torn by a stop mid-write; nothing after it was acted on
                raise ValueError(f"{path}:{number}: not a journal event") from None
            self._events.append(event)
            self.clock.advance_to(parse(event["at"]))

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            entry = {**event, "at": stamp(self.clock.now())}
            if self._path is not None:
                with self._path.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")
                    handle.flush()
                    if self._fsync:
                        os.fsync(handle.fileno())
            self._events.append(entry)
            return entry

    def events(self, key: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(item) for item in self._events if key is None or item.get("key") == key]

    def keys(self) -> list[str]:
        with self._lock:
            return list(dict.fromkeys(item["key"] for item in self._events
                                      if item.get("event") == "operation"))

    def history(self, key: str) -> History:
        history = History(key=key)
        replies: dict[int, str] = {}
        dispatched: list[dict[str, Any]] = []
        for event in self.events(key):
            kind = event.get("event")
            if kind == "operation" and history.operation is None:
                history.operation = event
            elif kind == "dispatch":
                dispatched.append(event)
            elif kind == "reply":
                replies[event["attempt"]] = event["reply"]
            elif kind == "lookup":
                history.lookups += 1
                if event.get("answered"):
                    history.reconciliations.append(
                        {"at": event["at"], "final": event["final"], "idempotencyKey": key,
                         "result": event["result"]})
            elif kind == "outcome":
                history.outcome = event["outcome"]
        history.attempts = [Attempt(number=item["attempt"], key=key, args_digest=item["argsDigest"],
                                    dispatched_at=item["at"], fencing_token=item.get("fencingToken"),
                                    reply=replies.get(item["attempt"])) for item in dispatched]
        return history

    def trail(self, key: str) -> dict[str, Any]:
        """The runtime's half of the record, without the owner's own effect count.

        A dispatch with no recorded reply is exported as ``connection_lost``: the runtime has no reply.
        An operation whose outcome was never reported is exported as ``unknown``.
        """
        history = self.history(key)
        if history.operation is None:
            raise KeyError(f"the journal holds no operation with key {key!r}")
        operation = history.operation
        attempts = []
        for item in history.attempts:
            attempt: dict[str, Any] = {"argsDigest": item.args_digest, "attempt": item.number,
                                       "dispatchedAt": item.dispatched_at, "idempotencyKey": item.key,
                                       "reply": item.reply or "connection_lost"}
            if item.fencing_token is not None:
                attempt["fencingToken"] = item.fencing_token
            attempts.append(attempt)
        events = self.events(key)
        return {
            "asOf": events[-1]["at"],
            "attempts": attempts,
            "contractId": CONTRACT_ID,
            "effectOwner": operation["owner"],
            "operation": {"action": operation["action"], "argsDigest": operation["argsDigest"],
                          "id": key, "idempotencyKey": key},
            "reconciliations": history.reconciliations,
            "recordId": f"record-{key}",
            "reported": {"outcome": history.outcome or "unknown"},
        }

    def record(self, key: str, *, owner_effects: int) -> dict[str, Any]:
        """The whole uncertain-effect/v1 record: the trail joined with the owner's effect count."""
        if isinstance(owner_effects, bool) or not isinstance(owner_effects, int) or owner_effects < 0:
            raise ValueError("owner_effects is the owner's own count of effects, a whole number")
        return {**self.trail(key), "ownerEffects": owner_effects}
