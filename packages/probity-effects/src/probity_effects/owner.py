"""The port to the service that owns an effect, and how a failed send is read."""

from __future__ import annotations

import enum
import socket
from collections.abc import Awaitable, Callable, Iterator, Mapping
from dataclasses import dataclass
from typing import Any


class Reply(str, enum.Enum):
    """What one dispatch learned, in the record's words."""

    CONFIRMED = "confirmed"
    NO_EFFECT = "no_effect"
    TIMEOUT = "timeout"
    CONNECTION_LOST = "connection_lost"

    @property
    def unknown(self) -> bool:
        """The caller does not know whether the effect happened."""
        return self in (Reply.TIMEOUT, Reply.CONNECTION_LOST)


class NoEffect(Exception):
    """Raise from a send when the owner answered that the effect did not happen."""


@dataclass(frozen=True)
class Lookup:
    """The owner's answer about one idempotency key.

    ``present`` means the owner holds the effect. ``final`` says an absent answer is settled: a
    lookup that is not final can miss a commit that lands later.
    """

    present: bool
    final: bool = True


@dataclass(frozen=True)
class EffectCall:
    """One dispatch, handed to the send: put ``key`` in the request the owner deduplicates by."""

    key: str
    action: str
    args: Mapping[str, Any]
    attempt: int
    fencing_token: int | None = None


LookupFn = Callable[[str], "Lookup | None | Awaitable[Lookup | None]"]


@dataclass(frozen=True)
class EffectOwner:
    """The service that owns the effect, as the guard sees it.

    ``lookup(key)`` answers what the owner holds for a key, or None while it cannot answer. ``send``,
    when given, performs the effect instead of the tool body (a test points a tool at a stand-in owner
    this way). ``lease()`` returns the owner's current fencing token for workers that hold leases.
    ``classify`` reads a failed send; the default is :func:`classify_failure`.
    """

    id: str
    lookup: LookupFn
    send: Callable[[EffectCall], Any] | None = None
    lease: Callable[[], Any] | None = None
    classify: Callable[[BaseException], Reply] | None = None
    deduplicates_by_key: bool = False
    key_retention_seconds: float | None = None
    max_sends: int = 3
    lookups: int = 5
    lookup_interval: float = 0.2

    def __post_init__(self) -> None:
        if not self.id:
            raise ValueError("an effect owner needs an id")
        if self.max_sends < 1 or self.lookups < 1:
            raise ValueError("max_sends and lookups must each be at least 1")
        if self.key_retention_seconds is not None and self.key_retention_seconds < 0:
            raise ValueError("key_retention_seconds cannot be negative")

    def read_failure(self, error: BaseException) -> Reply:
        return (self.classify or classify_failure)(error)

    def describe(self) -> dict[str, Any]:
        return {"deduplicatesByKey": self.deduplicates_by_key, "id": self.id,
                "keyRetentionSeconds": self.key_retention_seconds}


# Failures raised before a request could reach the owner, by top-level module and class name, so
# none of these libraries is imported here.
_BEFORE_SEND = frozenset({
    ("httpx", "ConnectError"), ("httpx", "ConnectTimeout"),
    ("requests", "ConnectTimeout"),
    ("urllib3", "NewConnectionError"), ("urllib3", "ConnectTimeoutError"),
    ("urllib3", "NameResolutionError"),
})


def _chain(error: BaseException) -> Iterator[BaseException]:
    """The error, its causes and contexts, and a wrapped ``reason``, each once."""
    seen: set[int] = set()
    pending: list[BaseException] = [error]
    while pending:
        item = pending.pop()
        if id(item) in seen:
            continue
        seen.add(id(item))
        yield item
        for nested in (item.__cause__, item.__context__, getattr(item, "reason", None)):
            if isinstance(nested, BaseException):
                pending.append(nested)


def _before_send(error: BaseException) -> bool:
    if isinstance(error, (ConnectionRefusedError, socket.gaierror)):
        return True
    return any((cls.__module__.split(".")[0], cls.__name__) in _BEFORE_SEND
               for cls in type(error).__mro__)


def _status(error: BaseException) -> int | None:
    response = getattr(error, "response", None)
    for value in (getattr(response, "status_code", None), getattr(error, "status_code", None),
                  getattr(error, "code", None)):
        if isinstance(value, int) and 100 <= value < 600:
            return value
    return None


def classify_failure(error: BaseException) -> Reply:
    """Read a failed send conservatively.

    No effect only when the owner said so (``NoEffect``, or a 4xx status other than 408 and 409) or the
    request never left (a refused connection, a failed name lookup, a connect timeout). Anything else
    is a lost reply: a timeout, or a lost connection.
    """
    if isinstance(error, NoEffect):
        return Reply.NO_EFFECT
    chain = list(_chain(error))
    if any(_before_send(item) for item in chain):
        return Reply.NO_EFFECT
    status = _status(error)
    if status is not None:
        if 400 <= status < 500 and status not in (408, 409):
            return Reply.NO_EFFECT
        return Reply.TIMEOUT if status in (408, 504) else Reply.CONNECTION_LOST
    if any(isinstance(item, TimeoutError) or "Timeout" in type(item).__name__ for item in chain):
        return Reply.TIMEOUT
    return Reply.CONNECTION_LOST
