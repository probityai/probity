"""Read the sealed grader's result channel (see ``grader_bootstrap.txt`` beside this module for the line format).

A channel that does not verify is never read as a grade: a bad HMAC, an index out of sequence, a
duplicate node id or a missing end line raises, and the verdict treats the reading as forged or
incomplete rather than as a set of outcomes.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Sequence

from ..formats import DoneError

OUTCOMES = ("passed", "failed", "error", "skipped")


class Forged(DoneError):
    """A result line does not verify under the reading's key."""


class Incomplete(DoneError):
    """The channel ended before the grader's end line."""


@dataclass(frozen=True)
class Results:
    outcomes: dict[str, str]
    flags: list[str]
    pytest_exit: int | None = None
    extra: dict[str, str] = field(default_factory=dict)

    def against(self, expected: Sequence[str]) -> dict[str, str]:
        """The outcome of every sealed test id; a test the grader never reported is ``missing``."""
        return {test: self.outcomes.get(test, "missing") for test in expected}

    def unexpected(self, expected: Sequence[str]) -> list[str]:
        return sorted(set(self.outcomes) - set(expected))


def bootstrap_path() -> Path:
    return Path(str(resources.files(__package__).joinpath("grader_bootstrap.txt")))


def _mac(key: bytes, *fields: object) -> str:
    return hmac.new(key, "\x1f".join(str(f) for f in fields).encode(), hashlib.sha256).hexdigest()


def _check(key: bytes, given: str, *fields: object) -> None:
    if not hmac.compare_digest(given, _mac(key, *fields)):
        raise Forged(f"result line {fields[:2]} does not verify")


def _line(kind: str, rest: str, expected_index: int, key: bytes) -> list[str]:
    head, _, tail = rest.partition("\t")
    if not head.isdigit() or int(head) != expected_index:
        raise Forged(f"result line out of sequence: {kind} {head!r}, expected {expected_index}")
    return tail.split("\t")


def parse(stdout: bytes, key: bytes) -> Results:
    """Verify and read every line of one reading's result channel."""
    outcomes: dict[str, str] = {}
    flags: list[str] = []
    index = 0
    for raw in stdout.decode("utf-8", "replace").splitlines():
        kind, _, rest = raw.partition(" ")
        fields = _line(kind, rest, index, key)
        if kind == "R" and len(fields) == 3:
            nodeid, outcome, mac = fields
            _check(key, mac, "R", index, nodeid, outcome)
            if nodeid in outcomes or outcome not in OUTCOMES:
                raise Forged(f"duplicate or unknown result for {nodeid!r}")
            outcomes[nodeid] = outcome
        elif kind == "F" and len(fields) == 2:
            _check(key, fields[1], "F", index, fields[0])
            flags.append(fields[0])
        elif kind == "E" and len(fields) == 2 and fields[0].lstrip("-").isdigit():
            _check(key, fields[1], "E", index, int(fields[0]))
            return Results(outcomes=outcomes, flags=flags, pytest_exit=int(fields[0]))
        else:
            raise Forged(f"unreadable result line {raw[:80]!r}")
        index += 1
    raise Incomplete("no end line on the result channel")
