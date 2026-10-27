"""Synthetic refund provider for the bounded refund sandbox (contract review-2026-10-23).

The only thing in a sandbox run that creates an effect. Its state is one JSON
file holding the effect ledger and the transcript of every request it received,
at the precision of its own clock. At most one ledger row exists per
idempotency key, so a repeated request returns the original row.

``query`` is the read path the executor's observations use. It returns the
simulator's raw state bytes (ledger plus transcript), so an observation hashes
what the provider actually held, not what the executor was told.

Fault modes, chosen per ``apply`` call:

* ``none``: commit, then answer.
* ``lose_response``: commit, then fail to answer (the client sees ``LostResponse``).
* ``receive_then_fail``: record the request, commit nothing, fail to answer.

This is a simulator: what it records says nothing about a live provider.
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

EXACT = "%Y-%m-%dT%H:%M:%S.%fZ"


class LostResponse(Exception):
    """The provider received the request but its answer never reached the client."""


def fmt_exact(value: datetime) -> str:
    """Format an instant at the simulator's own (microsecond) precision."""
    return value.astimezone(timezone.utc).strftime(EXACT)


def parse_exact(value: str) -> datetime:
    """Parse a simulator timestamp back to an exact UTC instant."""
    return datetime.strptime(value, EXACT).replace(tzinfo=timezone.utc)


class SandboxSimulator:
    """A file-backed synthetic provider with an idempotent effect ledger."""

    def __init__(self, path: Path, clock: Callable[[], datetime]) -> None:
        self.path = Path(path)
        self.clock = clock
        if not self.path.exists():
            self._save({"ledger": [], "requests": []})

    def _load(self) -> dict[str, Any]:
        return json.loads(self.path.read_bytes())

    def _save(self, state: dict[str, Any]) -> None:
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".sim-")
        with os.fdopen(fd, "wb") as fh:
            fh.write(json.dumps(state, sort_keys=True).encode("ascii"))
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.path)

    def _log(self, state: dict[str, Any], kind: str, key: str) -> None:
        state["requests"].append({"seq": len(state["requests"]) + 1, "kind": kind,
                                  "idempotency_key": key, "at": fmt_exact(self.clock())})

    def apply(self, request: dict[str, Any], fault: str = "none") -> dict[str, Any]:
        """Create (or return) the one effect for the request's idempotency key."""
        state = self._load()
        key = request["idempotency_key"]
        self._log(state, "apply", key)
        if fault == "receive_then_fail":
            self._save(state)
            raise LostResponse(key)
        row = next((r for r in state["ledger"] if r["idempotency_key"] == key), None)
        if row is None:
            row = {"effect_id": f"eff-{len(state['ledger']) + 1}", "idempotency_key": key,
                   "operation_id": request["operation_id"], "attempt_id": request["attempt_id"],
                   "arguments": request["arguments"], "committed_at": fmt_exact(self.clock())}
            state["ledger"].append(row)
        self._save(state)
        if fault == "lose_response":
            raise LostResponse(key)
        return {"status": "committed", "effect_id": row["effect_id"]}

    def query(self, key: str) -> tuple[bytes, dict[str, Any] | None, bool]:
        """Read back the ledger row for a key: (raw state bytes, row or None, request received)."""
        state = self._load()
        self._log(state, "query", key)
        self._save(state)
        raw = self.path.read_bytes()
        row = next((r for r in state["ledger"] if r["idempotency_key"] == key), None)
        received = any(r["kind"] == "apply" and r["idempotency_key"] == key for r in state["requests"])
        return raw, row, received

    def effect_count(self) -> int:
        """Number of effects in the ledger."""
        return len(self._load()["ledger"])
