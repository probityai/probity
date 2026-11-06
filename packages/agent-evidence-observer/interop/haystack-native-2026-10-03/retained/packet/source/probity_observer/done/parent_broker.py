"""The host's half of a replay parent that runs in a container of its own.

The parent container (:mod:`.parent_image`) holds the sealed test root, read-only, and nothing
else of the host: no host path, no grader key, no container runtime socket and no network. It
cannot start the candidate's child itself, so it asks this broker over its own standard input
and output (the frames :class:`.replay.HostLink` writes). The broker starts each child with the
one command the runner built for this replay, the candidate's locked-down container, so the
parent can ask for a child but never say what the host runs. It relays bytes both ways, ends a
child when asked, and ends every child it started when the parent ends, however it ends.
"""

from __future__ import annotations

import base64
import json
import os
import threading
from typing import Any, Sequence

from .replay import LINE_LIMIT, Child

# Children alive at once, and in all, for one parent: a replay holds one child, and at most one
# fresh child beside it; the fresh-child pass asks one per distinct request.
LIVE_CHILDREN = 4
TOTAL_CHILDREN = 4096


class HostBroker:
    """Serve one parent container's frames until its output ends."""

    def __init__(self, parent_in: Any, parent_out: Any, child_argv: Sequence[str],
                 child_cwd: str | None) -> None:
        self.parent_in, self.parent_out = parent_in, parent_out
        self.child_argv, self.child_cwd = list(child_argv), child_cwd
        self.children: dict[int, Child] = {}
        self.every: list[Child] = []
        self.lock = threading.Lock()
        self.readers: list[threading.Thread] = []
        self.closers: list[threading.Thread] = []
        self.result: dict[str, Any] | None = None
        self.exit: int | None = None
        self.refusals = 0

    def _tell(self, frame: dict[str, Any]) -> None:
        data = (json.dumps(frame, separators=(",", ":")) + "\n").encode()
        with self.lock:
            try:
                self.parent_in.write(data)
                self.parent_in.flush()
            except (OSError, ValueError):
                pass

    def _relay(self, handle: int, child: Child) -> None:
        """Forward the child's output to the parent until the child's output ends."""
        assert child.process is not None and child.process.stdout is not None
        descriptor = child.process.stdout.fileno()
        while True:
            try:
                chunk = os.read(descriptor, 1 << 16)
            except (OSError, ValueError):
                chunk = b""
            if not chunk:
                break
            self._tell({"op": "out", "child": handle,
                        "data": base64.b64encode(chunk).decode()})
        self._tell({"op": "eof", "child": handle})

    def _start(self, handle: Any) -> None:
        live = sum(1 for child in self.children.values() if not child.closed)
        if (type(handle) is not int or handle in self.children or live >= LIVE_CHILDREN
                or len(self.every) >= TOTAL_CHILDREN):
            self.refusals += 1
            self._tell({"op": "refused", "child": handle})
            return
        # The child's own limits are the parent's: the host only ends it when asked, or when
        # the parent ends.
        child = Child(self.child_argv, self.child_cwd, float("inf"), register=False)
        self.children[handle] = child
        self.every.append(child)
        reader = threading.Thread(target=self._relay, args=(handle, child), daemon=True)
        reader.start()
        self.readers.append(reader)
        self._tell({"op": "started", "child": handle})

    def _close(self, handle: int, child: Child, timed_out: bool) -> None:
        child.timed_out = child.timed_out or timed_out is True
        child.close()
        self._tell({"op": "closed", "child": handle})

    def _frame(self, frame: dict[str, Any]) -> None:
        op, handle = frame.get("op"), frame.get("child")
        if op == "start":
            self._start(handle)
            return
        if op == "result":
            if isinstance(frame.get("result"), dict) and type(frame.get("exit")) is int:
                self.result, self.exit = frame["result"], frame["exit"]
            return
        child = self.children.get(handle) if type(handle) is int else None
        if child is None:
            return
        if op == "write" and not child.closed:
            try:
                text = base64.b64decode(frame["data"], validate=True).decode()
            except (KeyError, TypeError, ValueError):
                return
            if child._send(text) is not None:
                child.end_input()
        elif op == "end":
            child.end_input()
        elif op == "close":
            closer = threading.Thread(target=self._close,
                                      args=(handle, child, frame.get("timed_out")), daemon=True)
            closer.start()
            self.closers.append(closer)

    def serve(self) -> None:
        """Read the parent's frames until its output ends, then end every child."""
        pending = bytearray()
        descriptor = self.parent_out.fileno()
        try:
            while True:
                try:
                    chunk = os.read(descriptor, 1 << 16)
                except OSError:
                    break
                if not chunk:
                    break
                pending += chunk
                while (end := pending.find(b"\n")) >= 0:
                    line = bytes(pending[:end])
                    del pending[:end + 1]
                    try:
                        frame = json.loads(line)
                    except (ValueError, RecursionError):
                        continue
                    if isinstance(frame, dict):
                        self._frame(frame)
                if len(pending) > 2 * LINE_LIMIT:
                    break
        finally:
            self.close_all()

    def close_all(self) -> None:
        """End every child: the closes the parent asked for finish first, so no child is
        ended by two threads at once."""
        for closer in self.closers:
            closer.join()
        for child in self.every:
            child.close()
        for reader in self.readers:
            reader.join(timeout=1.0)
