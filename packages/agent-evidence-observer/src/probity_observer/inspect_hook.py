"""Inspect hook that seals each finished log into a detached manifest.

Registered through the ``inspect_ai`` entry-point group, so installing the ``inspect``
extra is the whole activation. The hook reads event data and never writes to it: Inspect
owns ``EvalLog``, so the digests live only in the manifest beside the log. A hook failure
is logged by Inspect and cannot stop a run; it records, it does not gate.

Set ``AGENT_EVIDENCE_INSPECT_SEAL=off`` to turn it off.
"""

from __future__ import annotations

import logging
import os

import anyio.to_thread
from inspect_ai.hooks import Hooks, RunEnd, TaskEnd, hooks

from . import inspect_binding

LOGGER = logging.getLogger(__name__)
SWITCH = "AGENT_EVIDENCE_INSPECT_SEAL"
OFF_VALUES = frozenset({"0", "off", "false", "no"})


def _seal_if_missing(location: str) -> None:
    """Seal a log that has no manifest yet; a remote location is reported and skipped."""
    if not inspect_binding.is_local(location):
        LOGGER.warning("sealed manifest skipped: %s is not a local file", location)
        return
    if inspect_binding.manifest_path(location).exists():
        return
    inspect_binding.seal(location)


@hooks(
    name="agent-evidence-observer",
    description="Seals each finished log into a detached manifest of execution and results digests.",
)
class SealedManifestHooks(Hooks):
    """Writes ``<log>.sealed.json`` beside every finished log."""

    def enabled(self) -> bool:
        return os.environ.get(SWITCH, "").strip().lower() not in OFF_VALUES

    async def on_task_end(self, data: TaskEnd) -> None:
        location = data.log.location
        if not inspect_binding.is_local(location):
            LOGGER.warning("sealed manifest skipped: %s is not a local file", location)
            return
        await anyio.to_thread.run_sync(inspect_binding.seal, location)

    async def on_run_end(self, data: RunEnd) -> None:
        """Seal any finished log the task hook did not reach, for example after a hook error."""
        for log in data.logs:
            if log.location:
                await anyio.to_thread.run_sync(_seal_if_missing, log.location)
