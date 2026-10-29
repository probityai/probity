"""Plug-in points of the contract compiler and the grader.

Three entry-point groups, each holding at most one installed plug-in:

- ``probity_observer.contract_providers``: turns a repository task's description into its
  acceptance commands and protected paths (a :class:`ContractProvider`), and may return a
  :class:`Strengthener` the compiler asks for more tests while a seal gate fails. Without one,
  a repository task takes its acceptance commands from a proposal file
  (:func:`.repo_task.read_proposal`) and is compiled with no strengthening.
- ``probity_observer.guard_selectors``: chooses guard node ids from the repository's own suite
  for a task with a reference (a :class:`GuardSelector`). Without one, no guard is chosen by
  mutant kills; a task without a reference still seals its stable suite (:mod:`.suite`).
- ``probity_observer.visible_detectors``: reads how a sealed visible test was passed (a
  :class:`VisibleDetector`). Without one, the grade carries no ``visible_detectors`` block,
  which the receipt format makes optional.

Each plug-in is the loaded object of its entry point, usually a module whose functions have
the protocol's names. Two plug-ins in one group are refused rather than chosen between.
"""

from __future__ import annotations

from importlib.metadata import entry_points
from pathlib import Path
from typing import TYPE_CHECKING, Any, Mapping, Protocol, Sequence

from .formats import DoneError

if TYPE_CHECKING:
    from .contract import Task
    from .mutants import Mutant
    from .runner import Command, Runner

CONTRACT_PROVIDERS = "probity_observer.contract_providers"
GUARD_SELECTORS = "probity_observer.guard_selectors"
VISIBLE_DETECTORS = "probity_observer.visible_detectors"



class Strengthener(Protocol):
    """Writes held-out tests that kill mutants the sealed commands leave alive."""

    rounds: int

    def round(self, task: Task, runner: Runner, prefix: Sequence[str], found: Sequence[Mutant],
              alive: Sequence[int], number: int, mode: str, timeout: float
              ) -> tuple[Command | None, dict[str, Any]]:
        """Round ``number``: the sealed command its kept tests run as (its file already under
        ``task.heldout``), or ``None`` when no test was kept; and the round's record."""
        ...


class ContractProvider(Protocol):
    def provide(self, repo: Path, task_id: str, description: str, *, reference: Path | None,
                work: Path, runner: Runner, options: Mapping[str, Any]
                ) -> tuple[Task, Strengthener | None]:
        """An unsealed repository task with its provenance in ``task.notes``."""
        ...


class GuardChoice(Protocol):
    chosen: list[str]
    files: list[str]
    record: dict[str, Any]

    def kills(self, ids: Sequence[str]) -> set[int]: ...


class GuardSelector(Protocol):
    def harvest(self, runner: Runner, start: Path, reference: Path, heldout: Path | None,
                prefix: Sequence[str], tests: Sequence[str], sources: Sequence[str],
                found: list[Mutant], alive: Sequence[int], timeout: float) -> GuardChoice:
        """The guard node ids for the ``alive`` mutants, and the record they leave."""
        ...


class VisibleDetector(Protocol):
    def applies(self, contract: dict[str, Any], heldout: Path | None) -> str | None:
        """The entry point the visible test replays, when the detectors read this contract."""
        ...

    def detect(self, runner: Any, root: Path, heldout: Path, prompt: str, entry: str,
               agent_test: str | None, timeout: float
               ) -> tuple[dict[str, Any], dict[str, Any]]:
        """The grade's ``visible_detectors`` block and the staging record behind it."""
        ...


def plugin(group: str) -> Any | None:
    """The one plug-in installed in ``group``, else ``None``."""
    found = sorted(entry_points(group=group), key=lambda item: item.name)
    if len(found) > 1:
        raise DoneError(f"{group}: {len(found)} plug-ins installed "
                        f"({', '.join(item.name for item in found)}); install one")
    return found[0].load() if found else None


def contract_provider() -> ContractProvider | None:
    return plugin(CONTRACT_PROVIDERS)


def guard_selector() -> GuardSelector | None:
    return plugin(GUARD_SELECTORS)


def visible_detector() -> VisibleDetector | None:
    return plugin(VISIBLE_DETECTORS)
