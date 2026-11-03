"""With the failure-finding modules blocked from import, the public package imports and the loop runs.

`ratchet.improve.diagnose` and `ratchet.improve.overfit` are the implementation behind the failure-finding
seam; the engine must not need them. The loop runs here on the open diagnoser and the open overfit screen,
and every decision it signs names the screen that gated it.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

PROGRAM = textwrap.dedent(
    """
    import importlib, importlib.abc, pkgutil, sys

    BLOCKED = ("ratchet.improve.diagnose", "ratchet.improve.overfit")

    class Refuse(importlib.abc.MetaPathFinder):
        def find_spec(self, name, path=None, target=None):
            if name in BLOCKED:
                raise ImportError(f"{name} is not installed in this test")
            return None

    sys.meta_path.insert(0, Refuse())
    sys.path.insert(0, sys.argv[1])

    import ratchet.cli, ratchet.improve.loop, ratchet.improve.referee, ratchet.demo.scenario
    import ratchet.agent.worker
    for pkg in ("ratchet.verify", "ratchet.view", "ratchet.export"):
        for info in pkgutil.iter_modules(importlib.import_module(pkg).__path__, pkg + "."):
            if not info.name.endswith("__main__"):
                importlib.import_module(info.name)

    from improve.chat_proposer import ChatProposer
    from improve.test_loop import SEED, MemStore, RoutingChat, _lab
    from ratchet.improve import failures, loop
    from ratchet.improve.receipt import Signer

    loop.load_proposer = lambda name, model: ChatProposer(model)
    assert failures.installed_diagnoser() is failures.open_diagnose
    assert isinstance(failures.installed_overfit_screen(), failures.OpenOverfitScreen)

    chat, store, signer = RoutingChat(), MemStore(), Signer.generate()
    result = loop.evolve(store, model=None, generations=2, lab=_lab(store, chat, signer), seed=SEED)
    first = result.generations[0]
    assert first.clusters and all(c["members"] for c in first.clusters), first.clusters
    assert store.decisions, "the referee decided nothing"
    for d in store.decisions:
        check = next(c for c in d["checks"] if c["name"] == "overfit_lint")
        assert check["evidence"]["screen"] == "open-literals", check
    assert not [m for m in sys.modules if m in BLOCKED]
    print("ok", len(store.decisions))
    """
)


def test_the_loop_runs_without_the_failure_finding_modules(tmp_path: Path) -> None:
    tests_dir = Path(__file__).parent
    out = subprocess.run([sys.executable, "-c", PROGRAM, str(tests_dir)], capture_output=True,
                         text=True, check=False, timeout=300, cwd=tmp_path)  # fmt: skip
    assert out.returncode == 0, out.stderr
    assert out.stdout.split()[0] == "ok"
