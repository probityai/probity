"""A source materialization refusal must name its source, step and Git error."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import materialize_sources  # noqa: E402
from trust import HostRefusal  # noqa: E402

COMPONENT = {"repository": "probityai/example", "head": "a" * 40}


def _fake_run(failing_step: int | None, stderr: bytes, timeout: bool = False) -> Any:
    calls: list[list[str]] = []

    def run(command: list[str], **_: Any) -> subprocess.CompletedProcess[bytes]:
        calls.append(command)
        if len(calls) - 1 == failing_step:
            if timeout:
                raise subprocess.TimeoutExpired(command, 180)
            return subprocess.CompletedProcess(command, 128, b"", stderr)
        return subprocess.CompletedProcess(command, 0, b"", b"")

    run.calls = calls  # type: ignore[attr-defined]
    return run


@pytest.mark.parametrize("step,verb", [(0, "clone"), (1, "fetch"), (2, "checkout")])
def test_refusal_names_source_commit_step_and_git_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, step: int, verb: str
) -> None:
    """Each failing Git step is reported with the source, URL, commit and stderr."""
    logs = tmp_path / "logs"
    logs.mkdir()
    monkeypatch.setattr(materialize_sources.subprocess, "run", _fake_run(step, b"fatal: repository not found\n"))
    with pytest.raises(HostRefusal) as raised:
        materialize_sources.checkout("example", COMPONENT, tmp_path / "src", logs)
    reason = str(raised.value)
    assert reason.startswith("selected public source materialization failed")
    for needle in ("example", "probityai/example", COMPONENT["head"], "step " + str(step), "git " + verb,
                   "returned 128", "fatal: repository not found"):
        assert needle in reason


def test_timeout_is_a_named_refusal_not_a_traceback(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A hung Git step becomes a refusal that says it timed out."""
    logs = tmp_path / "logs"
    logs.mkdir()
    monkeypatch.setattr(materialize_sources.subprocess, "run", _fake_run(1, b"", timeout=True))
    with pytest.raises(HostRefusal) as raised:
        materialize_sources.checkout("example", COMPONENT, tmp_path / "src", logs)
    assert "returned timeout" in str(raised.value)
    assert "timed out after 180 seconds" in str(raised.value)


def test_success_runs_clone_fetch_checkout_in_order(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The fetch by hash sits between the clone and the detached checkout."""
    logs = tmp_path / "logs"
    logs.mkdir()
    run = _fake_run(None, b"")
    monkeypatch.setattr(materialize_sources.subprocess, "run", run)
    materialize_sources.checkout("example", COMPONENT, tmp_path / "src", logs)
    assert [c[3] if c[1] == "-C" else c[1] for c in run.calls] == ["clone", "fetch", "checkout"]
    assert run.calls[1][-1] == COMPONENT["head"]
