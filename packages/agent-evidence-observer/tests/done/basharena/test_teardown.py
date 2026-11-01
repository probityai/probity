"""Per-task teardown: a task's images go once its evidence is on disk, and the shared bases stay."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from probity_observer.done.basharena import episode, run, task

BASES = {"benchmark-base:latest", "bash-arena-malware-server:latest", "bash-arena-logging-server:latest"}


class FakeDocker:
    """A mocked docker client: an image store plus a log of every argv, in place of ``Commands``."""

    def __init__(self, images: dict[str, str]) -> None:
        self.images = dict(images)
        self.calls: list[list[str]] = []

    def run(self, argv, *, check=True, **_kw):
        argv = list(argv)
        self.calls.append(argv)
        out, code = b"", 0
        if argv[:3] == ["docker", "image", "inspect"]:
            name = argv[-1]
            out, code = (self.images[name].encode(), 0) if name in self.images else (b"", 1)
        elif argv[:3] == ["docker", "image", "rm"]:
            self.images.pop(argv[-1], None)
        return subprocess.CompletedProcess(argv, code, out, b"")

    def text(self, argv, **kw):
        return self.run(argv, **kw).stdout.decode().strip()


def _store(task_id: str) -> dict[str, str]:
    store = {name: f"sha256:{name}" for name in BASES}
    for name in (f"probity-start-ba-{task_id}:latest", f"probity-final-ba-{task_id}:latest",
                 f"bash-arena-default-{task_id}:latest", f"bash-arena-database-server-{task_id}:latest"):
        store[name] = f"sha256:{name}"
    return store


def test_task_images_name_the_four_per_task_images_and_no_base():
    found = run.task_images("42", ["probity-start-ba-42:latest", "probity-final-ba-42:latest"])
    assert set(found) == set(_store("42")) - BASES


def test_a_finished_task_loses_its_images_keeps_the_bases_and_keeps_the_digests(tmp_path: Path):
    docker = FakeDocker(_store("42"))
    images = run.task_images("42", ["probity-start-ba-42:latest", "probity-final-ba-42:latest"])
    run._save_image_digests(docker, tmp_path, images)
    run._teardown(docker, None, images)
    assert set(docker.images) == BASES
    saved = json.loads((tmp_path / "images.json").read_text())
    assert saved["probity-final-ba-42:latest"] == "sha256:probity-final-ba-42:latest"
    assert set(saved) == set(images)


def test_digests_are_read_before_the_first_removal(tmp_path: Path):
    docker = FakeDocker(_store("42"))
    images = run.task_images("42", ["probity-start-ba-42:latest"])
    run._save_image_digests(docker, tmp_path, images)
    run._teardown(docker, None, images)
    kinds = [c[2] for c in docker.calls if c[:2] == ["docker", "image"]]
    assert kinds.index("rm") > max(i for i, k in enumerate(kinds) if k == "inspect")


def test_an_image_already_gone_is_recorded_as_none(tmp_path: Path):
    docker = FakeDocker({})
    run._save_image_digests(docker, tmp_path, ["probity-final-ba-9:latest"])
    assert json.loads((tmp_path / "images.json").read_text()) == {"probity-final-ba-9:latest": None}


def test_the_build_cache_is_pruned_only_when_asked():
    plain, pruning = FakeDocker({}), FakeDocker({})
    run._teardown(plain, None, [])
    run._teardown(pruning, None, [], prune_build_cache=True)
    assert ["docker", "builder", "prune", "-f"] not in plain.calls
    assert ["docker", "builder", "prune", "-f"] in pruning.calls


def test_a_failed_episode_still_removes_the_tasks_images(tmp_path: Path, row: dict, monkeypatch):
    # Nothing was committed yet (the driver died first), so only BashArena's built images exist.
    docker = FakeDocker({n: i for n, i in _store(str(row["task_id"])).items() if "probity-" not in n})
    monkeypatch.setattr(run, "Commands", lambda _log: docker)
    monkeypatch.setattr(run, "_driver", lambda *_a: type("D", (), {"poll": lambda s: 1, "terminate": lambda s: None})())
    monkeypatch.setattr(task, "compile_spec", lambda *_a: type("S", (), {"task_id": str(row["task_id"])})())
    config = episode.Config(tmp_path, "obs", "m", {})
    with pytest.raises(RuntimeError):
        run.run_episode(row, 0, "rev", config, tmp_path, key=None)
    assert set(docker.images) == BASES
    work = tmp_path / episode.episode_id(row)
    assert (work / "images.json").exists()
