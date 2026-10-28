"""The replay parent runs in a container of its own, and the isolation record says where it ran.

Each test here starts real containers: the replay parent from the verifier's own image
(:mod:`probity_observer.done.parent_image`), and the candidate's children beside it, started by
the host broker. The sealed tests are those of ``test_pytest_replay.py``.
"""

from __future__ import annotations

import os
import shutil
import socket

import pytest
from probity_observer.done import parent_image, runner, verify_run
from probity_observer.done.runner import SubprocessRunner

from .test_pytest_replay import HONEST, IDS, TEST, TESTS, argv, tree

pytestmark = pytest.mark.skipif(shutil.which("docker") is None, reason="needs docker")


@pytest.fixture(scope="session")
def parent_image_id() -> str:
    return parent_image.ensure()


def docker_runner(image: str) -> verify_run.DockerRunner:
    # The parent's image also serves as the candidate's: it holds a Python and nothing else
    # the candidate needs.
    return verify_run.DockerRunner(image, parent_image=image)


def replay(base, runner_, source=HONEST, test=TEST):
    state, held = tree(base, source, test)
    return runner_.run(state, argv(), held, 120), runner_.replays[-1] if runner_.replays else None


def test_an_honest_module_passes_with_the_parent_in_its_own_container(tmp_path,
                                                                      parent_image_id):
    graded = docker_runner(parent_image_id)
    code, report = replay(tmp_path, graded)
    assert code == 0 and report["passed"], report
    assert runner.pytest_plugins.passed(report["items"], IDS) == len(IDS)
    # The parent measured itself: the worker's uid, the parent's own environment, and the host
    # name the runner gave its container alone.
    seen, launch = report["parent"], report["parent_launch"]
    assert seen["uid"] == graded.worker_uid != os.getuid()
    assert seen["env"] == sorted(runner.parent_env())
    assert seen["hostname"] == launch["hostname"] != socket.gethostname()
    assert runner.replay_parent(graded.replays) == {
        "runtime": "docker", "uid": graded.worker_uid, "env": sorted(runner.parent_env()),
        "image": parent_image_id}


def test_a_wrong_module_still_fails_in_the_container(tmp_path, parent_image_id):
    code, report = replay(tmp_path, docker_runner(parent_image_id),
                         HONEST.replace("return w * h", "return w + h"))
    assert code == 1 and not report["passed"]
    assert report["items"][IDS[0]]["failed"] == 2


def sealed_probe(host_file) -> str:
    """A sealed conftest that fails every test when the parent can see this host: a host-only
    file, a host-only variable, or a container runtime socket."""
    return ("import os\n\n"
            f"if (os.path.exists({str(host_file)!r}) or os.environ.get('PROBITY_HOST_ONLY')\n"
            "        or os.path.exists('/var/run/docker.sock')\n"
            "        or os.path.exists('/run/docker.sock')):\n"
            "    raise RuntimeError('the replay parent sees the verifier host')\n")


def plant(base, host_file):
    state, held = tree(base, HONEST)
    (held / runner.PYTEST_ROOT / TESTS / "conftest.py").write_text(sealed_probe(host_file))
    return state, held


def test_a_sealed_conftest_cannot_see_a_host_file_variable_or_socket(tmp_path, monkeypatch,
                                                                      parent_image_id):
    host_file = tmp_path / "grader.key"
    host_file.write_text("secret\n")
    monkeypatch.setenv("PROBITY_HOST_ONLY", "1")
    # The control: the same sealed conftest in a parent on this host sees the host file, and
    # every test fails.
    local = SubprocessRunner()
    state, held = plant(tmp_path / "host", host_file)
    assert local.run(state, argv(), held, 120) != 0
    assert not local.replays[-1]["passed"]
    graded = docker_runner(parent_image_id)
    state, held = plant(tmp_path / "container", host_file)
    code = graded.run(state, argv(), held, 120)
    assert code == 0 and graded.replays[-1]["passed"], graded.replays[-1]


def test_a_parent_run_on_the_host_is_recorded_as_the_host(tmp_path):
    # What a runner that kept the parent on this host would write: the record names the host
    # and the verifier's own uid, which the admission rule set refuses.
    local = SubprocessRunner()
    code, report = replay(tmp_path, local)
    assert code == 0, report
    assert runner.replay_parent(local.replays) == {
        "runtime": "host", "uid": os.getuid(), "env": sorted(runner.parent_env()),
        "image": None}
