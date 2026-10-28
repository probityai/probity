"""The replay parent's container command carries every lockdown flag, in front of the image.

A parent started without the flags would still run, and the tests that start real containers
could not tell: the image's own default user is the worker's, so only the missing network,
capability and filesystem limits would differ. This reads the command itself.
"""

from __future__ import annotations

from pathlib import Path

from probity_observer.done import runner, verify_run

IMAGE = "sha256:" + "0" * 64


def parent_command(runner: verify_run.DockerRunner) -> list[str]:
    return runner.parent_command("parent", "host-1", [(Path("/src"), "/sealed")],
                                 ["python", "-m", "parent"])


def contains_run(command: list[str], run: list[str]) -> bool:
    return any(command[i:i + len(run)] == run for i in range(len(command) - len(run) + 1))


def test_the_parent_container_carries_every_lockdown_flag_before_its_image():
    runner = verify_run.DockerRunner("worker-image", parent_image=IMAGE)
    command = parent_command(runner)
    assert contains_run(command, runner.flags())
    assert command.index(IMAGE) > command.index("--read-only")


def test_the_parent_container_starts_without_network_or_capabilities():
    command = parent_command(verify_run.DockerRunner("worker-image", parent_image=IMAGE))
    assert command[command.index("--network") + 1] == "none"
    assert command[command.index("--cap-drop") + 1] == "ALL"
    assert "no-new-privileges" in command and "--read-only" in command
    assert command[command.index("--user") + 1].split(":")[0] != "0"


def test_the_parent_container_has_read_only_mounts_and_no_socket():
    command = parent_command(verify_run.DockerRunner("worker-image", parent_image=IMAGE))
    volumes = [command[i + 1] for i, word in enumerate(command) if word == "--volume"]
    assert volumes == ["/src:/sealed:ro"]
    assert not any("docker.sock" in word for word in command)


def assigned_names(command: list[str], image: str) -> set[str]:
    """The names a container command gives its process: the assignments ``env -i`` takes
    right after the image."""
    start = command.index(image) + 2
    assert command[start - 1] == "-i"
    names = set()
    for word in command[start:]:
        if "=" not in word:
            break
        names.add(word.split("=", 1)[0])
    return names


def test_no_name_added_on_this_host_reaches_a_container(monkeypatch):
    # A coverage run of this suite adds coverage's start variables, which name this host's
    # paths, to the host's scrubbed environment (conftest.py). The parent, the worker and a
    # replay's children are given the container's fixed environment and nothing else; a parent
    # given the host's carried both names and the isolation rule set refused it.
    monkeypatch.setitem(runner.SCRUBBED_ENV, "COVERAGE_FILE", "/home/verifier/.coverage")
    docker = verify_run.DockerRunner("worker-image", parent_image=IMAGE)
    parent = parent_command(docker)
    assert assigned_names(parent, IMAGE) == {*runner.CONTAINER_ENV,
                                             "PYTEST_DISABLE_PLUGIN_AUTOLOAD"}
    assert set(runner.parent_container_env()) == assigned_names(parent, IMAGE)
    worker = docker.command("worker", Path("/scratch"), ["python", "-V"], False)
    child = docker.child_argv(Path("/candidate"), "pass")[0]
    for command in (worker, child):
        assert assigned_names(command, "worker-image") == set(runner.CONTAINER_ENV)
    assert not any("/home/verifier" in word for word in (*parent, *worker, *child))
