"""The verifier's account of itself (``_isolation``) and the runner's argv rule, without docker."""
from __future__ import annotations

from pathlib import Path

import pytest

from probity_observer.done import verify_run
from probity_observer.done.replay import COMMAND

COUNTS = {"expected": 1, "collected": 1, "skipped": 0}


class Runner(verify_run.DockerRunner):
    def groups(self):
        return []


def report(tmp_path, argvs):
    commands = [{"argv": argv} for argv in argvs]
    return verify_run._isolation("c" * 64, ("a" * 64, "a" * 64), Runner("img"), commands,
                                 (1, 2), tmp_path, None, COUNTS)["verifier"]


def full_report(tmp_path, argvs):
    commands = [{"argv": argv} for argv in argvs]
    return verify_run._isolation("c" * 64, ("a" * 64, "a" * 64), Runner("img"), commands,
                                 (1, 2), tmp_path, None, COUNTS)


@pytest.mark.parametrize("argv", [["python", "-m", "pytest"], ["python", "-I", "-m", "pytest"],
                                  ["env", "PYTHONPATH=/x", "python", "-I", "-m", "pytest"],
                                  ["sh", "-c", "X=1 python -I -m pytest"], ["make", "check"]])
def test_no_unmeasured_isolation_fact_is_reported(tmp_path, argv):
    """Neither the scrubbed-environment nor the Python-isolation fact can be read off an argv,
    so the report carries neither, whatever the command looks like."""
    found = full_report(tmp_path, [argv])
    assert "python_isolated" not in found["verifier"]
    assert "env_scrubbed" not in found["worker"]
    assert found["worker"] == {"uid": verify_run.WORKER_UID, "supplementary_groups": [],
                               "scratch_copy": True}


def test_assertions_in_parent_is_false_when_nothing_was_graded(tmp_path):
    assert report(tmp_path, [])["assertions_in_parent"] is False


def test_assertions_in_parent_needs_every_graded_command_to_be_a_replay(tmp_path):
    assert report(tmp_path, [[COMMAND, "x"]])["assertions_in_parent"] is True
    assert report(tmp_path, [[COMMAND, "x"], ["pytest"]])["assertions_in_parent"] is False


def test_the_runner_refuses_a_leading_environment_assignment(tmp_path):
    with pytest.raises(verify_run.GradeError, match="environment assignment"):
        Runner("img").command("n", tmp_path, ["PYTHONPATH=/injected", "python", "-m", "pytest"],
                              False)


def test_the_runner_builds_a_plain_command(tmp_path):
    command = Runner("img").command("n", tmp_path, ["python", "-m", "pytest"], False)
    assert command[-3:] == ["python", "-m", "pytest"]
    assert "PYTHONPATH=/injected" not in command
