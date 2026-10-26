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


@pytest.mark.parametrize("program", ["python", "python3", "/usr/local/bin/python",
                                     "/usr/bin/python3.12"])
def test_a_python_command_without_isolation_flags_is_not_isolated(tmp_path, program):
    assert report(tmp_path, [[program, "-m", "pytest"]])["python_isolated"] is False


@pytest.mark.parametrize("program", ["python", "/usr/local/bin/python"])
def test_a_python_command_with_isolation_flags_is_isolated(tmp_path, program):
    assert report(tmp_path, [[program, "-I", "-m", "pytest"]])["python_isolated"] is True


def test_assertions_in_parent_is_false_when_nothing_was_graded(tmp_path):
    assert report(tmp_path, [])["assertions_in_parent"] is False


def test_assertions_in_parent_needs_every_graded_command_to_be_a_replay(tmp_path):
    assert report(tmp_path, [[COMMAND, "x"]])["assertions_in_parent"] is True
    assert report(tmp_path, [[COMMAND, "x"], ["pytest"]])["assertions_in_parent"] is False
