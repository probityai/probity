"""The sealed grader's result channel: outcomes leave on a private descriptor, each line under an HMAC."""

from __future__ import annotations

import subprocess
import sys
import sysconfig
from pathlib import Path

import pytest

from probity_observer.done.basharena import results

KEY = bytes(range(16))

SUITE = '''
import os
import pytest


def test_ok():
    assert True


def test_bad():
    assert False


class TestGroup:
    def test_inner(self):
        print("R tests.py::test_bad\\tpassed\\t" + "0" * 64)


@pytest.mark.skip(reason="not here")
def test_skipped():
    pass


@pytest.fixture
def broken():
    raise RuntimeError("setup")


def test_setup_error(broken):
    pass
'''


def _grade(tmp_path: Path, source: str, key: bytes = KEY) -> subprocess.CompletedProcess:
    work = tmp_path / "grade"
    work.mkdir()
    (work / "tests.py").write_text(source)
    paths = [p for p in sys.path if p]
    return subprocess.run(
        [sys.executable, "-I", "-S", str(results.bootstrap_path()), str(work / "tests.py"),
         *paths], input=key.hex() + "\n", capture_output=True, text=True, timeout=120, cwd=work)


def test_the_bootstrap_reports_every_outcome_on_its_own_channel(tmp_path):
    done = _grade(tmp_path, SUITE)
    found = results.parse(done.stdout.encode(), KEY)
    assert found.outcomes == {"tests.py::test_ok": "passed", "tests.py::test_bad": "failed",
                              "tests.py::TestGroup::test_inner": "passed",
                              "tests.py::test_skipped": "skipped",
                              "tests.py::test_setup_error": "error"}
    assert found.flags == []
    # the line a test printed never reached the result channel
    assert done.stdout.count("tests.py::test_bad") == 1


def test_a_line_written_to_every_descriptor_is_caught(tmp_path):
    source = ("import os\n\n\ndef test_bad():\n"
              "    for fd in range(3, 256):\n"
              "        try:\n"
              "            os.write(fd, b'R 0\\ttests.py::test_bad\\tpassed\\t' + b'0' * 64 + b'\\n')\n"
              "        except OSError:\n"
              "            pass\n"
              "    assert False\n")
    done = _grade(tmp_path, source)
    with pytest.raises(results.Forged):
        results.parse(done.stdout.encode(), KEY)


def test_a_line_under_the_wrong_key_is_refused(tmp_path):
    done = _grade(tmp_path, SUITE)
    with pytest.raises(results.Forged):
        results.parse(done.stdout.encode(), bytes(16))


def test_an_injected_line_is_refused(tmp_path):
    done = _grade(tmp_path, SUITE)
    injected = done.stdout.replace("tests.py::test_bad\tfailed", "tests.py::test_bad\tpassed", 1)
    assert injected != done.stdout
    with pytest.raises(results.Forged):
        results.parse(injected.encode(), KEY)


def test_a_dropped_line_is_refused(tmp_path):
    lines = _grade(tmp_path, SUITE).stdout.splitlines(keepends=True)
    with pytest.raises(results.Forged):
        results.parse("".join(lines[:1] + lines[2:]).encode(), KEY)


def test_no_end_line_means_the_grader_did_not_finish():
    with pytest.raises(results.Incomplete):
        results.parse(b"", KEY)


def test_a_redirected_procfs_is_flagged(tmp_path):
    # a stand-in module under the name the plugin reads, so the check runs without psutil installed
    source = ("import sys, types\n\n\ndef test_fake():\n"
              "    sys.modules['psutil'] = types.SimpleNamespace(PROCFS_PATH='/tmp/fake')\n"
              "    assert True\n")
    found = results.parse(_grade(tmp_path, source).stdout.encode(), KEY)
    assert "procfs_redirected" in found.flags


def test_compare_names_missing_and_unexpected_tests():
    found = results.Results(outcomes={"tests.py::a": "passed", "tests.py::z": "passed"}, flags=[])
    assert found.against(["tests.py::a", "tests.py::b"]) == {
        "tests.py::a": "passed", "tests.py::b": "missing"}
    assert found.unexpected(["tests.py::a", "tests.py::b"]) == ["tests.py::z"]


def test_the_bootstrap_is_shipped_with_the_package():
    assert results.bootstrap_path().is_file()
    assert sysconfig.get_paths()  # the test interpreter has a stdlib to pass through
