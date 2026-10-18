"""The shared invocation model: honest spellings of one run match, different runs never do."""

import pytest

from probity_verify.adapters.done_argv import Invocation, invocation, unwrap

SEALED = ["pytest", "-q", "tests"]


@pytest.mark.parametrize("argv,exe", [
    (["pytest", "-q", "tests"], None),
    (["pytest", "tests", "-q"], None),
    (["pytest", "-q", "tests", "-x"], None),
    (["pytest", "-q", "./tests/"], None),
    (["/usr/local/bin/pytest", "--tb=short", "-v", "tests"], None),
    (["python", "-m", "pytest", "-q", "tests"], None),
    (["/usr/local/bin/python3.12", "-m", "pytest", "tests"], "/usr/local/bin/python3.12"),
    (["python3", "-I", "-mpytest", "tests", "--maxfail", "1"], None),
])
def test_reporting_options_order_and_module_runs_are_one_invocation(argv, exe):
    assert invocation(argv, exe) == invocation(SEALED)


@pytest.mark.parametrize("argv", [
    ["pytest", "-q", "tests", "-k", "not slow"],
    ["pytest", "-q", "tests", "--deselect", "tests/test_a.py::test_x"],
    ["pytest", "-q", "tests", "-p", "no:randomly"],
    ["pytest", "-q", "tests", "--lf"],
    ["pytest", "-q", "tests", "-o", "addopts="],
    ["pytest", "-q", "tests", "--noconftest"],
    ["pytest", "-q", "tests", "--co"],
    ["pytest", "-q", "tests", "-W", "ignore"],
    ["pytest", "-q", "tests/test_a.py"],
    ["pytest", "-q", "tests", "other"],
    ["python", "-c", "import pytest; pytest.main(['-q', 'tests'])"],
])
def test_options_that_choose_or_change_what_runs_never_match(argv):
    assert invocation(argv) != invocation(SEALED)


def test_a_script_keeps_its_arguments_in_order():
    assert invocation(["python3", "./test.py"]) == Invocation("python3", ("test.py",))
    assert invocation(["python", "test.py", "a", "b"]).args != invocation(
        ["python", "test.py", "b", "a"]).args


@pytest.mark.parametrize("argv,cwd,expected", [
    (["timeout", "60", "python", "test.py"], None, (["python", "test.py"], None)),
    (["timeout", "-s", "KILL", "60", "pytest", "-q", "tests"], None,
     (["pytest", "-q", "tests"], None)),
    (["env", "PYTHONHASHSEED=0", "python", "test.py"], None, (["python", "test.py"], None)),
    (["PYTHONHASHSEED=0", "python", "test.py"], None, (["python", "test.py"], None)),
    (["uv", "run", "pytest", "-q", "tests"], None, (["pytest", "-q", "tests"], None)),
    (["poetry", "run", "pytest", "-q", "tests"], None, (["pytest", "-q", "tests"], None)),
    (["sh", "-c", "cd /workspace && python test.py"], None,
     (["python", "test.py"], "/workspace")),
    (["bash", "-lc", "cd /workspace; python test.py"], None,
     (["python", "test.py"], "/workspace")),
    (["sh", "-c", "python test.py 2>&1 | tee out.log"], "/workspace",
     (["python", "test.py"], "/workspace")),
    (["sh", "-c", "cd sub && timeout 5 python test.py 2>&1"], "/workspace",
     (["python", "test.py"], "/workspace/sub")),
])
def test_unwrap_takes_a_printed_line_to_the_command_it_runs(argv, cwd, expected):
    assert unwrap(argv, cwd) == expected


@pytest.mark.parametrize("line", [
    "python test.py && echo ok", "python test.py || true", "python test.py > out",
    "python test.py; python other.py", "$(python test.py)", "python test.py | grep -v FAIL",
])
def test_other_shell_syntax_is_no_command(line):
    assert unwrap(["sh", "-c", line]) is None
