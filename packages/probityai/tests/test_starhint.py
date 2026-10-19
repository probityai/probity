"""The star hint prints once, to a terminal, outside CI, and never beside JSON."""

from __future__ import annotations

import io

import pytest
from probityai import main
from probityai.starhint import OPT_OUT, REPO, maybe_print_hint


class _Stream(io.StringIO):
    def __init__(self, tty: bool) -> None:
        super().__init__()
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


def _env(tmp_path, **extra):
    return {"HOME": str(tmp_path), "XDG_STATE_HOME": str(tmp_path / "state"), **extra}


def _run(tmp_path, argv=(), tty=True, **extra):
    stream = _Stream(tty)
    return maybe_print_hint(list(argv), _env(tmp_path, **extra), stream), stream.getvalue()


def test_first_run_prints_the_hint_once(tmp_path):
    printed, text = _run(tmp_path)
    assert printed and text.strip() == f"Found this useful? Star github.com/{REPO}"
    assert _run(tmp_path) == (False, "")


@pytest.mark.parametrize(
    "kwargs",
    [{"CI": "true"}, {"tty": False}, {"argv": ["--json"]}, {OPT_OUT: "1"}],
    ids=["ci", "not-a-terminal", "json", "opt-out"],
)
def test_quiet_conditions(tmp_path, kwargs):
    assert _run(tmp_path, **kwargs) == (False, "")
    assert _run(tmp_path) [0] is True  # the quiet run did not use up the one showing


def test_unwritable_state_stays_silent(tmp_path):
    (tmp_path / "state").write_text("a file where the directory should be\n")
    assert _run(tmp_path) == (False, "")


def test_hint_follows_only_a_successful_command(tmp_path, monkeypatch, capsys):
    import types

    from probityai import register_leaf

    def register(subparsers):
        parser = subparsers.add_parser("x")
        parser.add_argument("--code", type=int, default=0)
        register_leaf(parser, handler=lambda args: args.code)

    class _Point:
        name, value, group = "x", "m:register", "g"
        dist = types.SimpleNamespace(name="d")

        def load(self):
            return register

    class _Err(io.StringIO):
        def isatty(self):
            return True

    for key, value in _env(tmp_path).items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv(OPT_OUT, raising=False)
    err = _Err()
    monkeypatch.setattr("sys.stderr", err)
    assert main(["x", "--code", "3"], [_Point()]) == 3
    assert err.getvalue() == ""
    assert main(["x"], [_Point()]) == 0
    assert REPO in err.getvalue()
    assert capsys.readouterr().out == ""
