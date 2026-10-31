"""Tests for subcommand registration and dispatch in the probityai launcher."""

from __future__ import annotations

import json
import sys
import types
from importlib.metadata import EntryPoint, entry_points, version
from importlib.resources import files
from pathlib import Path

import pytest
from probityai import GROUP, main, register_leaf


class _Point:
    """An entry point as an installed distribution exposes it."""

    def __init__(self, name: str, value: str, dist: str = "member-a") -> None:
        self.name, self.value, self.group = name, value, GROUP
        self.dist = types.SimpleNamespace(name=dist)

    def load(self):
        return EntryPoint(name=self.name, value=self.value, group=self.group).load()


def _plugin(monkeypatch, module_name: str, register) -> str:
    module = types.ModuleType(module_name)
    module.register = register
    monkeypatch.setitem(sys.modules, module_name, module)
    return f"{module_name}:register"


def _leaf(name: str, calls: list, status: int = 7):
    def register(subparsers):
        parser = subparsers.add_parser(name, help=f"the {name} command")
        parser.add_argument("--flag")
        register_leaf(parser, handler=lambda args: calls.append((name, args.flag)) or status)
    return register


def test_dispatch_runs_the_handler_with_parsed_arguments(monkeypatch):
    calls = []
    value = _plugin(monkeypatch, "plug_fake", _leaf("fake", calls))
    assert main(["fake", "--flag", "x"], points=[_Point("fake", value)]) == 7
    assert calls == [("fake", "x")]


def test_help_lists_every_registered_command(monkeypatch, capsys):
    a = _plugin(monkeypatch, "plug_a", _leaf("alpha", []))
    b = _plugin(monkeypatch, "plug_b", _leaf("beta", []))
    with pytest.raises(SystemExit) as stop:
        main(["--help"], points=[_Point("beta", b), _Point("alpha", a)])
    assert stop.value.code == 0
    out = capsys.readouterr().out
    assert "the alpha command" in out and "the beta command" in out


def test_no_command_is_a_usage_error(monkeypatch, capsys):
    value = _plugin(monkeypatch, "plug_fake", _leaf("fake", []))
    assert main([], points=[_Point("fake", value)]) == 2
    assert "a command is required" in capsys.readouterr().err


def test_no_commands_installed_is_reported_not_hidden(capsys):
    assert main([], points=[]) == 2
    assert "no commands are installed" in capsys.readouterr().err


def test_unknown_command_is_refused_by_argparse(monkeypatch, capsys):
    value = _plugin(monkeypatch, "plug_fake", _leaf("fake", []))
    with pytest.raises(SystemExit) as stop:
        main(["nope"], points=[_Point("fake", value)])
    assert stop.value.code == 2
    assert "invalid choice: 'nope'" in capsys.readouterr().err


def test_two_entry_points_with_one_name_are_refused(monkeypatch, capsys):
    a = _plugin(monkeypatch, "plug_a", _leaf("fake", []))
    b = _plugin(monkeypatch, "plug_b", _leaf("fake", []))
    assert main(["fake"], points=[_Point("fake", a, "member-a"), _Point("fake", b, "member-b")]) == 2
    assert "is already registered" in capsys.readouterr().err


def test_a_plugin_that_replaces_another_command_is_refused(monkeypatch, capsys):
    a = _plugin(monkeypatch, "plug_a", _leaf("alpha", []))

    def sneaky(subparsers):
        _leaf("zeta", [])(subparsers)
        subparsers.choices["alpha"] = subparsers.choices["zeta"]

    z = _plugin(monkeypatch, "plug_z", sneaky)
    assert main(["alpha"], points=[_Point("alpha", a), _Point("zeta", z)]) == 2
    assert "replaced the registered subcommand(s) alpha" in capsys.readouterr().err


def test_a_plugin_that_registers_another_name_is_refused(monkeypatch, capsys):
    value = _plugin(monkeypatch, "plug_fake", _leaf("other", []))
    assert main(["fake"], points=[_Point("fake", value)]) == 2
    assert "did not register a subcommand named 'fake'" in capsys.readouterr().err


def test_a_plugin_that_cannot_import_is_reported_with_its_name(capsys):
    assert main(["--help"], points=[_Point("broken", "no_such_module_for_probity:register")]) == 2
    err = capsys.readouterr().err
    assert "'broken' from no_such_module_for_probity:register (member-a) failed to register" in err


def test_a_plugin_whose_register_raises_is_reported(monkeypatch, capsys):
    def boom(subparsers):
        raise RuntimeError("bad state")

    value = _plugin(monkeypatch, "plug_boom", boom)
    assert main(["boom"], points=[_Point("boom", value)]) == 2
    assert "failed to register: bad state" in capsys.readouterr().err


def test_version_reports_the_installed_distribution(capsys):
    with pytest.raises(SystemExit):
        main(["--version"], points=[])
    assert capsys.readouterr().out.startswith(f"probityai {version('probityai')}")


def test_installed_probity_verify_registers_verify():
    names = {point.name for point in entry_points(group=GROUP)}
    assert "verify" in names


def _samples(tmp_path):
    for item in files("probity_verify.samples").iterdir():
        if item.name.endswith((".json", ".html", ".txt")):
            (tmp_path / item.name).write_bytes(item.read_bytes())


def test_probity_verify_runs_the_installed_verifier(tmp_path, capsys):
    _samples(tmp_path)
    status = main(["verify", str(tmp_path / "case.json"), "--policy", str(tmp_path / "policy-june.json"), "--json"])
    assert status == 0
    result = json.loads(capsys.readouterr().out)
    assert (result["decision"], result["reason"]) == ("contradicted", "selected_span_missing_from_record")


def test_probity_verify_errors_carry_the_subcommand_program_name(tmp_path, capsys):
    status = main(["verify", str(tmp_path / "missing.json"), "--policy", str(tmp_path / "missing.json")])
    assert status == 2
    assert capsys.readouterr().err.startswith("probityai verify: ")


_DONE = Path(__file__).resolve().parents[2] / "probity-verify/examples/done-receipt"


@pytest.mark.parametrize("example, decision, reason", [
    ("honest", "supported", "done_receipt_accepted"),
    ("tampered-grader", "contradicted", "external_effect_on_grader_path"),
    ("honest-failure", "contradicted", "acceptance_failed_in_verifier"),
])
def test_probity_verify_checks_a_done_receipt(capsys, example, decision, reason):
    case = _DONE / example
    status = main(["verify", str(case / "receipt.case.json"), "--policy", str(case / "receipt.policy.json"), "--json"])
    assert status == 0
    result = json.loads(capsys.readouterr().out)
    assert result["claim_type"] == "done_receipt/v2"
    assert (result["decision"], result["reason"]) == (decision, reason)


def test_the_distribution_installs_one_command_named_probityai():
    """The binary is the word the user typed to install it, with no second name (no alias)."""
    from importlib.metadata import distribution

    scripts = {ep.name for ep in distribution("probityai").entry_points if ep.group == "console_scripts"}
    assert scripts == {"probityai"}
