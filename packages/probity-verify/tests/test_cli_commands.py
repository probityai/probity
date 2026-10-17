"""CLI output must preserve the decision and refuse broken packet writes."""

import json
from pathlib import Path

from probity_verify.cli import main

ROOT = Path(__file__).resolve().parents[1] / "examples/source-coverage"


def test_cli_text_json_and_packet_agree(tmp_path, capsys):
    argv = [str(ROOT / "case.json"), "--policy", str(ROOT / "policy-june.json")]
    assert main(argv) == 0
    text = capsys.readouterr().out
    assert "Decision: contradicted" in text
    packet = tmp_path / "decision.txt"
    assert main(argv + ["--packet", str(packet), "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["decision"] == "contradicted"
    assert packet.read_text() == text


def test_cli_failed_packet_write_does_not_print_a_verdict(tmp_path, capsys):
    argv = [str(ROOT / "case.json"), "--policy", str(ROOT / "policy-june.json"),
            "--packet", str(tmp_path / "absent/packet.txt"), "--json"]
    assert main(argv) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "probity-verify:" in captured.err
