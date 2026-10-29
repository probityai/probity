"""Conformance output names the verifier that produced it, and the release manifest stays current."""

import json
import runpy
from pathlib import Path

import pytest
from probity_verify.cli import main
from probity_verify.core import REFERENCE_VERIFIER_ID, adjudicate

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples/source-coverage"
EXPECTED_ID = "https://probityai.github.io/probity/verifiers/probity-verify"
MANIFEST_SCRIPT = runpy.run_path(str(ROOT / "scripts/build-release-manifest.py"))


def _decision():
    case = json.loads((EXAMPLE / "case.json").read_text())
    policy = json.loads((EXAMPLE / "policy-june.json").read_text())
    return adjudicate(case, policy, EXAMPLE)


def test_decision_carries_reference_verifier_id():
    assert _decision()["reference"] == {"verifier": {"id": EXPECTED_ID}}
    assert REFERENCE_VERIFIER_ID == EXPECTED_ID


def test_cli_json_and_packet_name_the_reference_verifier(capsys, tmp_path):
    argv = [str(EXAMPLE / "case.json"), "--policy", str(EXAMPLE / "policy-june.json")]
    assert main(argv + ["--json"]) == 0
    assert json.loads(capsys.readouterr().out)["reference"]["verifier"]["id"] == EXPECTED_ID
    assert main(argv) == 0
    assert f"Reference verifier: {EXPECTED_ID}" in capsys.readouterr().out


def test_release_manifest_is_current_and_names_the_verifier():
    recorded = json.loads((ROOT / "docs/release-manifest.json").read_text())
    assert recorded == MANIFEST_SCRIPT["build"]()
    assert recorded["reference"]["verifier"]["id"] == EXPECTED_ID
    assert len(recorded["expectations_digest"]) == 64
    assert {item["suite"] for item in recorded["corpora"]} == {
        "done-checks/v1", "operand-lineage/v1", "source-text-coverage/v1"}


def test_release_manifest_check_fails_when_stale(tmp_path, monkeypatch):
    module = dict(MANIFEST_SCRIPT)
    stale = tmp_path / "release-manifest.json"
    stale.write_text("{}\n")
    module["main"].__globals__["OUTPUT"] = stale
    try:
        monkeypatch.setattr("sys.argv", ["build-release-manifest.py", "--check"])
        assert module["main"]() == 1
    finally:
        module["main"].__globals__["OUTPUT"] = ROOT / "docs/release-manifest.json"


@pytest.mark.parametrize("path", ["docs/release-manifest.json"])
def test_manifest_matches_pyproject_version(path):
    import tomllib
    version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    assert json.loads((ROOT / path).read_text())["version"] == version
