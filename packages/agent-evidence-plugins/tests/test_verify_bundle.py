"""The gate against real bundles built from agent-evidence-vectors members."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "plugins" / "verdict-bundle-gate" / "scripts" / "verify_bundle.py"
FIXTURES = ROOT / "tests" / "fixtures"
GOOD = FIXTURES / "honest.decision.zip"
CONTRADICTED = FIXTURES / "honest-failure.decision.zip"


@pytest.fixture(autouse=True)
def replay_tool(monkeypatch):
    """Run the pinned probity-verify of this environment, not whatever is on PATH."""
    monkeypatch.setenv("PROBITY_BUNDLE_CMD", f"{sys.executable} -m probity_verify.bundle")
    monkeypatch.delenv("PROBITY_BUNDLE_ALLOW", raising=False)
    monkeypatch.delenv("PROBITY_BUNDLE_GLOBS", raising=False)


def run(*args: str, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args], input=stdin, capture_output=True, text=True,
        env=os.environ.copy(), check=False,
    )


def tamper(source: Path, target: Path, member: str = "artifacts/tree.json") -> Path:
    """Copy a bundle, changing one bound artifact by one byte."""
    with zipfile.ZipFile(source) as zin, zipfile.ZipFile(target, "w") as zout:
        for info in zin.infolist():
            data = zin.read(info)
            if info.filename == member:
                data = data + b" "
            zout.writestr(info, data)
    return target


def test_supported_bundle_passes():
    done = run(str(GOOD))
    assert done.returncode == 0, done.stderr
    assert "OK" in done.stdout and "supported" in done.stdout


def test_contradicted_bundle_fails_with_exit_1():
    done = run(str(CONTRADICTED))
    assert done.returncode == 1
    assert "contradicted" in done.stderr and "acceptance_failed_in_verifier" in done.stderr


def test_allow_list_accepts_a_named_decision():
    done = run(str(CONTRADICTED), "--allow", "supported,contradicted")
    assert done.returncode == 0, done.stderr


def test_allow_env_matches_the_flag(monkeypatch):
    monkeypatch.setenv("PROBITY_BUNDLE_ALLOW", "contradicted")
    assert run(str(CONTRADICTED)).returncode == 0
    assert run(str(GOOD)).returncode == 1


def test_unknown_allow_value_is_refused():
    done = run(str(GOOD), "--allow", "valid")
    assert done.returncode == 2 and "--allow" in done.stderr


def test_tampered_artifact_is_refused_with_exit_2(tmp_path):
    bad = tamper(GOOD, tmp_path / "t.decision.zip")
    done = run(str(bad))
    assert done.returncode == 2
    assert done.stderr.startswith("FAIL")


def test_tampered_decision_is_refused(tmp_path):
    """Editing the stored verdict to a better one must not pass."""
    with zipfile.ZipFile(CONTRADICTED) as zin:
        members = {i.filename: zin.read(i) for i in zin.infolist()}
    decision = json.loads(members["decision.json"])
    decision["decision"] = "supported"
    members["decision.json"] = json.dumps(decision, sort_keys=True).encode()
    forged = tmp_path / "forged.decision.zip"
    with zipfile.ZipFile(forged, "w") as zout:
        for name, data in members.items():
            zout.writestr(name, data)
    assert run(str(forged)).returncode == 2


def test_missing_file_fails_closed(tmp_path):
    done = run(str(tmp_path / "absent.decision.zip"))
    assert done.returncode == 2 and "no such file" in done.stderr


def test_non_zip_fails_closed(tmp_path):
    junk = tmp_path / "junk.decision.zip"
    junk.write_bytes(b"not a zip")
    assert run(str(junk)).returncode == 2


def test_missing_verifier_fails_closed(monkeypatch):
    monkeypatch.setenv("PROBITY_BUNDLE_CMD", "/nonexistent/probity-bundle")
    done = run(str(GOOD))
    assert done.returncode == 2 and "did not run" in done.stderr


def hook_payload(tmp_path: Path, bundle: Path, key: str = "file_path") -> str:
    return json.dumps({"cwd": str(tmp_path), "tool_name": "Write", "tool_input": {key: str(bundle)}})


def test_hook_passes_a_good_bundle(tmp_path):
    bundle = shutil.copy(GOOD, tmp_path / "run.decision.zip")
    done = run("--hook", stdin=hook_payload(tmp_path, Path(bundle)))
    assert done.returncode == 0 and "OK" in done.stdout


def test_hook_blocks_a_contradicted_bundle_with_exit_2(tmp_path):
    bundle = shutil.copy(CONTRADICTED, tmp_path / "run.verdict.zip")
    done = run("--hook", stdin=hook_payload(tmp_path, Path(bundle)))
    assert done.returncode == 2 and "contradicted" in done.stderr


def test_hook_finds_a_relative_path_inside_a_shell_command(tmp_path):
    shutil.copy(CONTRADICTED, tmp_path / "out.decision.zip")
    payload = json.dumps(
        {"cwd": str(tmp_path), "tool_input": {"command": "curl -o out.decision.zip https://x.example/b"}}
    )
    assert run("--hook", stdin=payload).returncode == 2


def test_hook_ignores_a_payload_without_a_bundle(tmp_path):
    payload = json.dumps({"cwd": str(tmp_path), "tool_input": {"file_path": str(tmp_path / "notes.txt")}})
    done = run("--hook", stdin=payload)
    assert done.returncode == 0 and done.stdout == "" and done.stderr == ""


def test_hook_ignores_other_zips(tmp_path):
    other = tmp_path / "archive.zip"
    shutil.copy(CONTRADICTED, other)
    assert run("--hook", stdin=hook_payload(tmp_path, other)).returncode == 0


def test_hook_ignores_non_json_stdin():
    assert run("--hook", stdin="not json").returncode == 0


def test_manifests_parse_and_agree():
    market = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text())
    for entry in market["plugins"]:
        base = ROOT / entry["source"]
        manifest = json.loads((base / ".claude-plugin" / "plugin.json").read_text())
        assert manifest["name"] == entry["name"] and manifest["version"] == entry["version"]
        hooks = json.loads((base / "hooks" / "hooks.json").read_text())
        command = hooks["hooks"]["PostToolUse"][0]["hooks"][0]["command"]
        assert "${CLAUDE_PLUGIN_ROOT}/scripts/verify_bundle.py" in command
        assert (base / "scripts" / "verify_bundle.py").is_file()
    json.loads((ROOT / "cursor" / "hooks.json").read_text())
