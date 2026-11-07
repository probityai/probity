"""Real Inspect runs of the sealed manifest, and probity-verify judging its digests.

Needs the ``inspect`` and ``done`` extras: ``pip install -e '.[test,inspect,done]'`` from the package
root, then ``python -m pytest -q interop/inspect-sealed-manifest-2026-11-03/test_real_run.py``.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import zipfile
from importlib import metadata
from pathlib import Path
from typing import Any

import pytest
from inspect_ai import Task
from inspect_ai import eval as inspect_eval
from inspect_ai.dataset import Sample
from inspect_ai.log import read_eval_log, write_eval_log
from inspect_ai.scorer import match
from inspect_ai.solver import generate

from probity_observer import inspect_binding as binding

# Raised inside inspect_ai's own retry module on every model call; nothing here can change it.
pytestmark = pytest.mark.filterwarnings("ignore:The 'initial' parameter is deprecated:DeprecationWarning")

TASK_SOURCE = '''
from inspect_ai import Task, task
from inspect_ai.dataset import Sample
from inspect_ai.scorer import match
from inspect_ai.solver import generate


@task
def tiny():
    return Task(
        dataset=[Sample(input="2+2?", target="4", id="a"), Sample(input="3+3?", target="6", id="b")],
        solver=generate(),
        scorer=match(),
    )
'''


def _tiny_task() -> Task:
    return Task(
        dataset=[
            Sample(input="2+2?", target="4", id="a", files={"x.txt": "hi"}),
            Sample(input="3+3?", target="6", id="b"),
        ],
        solver=generate(),
        scorer=match(),
    )


def _run(tmp_path: Path, **kwargs: Any) -> str:
    logs = inspect_eval(_tiny_task(), model="mockllm/model", log_dir=str(tmp_path / "logs"),
                        display="none", **kwargs)
    assert logs[0].status == "success"
    return logs[0].location


def test_a_real_mockllm_run_writes_a_manifest_beside_the_log_through_the_entry_point(tmp_path: Path) -> None:
    location = _run(tmp_path, epochs=2)
    manifest = json.loads(binding.manifest_path(location).read_text(encoding="utf-8"))

    assert binding.manifest_path(location).name == Path(location).name + ".sealed"
    assert manifest["schema"] == binding.SCHEMA
    assert manifest["status"] == "success"
    assert manifest["counts"] == {"samples_in_log": 4, "samples_with_error": 0, "dataset_samples": 2,
                                  "epochs": 2}
    assert manifest["read_with"]["inspect_ai"] == manifest["log_inspect_ai"] == "0.3.287"
    assert manifest["read_with"]["inspect_ai"] == metadata.version("inspect-ai")
    assert manifest["read_with"]["agent_evidence_observer"] == metadata.version("agent-evidence-observer")
    assert set(manifest["not_captured"]) == {"container_observation", "input_file_digests",
                                             "grading_artifact_digests"}
    assert "execution-truth" in manifest["doesNotAssert"]
    result = binding.verify(location)
    assert result is not None and result.established


def test_inspect_does_not_list_the_manifest_as_a_log(tmp_path: Path) -> None:
    from inspect_ai.log import list_eval_logs

    location = _run(tmp_path)
    assert binding.manifest_path(location).exists()
    assert [Path(info.name).name for info in list_eval_logs(str(tmp_path / "logs"))] == [Path(location).name]


def test_the_hook_does_not_write_into_the_log(tmp_path: Path) -> None:
    location = _run(tmp_path)
    log = read_eval_log(location)
    assert not log.metadata
    assert not (log.eval.metadata or {})
    with zipfile.ZipFile(location) as archive:
        assert not any("sealed" in name for name in archive.namelist())
    assert "sha256:" not in json.dumps(log.model_dump(mode="json"))


def test_inspect_eval_cli_with_the_extra_writes_the_manifest(tmp_path: Path) -> None:
    task_file = tmp_path / "tiny_task.py"
    task_file.write_text(TASK_SOURCE, encoding="utf-8")
    logs = tmp_path / "cli-logs"
    command = [str(Path(sys.executable).parent / "inspect"), "eval", task_file.name, "--model", "mockllm/model",
               "--display", "none", "--log-dir", str(logs)]
    done = subprocess.run(command, capture_output=True, text=True, check=False, timeout=240, cwd=tmp_path)
    assert done.returncode == 0, done.stderr
    written = sorted(path.name for path in logs.iterdir())
    assert len(written) == 2 and written[1] == written[0] + ".sealed"
    result = binding.verify(str(logs / written[0]))
    assert result is not None and result.established


def test_the_switch_turns_the_hook_off(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_EVIDENCE_INSPECT_SEAL", "off")
    location = _run(tmp_path)
    assert not binding.manifest_path(location).exists()
    assert binding.verify(location) is None


def test_verify_survives_a_restamp_and_reports_a_regrade_and_a_changed_environment(tmp_path: Path) -> None:
    location = _run(tmp_path)

    log = read_eval_log(location)
    log.eval.eval_set_id = "adopted"
    log.eval.metadata = {"created_by": "importer"}
    log.tags = ["handled"]
    write_eval_log(log, location)
    restamped = binding.verify(location)
    assert restamped is not None and restamped.established

    log = read_eval_log(location)
    assert log.samples
    next(iter(log.samples[0].scores.values())).value = "C"
    write_eval_log(log, location)
    regraded = binding.verify(location)
    assert regraded is not None and regraded.summary == "same execution, different grading"

    log = read_eval_log(location)
    log.eval.packages = {"inspect_ai": "0.0.0"}
    write_eval_log(log, location)
    both = binding.verify(location)
    assert both is not None and not both.execution_match


def test_a_log_with_no_manifest_reads_as_nothing_recorded(tmp_path: Path) -> None:
    location = _run(tmp_path)
    binding.manifest_path(location).unlink()
    assert binding.read_manifest(location) is None
    assert binding.verify(location) is None
    assert binding.main(["verify", location]) == 2


def test_the_command_line_seals_and_verifies(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    location = _run(tmp_path)
    binding.manifest_path(location).unlink()
    assert binding.main(["seal", location]) == 0
    assert binding.main(["verify", location]) == 0
    assert "both reproduce" in capsys.readouterr().out


def _verify(tmp_path: Path, name: str, claimed: bytes, source: bytes, digest: str) -> tuple[int, dict[str, Any]]:
    case_dir = tmp_path / name
    case_dir.mkdir()
    (case_dir / "input.json").write_bytes(source)
    (case_dir / "claimed.bin").write_bytes(claimed)
    artifacts = {
        "input": {"path": "input.json", "sha256": hashlib.sha256(source).hexdigest(), "length": len(source)},
        "claimed": {"path": "claimed.bin", "sha256": digest, "length": len(claimed)},
    }
    (case_dir / "case.json").write_text(json.dumps(
        {"schema_version": "probity-case/v1", "case_id": name, "artifacts": artifacts}), encoding="utf-8")
    (case_dir / "policy.json").write_text(json.dumps({
        "schema_version": "probity-policy/v1",
        "assessments": {name: {"claim_type": "jcs_canonical/v1", "target": "rfc8785", "input": "input",
                               "claimed": "claimed"}},
    }), encoding="utf-8")
    done = subprocess.run(
        [str(Path(sys.executable).parent / "agent-evidence-verify"), str(case_dir / "case.json"), "--policy",
         str(case_dir / "policy.json"), "--json"],
        capture_output=True, text=True, check=False, timeout=120)
    return done.returncode, json.loads(done.stdout) if done.stdout.strip() else {}


@pytest.mark.parametrize("which", ["execution", "results"])
def test_probity_verify_confirms_each_manifest_digest(tmp_path: Path, which: str) -> None:
    version = tuple(int(part) for part in metadata.version("agent-evidence-verify").split(".")[:2])
    assert version >= (0, 4), "jcs_canonical/v1 ships from agent-evidence-verify 0.5.0 (probity-verify 0.4.0)"
    location = _run(tmp_path)
    manifest = json.loads(binding.manifest_path(location).read_text(encoding="utf-8"))
    log = binding.decode_log(location)
    cover = binding.execution_cover(log) if which == "execution" else binding.results_cover(log)
    pretty = json.dumps(cover, indent=2).encode("utf-8")
    claimed = binding.canonical_bytes(cover)
    pinned = manifest[f"{which}_digest"].removeprefix("sha256:")

    code, decision = _verify(tmp_path, f"{which}-supported", claimed, pretty, pinned)

    assert code == 0, decision
    assert decision["decision"] == "supported"
    assert decision["reason"] == "canonical_bytes_match"
    assert decision["claim_type"] == "jcs_canonical/v1"


def test_probity_verify_refuses_a_cover_that_does_not_hash_to_the_manifest(tmp_path: Path) -> None:
    location = _run(tmp_path)
    manifest = json.loads(binding.manifest_path(location).read_text(encoding="utf-8"))
    cover = binding.results_cover(binding.decode_log(location))
    cover["samples"][0]["scores"]["match"]["value"] = "C"
    pretty = json.dumps(cover, indent=2).encode("utf-8")

    code, _ = _verify(tmp_path, "altered", binding.canonical_bytes(cover), pretty,
                      manifest["results_digest"].removeprefix("sha256:"))

    assert code == 2


def test_probity_verify_contradicts_bytes_that_are_not_the_canonical_form(tmp_path: Path) -> None:
    location = _run(tmp_path)
    cover = binding.execution_cover(binding.decode_log(location))
    spaced = json.dumps(cover, indent=2).encode("utf-8")

    code, decision = _verify(tmp_path, "spaced", spaced, spaced, hashlib.sha256(spaced).hexdigest())

    assert code == 0
    assert decision["decision"] == "contradicted"
    assert decision["reason"] == "canonical_bytes_differ"
