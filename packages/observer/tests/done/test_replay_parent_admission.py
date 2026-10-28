"""The admission rule set reads the record this verifier writes for where the replay parent ran.

The rule module and its vectors are those of probityai/agent-evidence at the commit that merged
the rule (pinned below by commit and SHA-256); OPA is the version that repository's CI pins,
by the SHA-256 of its release asset. The baseline statement is the rule set's own admitted
case, and the only thing replaced is ``verifier.replay_parent`` with what this verifier
writes after a real replay: from a parent on this host, and from a parent in its own container.
"""

import hashlib
import json
import os
import platform
import shutil
import subprocess
import urllib.request
from pathlib import Path

import pytest
from probity_observer.done import parent_image, runner, verify_run
from probity_observer.done.runner import SubprocessRunner

from .test_pytest_replay import HONEST
from .test_replay_parent_container import TEST, replay

RULES_COMMIT = "ae518073f7623acdbf5ac2774c90f1595b0543ef"
RULES = {"verifier_isolation.rego": "a2b7af9e8ef0e49841f44e1216aa00dfdd20e344e6591d0ed3d42ec5b639c3a8",
         "verifier_isolation_vectors.json": "560a8f9c7bd6e21a605e4421ec62819d07e614507d230daeffb8eb5e09a10630"}
RULES_URL = ("https://raw.githubusercontent.com/probityai/agent-evidence/" + RULES_COMMIT
             + "/packages/admission/rego/")
OPA_VERSION = "v1.18.0"
OPA_SHA256 = "65d700b14b99b354982b61031b40bdc8e316ea93dadd61818f066d1d9a69dcce"
OPA_URL = ("https://github.com/open-policy-agent/opa/releases/download/" + OPA_VERSION
           + "/opa_linux_amd64_static")


def fetch(url: str, digest: str, target: Path) -> Path:
    with urllib.request.urlopen(url, timeout=120) as response:
        data = response.read()
    assert hashlib.sha256(data).hexdigest() == digest, f"{url} is not the pinned file"
    target.write_bytes(data)
    return target


@pytest.fixture(scope="module")
def opa(tmp_path_factory) -> str:
    found = shutil.which("opa")
    if found:
        shown = subprocess.run([found, "version"], capture_output=True, text=True, check=False)
        if f"Version: {OPA_VERSION[1:]}" in shown.stdout:
            return found
    assert platform.system() == "Linux" and platform.machine() in ("x86_64", "AMD64")
    binary = fetch(OPA_URL, OPA_SHA256, tmp_path_factory.mktemp("opa") / "opa")
    binary.chmod(0o755)
    return str(binary)


@pytest.fixture(scope="module")
def rules(tmp_path_factory) -> Path:
    directory = tmp_path_factory.mktemp("rules")
    for name, digest in RULES.items():
        fetch(RULES_URL + name, digest, directory / name)
    return directory


def reasons(opa: str, rules: Path, tmp_path: Path, record: dict) -> list[str]:
    """What the pinned rule set says about the baseline statement with this parent record."""
    case = json.loads((rules / "verifier_isolation_vectors.json").read_text())[
        "verifier_isolation_vectors"]["cases"]["baseline-admitted"]
    report = case["input"]["predicate"]["verifier_isolation"]
    report["verifier"]["uid"] = record["verifier_uid"]
    report["verifier"]["replay_parent"] = record["replay_parent"]
    (tmp_path / "in.json").write_text(json.dumps(case["input"]))
    (tmp_path / "data.json").write_text(json.dumps({"verifier_isolation_consumer": case["consumer"]}))
    done = subprocess.run(
        [opa, "eval", "-f", "json", "-d", str(rules / "verifier_isolation.rego"),
         "-d", str(tmp_path / "data.json"), "-i", str(tmp_path / "in.json"),
         "data.verifier_isolation.reasons"], capture_output=True, text=True, check=False)
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)["result"][0]["expressions"][0]["value"]


def test_the_baseline_is_admitted_with_a_container_parent_record(opa, rules, tmp_path):
    # The control: the rule set's own record of a contained parent admits the statement, so
    # the refusals below are the parent's and nothing else.
    case = json.loads((rules / "verifier_isolation_vectors.json").read_text())[
        "verifier_isolation_vectors"]["cases"]["baseline-admitted"]
    parent = case["input"]["predicate"]["verifier_isolation"]["verifier"]["replay_parent"]
    assert reasons(opa, rules, tmp_path, {"verifier_uid": 0, "replay_parent": parent}) == []


def test_a_parent_run_on_this_host_is_refused(opa, rules, tmp_path):
    local = SubprocessRunner()
    code, _ = replay(tmp_path / "run", local, HONEST, TEST)
    assert code == 0
    record = {"verifier_uid": os.getuid(),
              "replay_parent": runner.replay_parent(local.replays)}
    assert record["replay_parent"]["runtime"] == "host"
    refused = reasons(opa, rules, tmp_path, record)
    assert "vi-2:replay_parent_not_contained" in refused
    assert "vi-2:replay_parent_shares_verifier_uid" in refused


@pytest.mark.skipif(shutil.which("docker") is None, reason="needs docker")
def test_a_parent_run_in_its_own_container_is_admitted(opa, rules, tmp_path):
    image = parent_image.ensure()
    graded = verify_run.DockerRunner(image, parent_image=image)
    code, _ = replay(tmp_path / "run", graded, HONEST, TEST)
    assert code == 0
    record = {"verifier_uid": os.getuid(),
              "replay_parent": runner.replay_parent(graded.replays)}
    assert record["replay_parent"]["runtime"] == "docker"
    assert reasons(opa, rules, tmp_path, record) == []
