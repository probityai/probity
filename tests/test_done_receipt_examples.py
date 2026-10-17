"""The retained done-receipt runs reproduce byte for byte and decide as documented."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from probity_verify import adjudicate

ROOT = Path(__file__).resolve().parents[1] / "examples/done-receipt"
EXPECTED = {
    ("honest", "protected-paths"): ("supported", "protected_paths_untouched"),
    ("planted-adversary", "protected-paths"): ("contradicted", "protected_path_mutated"),
    ("lost-events", "protected-paths"): ("not_established",
                                         "observation_coverage_unestablished"),
}


@pytest.mark.parametrize("run,check", sorted(EXPECTED))
def test_example_decision(run, check):
    case = json.loads((ROOT / run / f"{check}.case.json").read_text())
    policy = json.loads((ROOT / run / f"{check}.policy.json").read_text())
    result = adjudicate(case, policy, ROOT / run)
    assert (result["decision"], result["reason"]) == EXPECTED[(run, check)]


def test_every_retained_case_has_an_expected_decision():
    cases = {(path.parent.name, path.name.removesuffix(".case.json"))
             for path in ROOT.glob("*/*.case.json")}
    assert cases == set(EXPECTED)


def test_generator_reproduces_the_committed_bytes():
    completed = subprocess.run([sys.executable, str(ROOT / "generate.py"), "--check"],
                               capture_output=True, text=True, check=False)
    assert completed.returncode == 0, completed.stdout + completed.stderr
