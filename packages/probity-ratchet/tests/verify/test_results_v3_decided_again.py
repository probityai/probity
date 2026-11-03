"""The published v3 decision is decided again from its execution records with the public policy rule, and a
re-signed record whose verdict, gate checks or tables differ from what the records yield is refused."""

from __future__ import annotations

import json
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from ratchet_cases.types import sha256_hex

from ratchet.canonical import canonical_json
from ratchet.improve.receipt import Signer
from ratchet.verify import dsse
from ratchet.verify.adapter import DECISION_PAYLOAD_TYPE
from ratchet.verify.keys import DEFAULT_KEY_PATH, load_trusted_key
from ratchet.verify.results import RESULTS_TYPE, verify_results

PINNED = Path(__file__).resolve().parents[2] / "docs" / "results" / "v3-cell" / "v3-cell-results"
RESULTS = "v3-cell.dsse"
BUNDLE = "bundles/bdb5bd9b003912c4"

Edit = Callable[[dict[str, Any], dict[str, Any]], None]


def _check(payload: dict[str, Any], name: str) -> dict[str, Any]:
    return next(c for c in payload["checks"] if c["name"] == name)


def _forge(
    tmp_path: Path, edit: Edit, runs: Callable[[dict[str, Any]], None] | None = None
) -> tuple[Path, Signer]:
    """The pinned record copied, its receipt and results file edited and both signed again by a test key."""
    root = tmp_path / "results"
    shutil.copytree(PINNED, root)
    signer = Signer.generate()
    receipt_path = root / BUNDLE / "receipt.dsse"
    receipt = json.loads(dsse.parse(receipt_path.read_bytes()).payload)
    results = json.loads(dsse.parse((root / RESULTS).read_bytes()).payload)
    edit(receipt, results["decisions"][0])
    if runs is not None:
        runs(results["runs"])
    envelope = signer.sign(DECISION_PAYLOAD_TYPE, canonical_json(receipt))
    receipt_path.write_bytes(envelope)
    results["decisions"][0]["receipt_sha256"] = sha256_hex(envelope)
    (root / RESULTS).write_bytes(signer.sign(RESULTS_TYPE, canonical_json(results)))
    return root / RESULTS, signer


def _verify(path: Path, signer: Signer) -> Any:
    return verify_results(path.read_bytes(), signer.public_key, path.parent)


def test_the_published_decision_is_decided_again_under_the_pinned_key() -> None:
    path = PINNED / RESULTS
    report = verify_results(path.read_bytes(), load_trusted_key(DEFAULT_KEY_PATH), PINNED)
    assert report.ok, report.reason
    detail = report.recomputed[0]
    assert detail["decided_again"] == {"admitted": False, "cohort": "UNQUALIFIED", "gates": 7}
    assert detail["executions"] == 160 and {"id": "v3_identity_controls", "arms": 2} in report.recomputed
    assert report.authenticated_only == []


def test_an_unchanged_record_signed_again_still_verifies(tmp_path: Path) -> None:
    report = _verify(*_forge(tmp_path, lambda receipt, entry: None))
    assert report.ok, report.reason


def _qualify(receipt: dict[str, Any], entry: dict[str, Any]) -> None:
    cohort = _check(receipt, "cohort_qualified")
    cohort["passed"] = True
    cohort["evidence"]["cohort"]["status"] = "QUALIFIED"
    _check(receipt, "stochastic_v3")["evidence"]["gate"]["checks"]["cohort_qualified"] = True


def _admit(receipt: dict[str, Any], entry: dict[str, Any]) -> None:
    """A consistent forgery: every check passed and the candidate admitted, so the gate record agrees with
    the admitted flag and only the recomputation can refuse it."""
    for c in receipt["checks"]:
        c["passed"] = True
    _check(receipt, "cohort_qualified")["evidence"]["cohort"]["status"] = "QUALIFIED"
    gate = _check(receipt, "stochastic_v3")["evidence"]["gate"]
    gate["checks"] = dict.fromkeys(gate["checks"], True)
    gate["passed"] = True
    receipt["admitted"] = entry["admitted"] = True
    entry["failed"] = []


def _recoveries(receipt: dict[str, Any], entry: dict[str, Any]) -> None:
    _check(receipt, "stochastic_v3")["evidence"]["gate"]["checks"]["min_stable_recoveries"] = True


def _aggregate(receipt: dict[str, Any], entry: dict[str, Any]) -> None:
    _check(receipt, "stochastic_v3")["evidence"]["comparison"]["aggregate"]["pooled"]["arm"] = 90


def _control(receipt: dict[str, Any], entry: dict[str, Any]) -> None:
    control = _check(receipt, "cohort_qualified")["evidence"]["cohort"]["controls"][0]
    control["aggregate"]["panel_0"]["ok"] = True


def _benign(receipt: dict[str, Any], entry: dict[str, Any]) -> None:
    benign = _check(receipt, "benign_twins")
    benign["passed"], benign["evidence"]["interventions"] = False, 1


def _change(receipt: dict[str, Any], entry: dict[str, Any]) -> None:
    _check(receipt, "effective_change")["evidence"]["changed"]["system_prompt"] = True


def _listed(receipt: dict[str, Any], entry: dict[str, Any]) -> None:
    entry["failed"] = ["cohort_qualified"]


def _class(receipt: dict[str, Any], entry: dict[str, Any]) -> None:
    for row in (_check(receipt, "stochastic_v3")["evidence"]["comparison"]["cases"][0], entry["per_case"][0]):
        row["parent_class"] = "low"


@pytest.mark.parametrize(
    ("edit", "reason"),
    [
        (_qualify, "v3_evidence_not_recomputed:stochastic_v3:gate"),
        (_admit, "v3_gate_misstated:"),
        (_recoveries, "v3_evidence_not_recomputed:stochastic_v3:gate"),
        (_aggregate, "v3_evidence_not_recomputed:stochastic_v3:comparison"),
        (_control, "v3_evidence_not_recomputed:cohort_qualified:cohort"),
        (_benign, "v3_gate_misstated:benign_twins"),
        (_change, "v3_evidence_not_recomputed:effective_change:changed"),
        (_listed, "v3_listed_failed_not_recomputed"),
        (_class, "v3_evidence_not_recomputed:stochastic_v3:comparison"),
    ],
)
def test_a_resigned_record_that_the_executions_do_not_yield_is_contradicted(
    tmp_path: Path, edit: Edit, reason: str
) -> None:
    report = _verify(*_forge(tmp_path, edit))
    assert report.decision == "contradicted", report.reason
    assert report.reason.startswith(reason), report.reason


def test_an_identity_control_arm_must_be_the_signed_one(tmp_path: Path) -> None:
    path, signer = _forge(tmp_path, lambda receipt, entry: None)
    arm = next((path.parent / "cohorts").iterdir()) / "arms" / "identity_2.json"
    records = json.loads(arm.read_text())
    records[0]["passed"] = not records[0]["passed"]
    arm.write_text(json.dumps(records))
    report = _verify(path, signer)
    assert report.reason.startswith("arm_records_not_signed") and report.reason.endswith("identity_2")


def test_the_identity_control_table_is_recomputed(tmp_path: Path) -> None:
    def edit(runs: dict[str, Any]) -> None:
        runs["v3_identity_controls"]["identity_1"][0]["arm"] = 11

    report = _verify(*_forge(tmp_path, lambda receipt, entry: None, edit))
    assert report.reason == "v3_identity_controls_not_recomputed"
