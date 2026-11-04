"""Fresh public-key-only consumers must replay actual selected public bytes."""
from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import subprocess
import sys
from contextlib import closing
from pathlib import Path
from typing import Any

import pytest
from probity_aps_refund.reader import read
from probity_observer.crypto import (
    VerificationError,
    canonical,
)

PROFILE = Path(__file__).resolve().parent


def consume(case: Path) -> dict:
    """Select this test's own operator policy; this is not independent evidence."""
    pin = hashlib.sha256((case / "host-policy.json").read_bytes()).hexdigest()
    return read(case, pin, node=Path(shutil.which("node")).resolve(), verifier=PROFILE / "verify-aps.mjs")



@pytest.mark.parametrize("name,effects", [("restart", 1), ("cross-instance", 1), ("after-intent", 0), ("inside-effect-transaction", 0), ("lost-ack", 1), ("approval-reissue", 1), ("different-action-first", 1), ("different-action", 1)])
def test_public_selected_native_capture(capture: Path, name: str, effects: int) -> None:
    """Installed readers need no producer private keys to verify selected local outcomes."""
    result = consume(capture / name)
    assert result["logicalAdmissions"] == 1 and result["localEffects"] == effects
    assert result["independentCustody"] is False and result["witnessScope"] == "PEER"


def test_public_policy_requires_external_pin(capture: Path) -> None:
    """A capture cannot nominate its own host trust policy."""
    with pytest.raises(VerificationError, match="consumer selection"):
        read(capture / "restart", "00" * 32, node=Path(shutil.which("node")).resolve(), verifier=PROFILE / "verify-aps.mjs")


def test_public_reissue_replay_refuses_changed_authorization(capture: Path) -> None:
    """A fresh public-key-only reader replays actual native and installed completion verification."""
    case = capture / "approval-reissue"
    before = (case / "service.sqlite").read_bytes()
    result = consume(case)
    assert result["approvalReissue"] == "same-operation-changed-authorization-refused"
    assert (case / "service.sqlite").read_bytes() == before
    assert result["logicalAdmissions"] == result["localEffects"] == 1


def test_installed_public_cli_repeats_and_refuses_wrong_selection(capture: Path) -> None:
    """A real public CLI needs no producer secrets and emits no result on a wrong policy pin."""
    case = capture / "restart"
    before = (case / "service.sqlite").read_bytes()
    pin = hashlib.sha256((case / "host-policy.json").read_bytes()).hexdigest()
    command = [sys.executable, "-I", "-B", "-m", "probity_aps_refund.reader", str(case),
               "--node", str(Path(shutil.which("node")).resolve()),
               "--verifier", str(PROFILE / "verify-aps.mjs"), "--policy-sha256", pin]
    first = subprocess.run(command, capture_output=True, timeout=20, check=False)
    repeated = subprocess.run(command, capture_output=True, timeout=20, check=False)
    assert first.returncode == repeated.returncode == 0, (first.stderr, repeated.stderr)
    assert not first.stderr and not repeated.stderr and first.stdout == repeated.stdout
    assert json.loads(first.stdout)["localEffects"] == 1
    command[-1] = "00" * 32
    refused = subprocess.run(command, capture_output=True, timeout=20, check=False)
    assert refused.returncode == 2 and not refused.stdout
    assert b"consumer selection" in refused.stderr
    assert (case / "service.sqlite").read_bytes() == before



@pytest.mark.parametrize("kind", ["tenant", "ticket", "receipt-copy", "admission-count", "member-population"])
def test_selected_wrapper_cannot_override_native_capture(capture: Path, tmp_path: Path, kind: str) -> None:
    """Selecting changed wrapper bytes cannot change authentic native identity, state or counts."""
    case = tmp_path / "capture"
    shutil.copytree(capture / "restart", case)
    policy = json.loads((case / "host-policy.json").read_bytes())
    readback = json.loads((case / "readback.json").read_bytes())
    if kind in {"tenant", "ticket"}:
        readback[{"tenant": "tenantId", "ticket": "ticketId"}[kind]] = "wrong"
    elif kind == "receipt-copy":
        readback["receipt"]["payload"]["witnessScope"] = "INDEPENDENT"
    elif kind == "admission-count":
        policy["expected"]["logicalAdmissions"] = 2
    else:
        del policy["files"]["attempts.json"]
    (case / "readback.json").write_bytes(canonical(readback))
    policy["files"]["readback.json"] = hashlib.sha256((case / "readback.json").read_bytes()).hexdigest()
    (case / "host-policy.json").write_bytes(canonical(policy))
    before = (case / "service.sqlite").read_bytes()
    with pytest.raises(VerificationError):
        consume(case)
    assert (case / "service.sqlite").read_bytes() == before


def test_public_different_action_pair_keeps_distinct_operation(capture: Path) -> None:
    """Two valid same-key approvals with different action nonces remain distinct local operations."""
    first, second = consume(capture / "different-action-first"), consume(capture / "different-action")
    assert first["logicalOperationId"] != second["logicalOperationId"]
    a = json.loads((capture / "different-action-first/host-policy.json").read_bytes())
    b = json.loads((capture / "different-action/host-policy.json").read_bytes())
    assert a["evidence"]["policy"]["publicKey"] == b["evidence"]["policy"]["publicKey"]
    assert first["localEffects"] == second["localEffects"] == 1


@pytest.mark.parametrize("filename", ["receipt.json", "readback.json", "attempts.json", "service.sqlite"])
def test_public_members_are_selected(capture: Path, tmp_path: Path, filename: str) -> None:
    """Tampering with any retained public member refuses without private-key access."""
    case = tmp_path / "capture"
    shutil.copytree(capture / "restart", case)
    with (case / filename).open("ab") as stream:
        stream.write(b"hostile mutation")
    with pytest.raises(VerificationError, match="capture bytes differ"):
        consume(case)


@pytest.mark.parametrize("kind", ["sdk-key", "sdk-pin", "native-count", "logical-operation", "grant"])
def test_reselected_wrong_policy_is_still_not_valid(capture: Path, tmp_path: Path, kind: str) -> None:
    """A selected but incorrect expectation cannot override actual cryptographic or native bytes."""
    case = tmp_path / "capture"
    shutil.copytree(capture / "after-intent", case)
    policy = json.loads((case / "host-policy.json").read_bytes())
    if kind == "sdk-key":
        policy["evidence"]["policy"]["publicKey"] = "00" * 32
    elif kind == "sdk-pin":
        policy["sdkSha256"] = "00" * 32
    elif kind == "native-count":
        policy["expected"]["localEffects"] = 1
    elif kind == "logical-operation":
        policy["request"]["request_id"] = "00" * 32
    else:
        policy["grant"]["signature"] = "AAAA"
    (case / "host-policy.json").write_bytes(canonical(policy))
    with pytest.raises(VerificationError):
        consume(case)


@pytest.mark.parametrize("kind", ["boolean-admissions", "boolean-effects", "float-count", "expected-array", "expected-extra", "files-array", "policy-array", "clock-boolean", "clock-invalid"])
def test_selected_policy_requires_typed_count_population(capture: Path, tmp_path: Path, kind: str) -> None:
    """JSON booleans and floating values cannot masquerade as measured integer populations."""
    case = tmp_path / "capture"
    shutil.copytree(capture / "restart", case)
    policy = json.loads((case / "host-policy.json").read_bytes())
    if kind == "boolean-admissions":
        policy["expected"]["logicalAdmissions"] = True
    elif kind == "boolean-effects":
        policy["expected"]["localEffects"] = True
    elif kind == "float-count":
        policy["expected"]["localEffects"] = 0.5
    elif kind == "expected-array":
        policy["expected"] = []
    elif kind == "expected-extra":
        policy["expected"]["providerEffects"] = 1
    elif kind == "files-array":
        policy["files"] = []
    elif kind == "clock-boolean":
        policy["now"] = True
    elif kind == "clock-invalid":
        policy["now"] = "invalid"
    else:
        policy = []
    # The outer Observer profile forbids every float before canonicalization;
    # retain a real float token to exercise that existing reader boundary.
    encoded = json.dumps(policy, sort_keys=True, separators=(",", ":")).encode("ascii") if kind == "float-count" else canonical(policy)
    (case / "host-policy.json").write_bytes(encoded)
    before = (case / "service.sqlite").read_bytes()
    refusal = {
        "boolean-admissions": "counts must be JSON integers", "boolean-effects": "counts must be JSON integers",
        "float-count": "outside the prototype JSON profile", "expected-array": "expected count fields differ",
        "expected-extra": "expected count fields differ", "files-array": "policy member population differs",
        "policy-array": "policy member population differs", "clock-boolean": "clock is malformed",
        "clock-invalid": "clock is malformed",
    }
    with pytest.raises(VerificationError, match=refusal[kind]):
        consume(case)
    assert (case / "service.sqlite").read_bytes() == before


@pytest.mark.parametrize("kind", ["event-sequence", "effect-row", "signed-state"])
def test_selected_sqlite_changes_require_signed_history_and_effect_join(capture: Path, tmp_path: Path, kind: str) -> None:
    """Reselecting altered SQLite bytes cannot override authentic event and completion joins."""
    case = tmp_path / "capture"
    shutil.copytree(capture / "restart", case)
    with closing(sqlite3.connect(case / "service.sqlite")) as db:
        if kind == "event-sequence":
            db.execute("UPDATE events SET sequence=sequence+100")
        elif kind == "effect-row":
            db.execute("UPDATE tickets SET effect='changed'")
        else:
            record = json.loads(db.execute("SELECT record FROM state WHERE singleton=1").fetchone()[0])
            record["payload"]["eventHead"] = "00" * 32
            db.execute("UPDATE state SET record=?", (canonical(record),))
        db.commit()
    policy = json.loads((case / "host-policy.json").read_bytes())
    policy["files"]["service.sqlite"] = hashlib.sha256((case / "service.sqlite").read_bytes()).hexdigest()
    (case / "host-policy.json").write_bytes(canonical(policy))
    before = (case / "service.sqlite").read_bytes()
    with pytest.raises(VerificationError):
        consume(case)
    assert (case / "service.sqlite").read_bytes() == before


@pytest.mark.parametrize("kind", ["changed-authority", "same-approval", "different-action"])
def test_selected_alternate_requires_same_action_and_changed_approval(capture: Path, tmp_path: Path, kind: str) -> None:
    """The genuine SDK must verify a distinct same-action approval before refusal replay."""
    case = tmp_path / "capture"
    shutil.copytree(capture / "approval-reissue", case)
    policy = json.loads((case / "host-policy.json").read_bytes())
    if kind == "changed-authority":
        policy["alternateApproval"]["policy"]["publicKey"] = "00" * 32
    elif kind == "same-approval":
        policy["alternateApproval"] = policy["evidence"]
    else:
        policy["alternateApproval"] = json.loads((capture / "different-action/host-policy.json").read_bytes())["evidence"]
    (case / "host-policy.json").write_bytes(canonical(policy))
    before = (case / "service.sqlite").read_bytes()
    with pytest.raises(VerificationError):
        consume(case)
    assert (case / "service.sqlite").read_bytes() == before




@pytest.mark.parametrize("kind,value", [("policy-precision-missing", None), ("policy-precision-seconds", "seconds"),
    ("policy-precision-case", "Milliseconds"), ("policy-clock-seconds", "2026-10-05T20:00:00Z"),
    ("policy-clock-fine", "2026-10-05T20:00:00.000001Z"), ("policy-clock-offset", "2026-10-05T20:00:00.000+00:00")])
def test_public_native_precision_has_one_selected_contract(capture: Path, tmp_path: Path, kind: str, value: Any) -> None:
    """Reselected host pins cannot make a different precision or timestamp alias valid."""
    case = tmp_path / kind
    shutil.copytree(capture / "restart", case)
    policy = json.loads((case / "host-policy.json").read_bytes())
    if kind == "policy-precision-missing":
        del policy["timePrecision"]
        refusal = "policy member population differs"
    elif kind.startswith("policy-precision"):
        policy["timePrecision"] = value
        refusal = "native time precision must be milliseconds"
    else:
        policy["now"] = value
        refusal = "clock is malformed"
    (case / "host-policy.json").write_bytes(canonical(policy))
    before = (case / "service.sqlite").read_bytes()
    with pytest.raises(VerificationError, match=refusal):
        consume(case)
    pin = hashlib.sha256((case / "host-policy.json").read_bytes()).hexdigest()
    result = subprocess.run([sys.executable, "-I", "-B", "-m", "probity_aps_refund.reader", str(case),
        "--policy-sha256", pin, "--node", str(Path(shutil.which("node")).resolve()),
        "--verifier", str(PROFILE / "verify-aps.mjs")], capture_output=True, timeout=20, check=False)
    (case / "consumer-stdout.bin").write_bytes(result.stdout)
    (case / "consumer-stderr.txt").write_bytes(result.stderr)
    (case / "consumer-check.json").write_bytes(canonical({"kind": kind, "exit": result.returncode,
        "policySha256": pin, "refusal": refusal, "SQLiteSha256": hashlib.sha256(before).hexdigest(),
        "independentCustody": False, "witnessScope": "PEER"}))
    assert result.returncode == 2 and not result.stdout and refusal.encode("ascii") in result.stderr
    assert (case / "service.sqlite").read_bytes() == before
