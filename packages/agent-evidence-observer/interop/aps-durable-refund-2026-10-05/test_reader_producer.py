"""Controls that run the capture producer, then re-sign hostile host faults for the public reader."""
from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import subprocess
import sys
from contextlib import closing
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from probity_aps_refund.native import run
from probity_aps_refund.reader import read
from probity_observer.crypto import (
    SigningKey,
    VerificationError,
    canonical,
    digest,
    strict_loads,
)
from probity_observer.ticket_state import DOMAIN

PROFILE = Path(__file__).resolve().parent

@pytest.fixture(scope="module")
def capture(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Generate new actual native effects once; never reuse historical artifacts."""
    root = tmp_path_factory.mktemp("public-native-refund")
    run(root / "capture", root / "private", PROFILE)
    return root / "capture"


def consume(case: Path) -> dict:
    """Select this test's own operator policy; this is not independent evidence."""
    pin = hashlib.sha256((case / "host-policy.json").read_bytes()).hexdigest()
    return read(case, pin, node=Path(shutil.which("node")).resolve(), verifier=PROFILE / "verify-aps.mjs")

def test_installed_native_cli_retains_actual_public_controls(tmp_path: Path) -> None:
    """The real capture CLI retains the shared-operation boundary and only public capture bytes."""
    output = tmp_path / "capture"
    command = [sys.executable, "-I", "-B", "-m", "probity_aps_refund.native", str(output),
               "--private-state", str(tmp_path / "private"), "--profile", str(PROFILE)]
    produced = subprocess.run(command, capture_output=True, timeout=120, check=False)
    assert produced.returncode == 0 and not produced.stderr, produced.stderr
    report = json.loads(produced.stdout)
    assert json.loads((output / "native-report.json").read_bytes()) == report
    assert len(report["records"]) == 8
    assert report["sharedOperationCaptures"] == ["different-action-first", "approval-reissue"]
    assert report["witnessScope"] == "PEER" and report["independentCustody"] is False
    assert "must not be pooled" in report["casePopulation"]
    for item in report["records"]:
        case = output / item["case"]
        assert set(path.name for path in case.iterdir()) == {
            "host-policy.json", "receipt.json", "readback.json", "attempts.json", "service.sqlite"}
        policy = json.loads((case / "host-policy.json").read_bytes())
        assert "servicePrivateKey" not in policy and "issuerPrivateKey" not in policy
        assert consume(case)["localEffects"] == item["localEffects"]


def signed_hostile_capture(capture: Path, target: Path, kind: str) -> Path:
    """Re-sign controlled host faults; the actual consumer still receives only public keys."""
    incomplete = kind in {"signed-state-revision", "signed-state-count", "integer-revocation",
        "incomplete-readback-revision", "unsigned-copy-revision", "signed-public-revision", "missing-initialize", "historical-native-intent"}
    name = "after-intent" if incomplete else "restart"
    shutil.copytree(capture / name, target)
    runtime = json.loads((capture.parent / "private" / name / "runtime.json").read_bytes())
    key = SigningKey(Ed25519PrivateKey.from_private_bytes(bytes.fromhex(runtime["servicePrivateKey"])))
    with closing(sqlite3.connect(target / "service.sqlite")) as db:
        state = strict_loads(db.execute("SELECT record FROM state WHERE singleton=1").fetchone()[0])["payload"]
        events = [strict_loads(raw)["payload"] for (_, raw) in db.execute("SELECT sequence,record FROM events ORDER BY sequence")]
        if kind == "signed-event-sequence":
            events[0]["sequence"] = True
        elif kind == "signed-intent-revision":
            events[1]["event"]["beforeRevision"] = False
        elif kind == "signed-effect-revision":
            events[2]["event"]["revision"] = True
        elif kind == "unsupported-effect":
            events[2]["event"]["kind"] = "claimed-provider-effect"
        elif kind == "missing-initialize":
            events = events[1:]
            for number, event in enumerate(events, 1):
                event["sequence"] = number
        elif kind == "historical-native-intent":
            state["intentTime"] = "2026-10-05T19:59:58.000Z"
            events[1]["event"]["intentTime"] = state["intentTime"]
        elif kind == "consistent-effect-identity":
            state["effectId"] = "f" * 64
            events[1]["event"]["effectId"] = events[2]["event"]["effectId"] = state["effectId"]
            db.execute("UPDATE tickets SET effect=?", (state["effectId"],))
        elif kind == "terminal-content-and-row":
            altered = b'{"amount_minor":101,"currency":"USD","payment_id":"changed"}'
            state["contentDigest"] = hashlib.sha256(altered).hexdigest()
            db.execute("UPDATE tickets SET content=?", (altered,))
        elif kind.startswith("signed-time-"):
            suffix = {"signed-time-seconds": "Z", "signed-time-short": ".0Z",
                "signed-time-long": ".0000Z", "signed-time-offset": ".000+00:00"}[kind]
            state["intentTime"] = "2026-10-05T20:00:00" + suffix
            events[1]["event"]["intentTime"] = state["intentTime"]
        elif kind == "signed-state-revision":
            state["revision"] = False
        elif kind == "signed-state-count":
            state["eventCount"] = True
        elif kind == "integer-revocation":
            state["revoked"] = 0
        elif kind in {"sql-row-real", "sql-sequence-real"}:
            if kind == "sql-row-real":
                db.execute("ALTER TABLE tickets RENAME TO old_tickets")
                db.execute("CREATE TABLE tickets(tenant TEXT, ticket TEXT, content BLOB NOT NULL, revision REAL NOT NULL, effect TEXT NOT NULL, PRIMARY KEY(tenant,ticket))")
                db.execute("INSERT INTO tickets SELECT * FROM old_tickets")
                db.execute("DROP TABLE old_tickets")
            else:
                db.execute("ALTER TABLE events RENAME TO old_events")
                db.execute("CREATE TABLE events(sequence REAL PRIMARY KEY, record BLOB NOT NULL)")
                db.execute("INSERT INTO events SELECT * FROM old_events")
                db.execute("DROP TABLE old_events")
        elif kind not in {"incomplete-readback-revision", "completed-readback-revision", "unsigned-copy-revision",
                           "signed-public-revision", "signed-witness-scope", "signed-retained-revocation", "signed-retained-phase", "signed-retained-digest", "signed-retained-time"}:
            raise AssertionError("unknown signed host control")
        db.execute("DELETE FROM events")
        previous = "0" * 64
        for number, event in enumerate(events, 1):
            body = {"sequence": event["sequence"], "previous": previous, "event": event["event"]}
            body["hash"] = digest(DOMAIN + "-event", body)
            signed = {"payload": body, "keyid": key.public_hex, "signature": key.sign(DOMAIN, body)}
            db.execute("INSERT INTO events VALUES(?,?)", (number, canonical(signed)))
            previous = body["hash"]
        state["eventHead"] = previous
        if kind != "signed-state-count":
            state["eventCount"] = len(events)
        signed_state = {"payload": state, "keyid": key.public_hex, "signature": key.sign(DOMAIN, state)}
        db.execute("UPDATE state SET record=? WHERE singleton=1", (canonical(signed_state),))
        db.commit()
    receipt = json.loads((target / "receipt.json").read_bytes())
    receipt["payload"].update(state)
    if kind == "signed-public-revision":
        receipt["payload"]["revision"] = False
    elif kind == "signed-witness-scope":
        receipt["payload"]["witnessScope"] = "INDEPENDENT"
    elif kind == "signed-retained-revocation":
        receipt["payload"]["revoked"] = True
    elif kind == "signed-retained-phase":
        receipt["payload"].update(phase="incomplete", revision=0, contentDigest=None, effectTime=None)
    elif kind == "signed-retained-digest":
        receipt["payload"]["contentDigest"] = "f" * 64
    elif kind == "signed-retained-time":
        receipt["payload"]["effectTime"] = "2026-10-05T20:00:01.000Z"
    receipt["signature"] = key.sign(DOMAIN, receipt["payload"])
    readback = json.loads((target / "readback.json").read_bytes())
    readback["receipt"] = json.loads(canonical(receipt))
    if kind == "consistent-effect-identity":
        readback["effectId"] = state["effectId"]
    elif kind == "terminal-content-and-row":
        readback["contentHex"] = altered.hex()
    if kind == "unsigned-copy-revision":
        readback["receipt"]["payload"]["revision"] = False
    elif kind == "incomplete-readback-revision":
        readback["revision"] = False
    elif kind == "completed-readback-revision":
        readback["revision"] = True
    (target / "receipt.json").write_bytes(canonical(receipt))
    (target / "readback.json").write_bytes(canonical(readback))
    policy = json.loads((target / "host-policy.json").read_bytes())
    for filename in policy["files"]:
        policy["files"][filename] = hashlib.sha256((target / filename).read_bytes()).hexdigest()
    (target / "host-policy.json").write_bytes(canonical(policy))
    return target


@pytest.mark.parametrize("kind,refusal", [
    ("signed-event-sequence", "event schema"), ("signed-intent-revision", "intent history"),
    ("signed-effect-revision", "effect history"), ("unsupported-effect", "unsupported event"),
    ("missing-initialize", "lacks initial configuration"), ("signed-state-revision", "counters or revocation"),
    ("signed-state-count", "counters or revocation"), ("integer-revocation", "counters or revocation"),
    ("sql-row-real", "row types"), ("sql-sequence-real", "event schema"),
    ("incomplete-readback-revision", "revision type"), ("completed-readback-revision", "revision type"),
    ("unsigned-copy-revision", "state differs from selected signed readback"),
    ("signed-public-revision", "counters or revocation"), ("signed-witness-scope", "retained ticket head profile"),
    ("historical-native-intent", "native APS approval verification refused"),
    ("signed-retained-revocation", "retained state differs from native history"),
    ("signed-retained-phase", "retained state differs from native history"),
    ("signed-retained-digest", "retained state differs from native history"),
    ("signed-retained-time", "retained state differs from native history"),
    ("consistent-effect-identity", "intent authority or effect identity differs"),
    ("terminal-content-and-row", "retained state differs from native history"),
    ("signed-time-seconds", "canonical UTC milliseconds"), ("signed-time-short", "canonical UTC milliseconds"),
    ("signed-time-long", "canonical UTC milliseconds"), ("signed-time-offset", "canonical UTC milliseconds"),
])
def test_authentic_host_signatures_do_not_override_native_capture_rules(capture: Path, tmp_path: Path, kind: str, refusal: str) -> None:
    """Genuine SDK approval, valid host signatures and reselected pins still require native types and phases."""
    case = signed_hostile_capture(capture, tmp_path / kind, kind)
    before = (case / "service.sqlite").read_bytes()
    with pytest.raises(VerificationError, match=refusal):
        consume(case)
    policy_pin = hashlib.sha256((case / "host-policy.json").read_bytes()).hexdigest()
    command = [sys.executable, "-I", "-B", "-m", "probity_aps_refund.reader", str(case),
        "--policy-sha256", policy_pin, "--node", str(Path(shutil.which("node")).resolve()),
        "--verifier", str(PROFILE / "verify-aps.mjs")]
    refused = subprocess.run(command, capture_output=True, timeout=20, check=False)
    (case / "consumer-stdout.bin").write_bytes(refused.stdout)
    (case / "consumer-stderr.txt").write_bytes(refused.stderr)
    (case / "consumer-check.json").write_bytes(canonical({"kind": kind, "exit": refused.returncode,
        "policySha256": policy_pin, "refusal": refusal, "SQLiteSha256": hashlib.sha256(before).hexdigest(),
        "independentCustody": False, "witnessScope": "PEER"}))
    assert refused.returncode == 2 and not refused.stdout and refusal.encode("ascii") in refused.stderr
    assert (case / "service.sqlite").read_bytes() == before

