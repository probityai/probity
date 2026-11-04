"""Controls that produce live signed cases with the producer, then contradict them."""

from __future__ import annotations

import json
import logging
import sqlite3

import pytest
from probity_observer.crypto import (
    SigningKey,
    VerificationError,
    canonical,
    digest,
    strict_loads,
)
from probity_observer.ticket_state import DOMAIN

from authority_checks import (
    CONTRACT_ID,
    MAX_AGE_SECONDS,
    PROFILE,
    RECORD_DOMAIN,
    sign_record,
)
from producer import _case
from reader import read_case


@pytest.fixture
def signable_case(tmp_path):
    """Retain author keys only inside a test that constructs signed contradictions."""
    keys = {name: SigningKey.generate() for name in ("issuer", "authority", "service", "record")}
    pins = {"profile": PROFILE, "maxValiditySeconds": 300,
            **{name + "Key": key.public_hex for name, key in keys.items()}}
    return tmp_path, keys, pins


def rewrite_native(path, key, mutation):
    """Re-sign an internally contradictory native record, preserving its chain."""
    with sqlite3.connect(path / "native.sqlite") as db:
        state = strict_loads(db.execute("SELECT record FROM state WHERE singleton=1").fetchone()[0])["payload"]
        if mutation == "effect-identity":
            state["effectId"] = "1" * 64
            db.execute("UPDATE tickets SET effect=?", (state["effectId"],))
        if mutation == "effect-time":
            state["effectTime"] = "2026-10-03T12:00:11Z"
        head = "0" * 64
        for sequence, raw in db.execute("SELECT sequence,record FROM events ORDER BY sequence").fetchall():
            event = strict_loads(raw)["payload"]
            carried = event["event"]
            if mutation == "effect-identity" and "effectId" in carried:
                carried["effectId"] = state["effectId"]
            if mutation == "effect-time" and carried["kind"] == "effect":
                carried["effectTime"] = state["effectTime"]
            if mutation == "wrong-initial-configuration" and sequence == 1:
                carried["configuration"] = "0" * 64
            if mutation == "repeated-initialize" and sequence == 2:
                event["event"] = {"kind": "initialize", "configuration": state["configuration"]}
            if mutation == "boolean-effect-revision" and carried["kind"] == "effect":
                carried["revision"] = True
            if mutation == "wrong-intent-principal" and carried["kind"] == "intent":
                carried["request"]["principal_id"] = "other-principal"
            event["previous"] = head
            event["hash"] = digest(DOMAIN + "-event", {field: event[field] for field in ("sequence", "previous", "event")})
            head = event["hash"]
            db.execute("UPDATE events SET record=? WHERE sequence=?", (canonical(sign_record(event, key, DOMAIN)), sequence))
        state["eventHead"] = head
        db.execute("UPDATE state SET record=? WHERE singleton=1", (canonical(sign_record(state, key, DOMAIN)),))


class TestProducerControls:
    class TestFailingCases:
        @pytest.mark.parametrize("mutation,reason", [
            ("missing", "trace contract id is missing"),
            ("other-version", "trace contract id differs"),
            ("age", "evidence age differs from decision time"),
            ("age-bool", "evidence age differs from decision time"),
            ("limit", "freshness limit differs from consumer selection"),
        ])
        def test_trace_without_contract_or_with_wrong_age_is_rejected(self, signable_case, mutation, reason, caplog):
            root, keys, pins = signable_case
            _case(root, "approved-human-reachable", keys)
            case = root / "approved-human-reachable"
            assert read_case(case, pins)["publicationReady"] is True
            payload = json.loads((case / "record.json").read_text())["payload"]
            if mutation == "missing":
                payload.pop("contractId")
            if mutation == "other-version":
                payload["contractId"] = CONTRACT_ID.replace("/v1", "/v0")
            if mutation == "age":
                payload["evidenceAgeSeconds"] += 1
            if mutation == "age-bool":
                payload["evidenceAgeSeconds"] = False
            if mutation == "limit":
                payload["freshnessLimitSeconds"] = MAX_AGE_SECONDS + 1
            (case / "record.json").write_bytes(canonical(sign_record(payload, keys["record"], RECORD_DOMAIN)))
            with caplog.at_level(logging.WARNING), pytest.raises(VerificationError) as error:
                read_case(case, pins)
            assert str(error.value) == reason
            assert "authority profile refused: " + reason in caplog.messages

        def test_unreachable_trace_that_claims_an_evidence_age_is_rejected(self, signable_case, caplog):
            root, keys, pins = signable_case
            _case(root, "authority-source-unreachable", keys)
            case = root / "authority-source-unreachable"
            assert read_case(case, pins)["authorityReason"] == "authority source unreachable"
            payload = json.loads((case / "record.json").read_text())["payload"]
            payload["evidenceAgeSeconds"] = 0
            (case / "record.json").write_bytes(canonical(sign_record(payload, keys["record"], RECORD_DOMAIN)))
            with caplog.at_level(logging.WARNING), pytest.raises(VerificationError) as error:
                read_case(case, pins)
            assert str(error.value) == "evidence age differs from decision time"
            assert "authority profile refused: evidence age differs from decision time" in caplog.messages

        @pytest.mark.parametrize("mutation,reason", [
            ("dropped", "record closes a residual risk this profile leaves open"),
            ("added", "residual risks differ from selected profile"),
            ("not-a-list", "residual risks differ from selected profile"),
        ])
        def test_record_that_closes_a_residual_risk_is_rejected(self, signable_case, mutation, reason, caplog):
            root, keys, pins = signable_case
            _case(root, "authority-evidence-stale", keys)
            case = root / "authority-evidence-stale"
            assert read_case(case, pins)["residualRisks"] == ["status-source-trusted-within-freshness-limit"]
            payload = json.loads((case / "record.json").read_text())["payload"]
            if mutation == "dropped":
                payload["residualRisks"] = []
            if mutation == "added":
                payload["residualRisks"].append("revocation-propagation-unmeasured")
            if mutation == "not-a-list":
                payload["residualRisks"] = "status-source-trusted-within-freshness-limit"
            (case / "record.json").write_bytes(canonical(sign_record(payload, keys["record"], RECORD_DOMAIN)))
            with caplog.at_level(logging.WARNING), pytest.raises(VerificationError) as error:
                read_case(case, pins)
            assert str(error.value) == reason
            assert "authority profile refused: " + reason in caplog.messages

        @pytest.mark.parametrize("mutation", ["content", "head", "time", "revoked-prefix"])
        def test_signed_completed_return_must_match_native_prefix(self, signable_case, mutation, caplog):
            root, keys, pins = signable_case
            case_id = "effect-then-authority-revoked" if mutation == "revoked-prefix" else "approved-human-reachable"
            _case(root, case_id, keys)
            case = root / case_id
            original = read_case(case, pins)
            assert original["effectObserved"] is True
            assert original["publicationReady"] is (mutation != "revoked-prefix")
            payload = json.loads((case / "record.json").read_text())["payload"]
            receipt = payload["attempts"][0]["receipt"]["payload"]
            if mutation == "content":
                receipt["contentDigest"] = "0" * 64
            if mutation == "head":
                receipt["eventHead"] = "0" * 64
            if mutation == "time":
                receipt["effectTime"] = "2026-10-03T12:01:00Z"
            if mutation == "revoked-prefix":
                current = payload["readback"]["receipt"]["payload"]
                receipt.update(eventCount=current["eventCount"], eventHead=current["eventHead"])
            payload["attempts"][0]["receipt"] = sign_record(receipt, keys["service"], DOMAIN)
            (case / "record.json").write_bytes(canonical(sign_record(payload, keys["record"], RECORD_DOMAIN)))
            reason = "retained completed dispatch differs from observed native history"
            with caplog.at_level(logging.WARNING), pytest.raises(VerificationError) as error:
                read_case(case, pins)
            assert str(error.value) == reason
            assert "authority profile refused: " + reason in caplog.messages

        @pytest.mark.parametrize("mutation,reason", [
            ("effect-identity", "retained completion differs from observed native state"),
            ("effect-time", "retained completion differs from observed native state"),
            ("wrong-initial-configuration", "native event body differs"),
            ("repeated-initialize", "native initialization history differs"),
            ("boolean-effect-revision", "native event body differs"),
            ("wrong-intent-principal", "native event body differs"),
        ])
        def test_signed_native_contradictions_are_refused(self, signable_case, mutation, reason, caplog):
            root, keys, pins = signable_case
            _case(root, "approved-human-reachable", keys)
            case = root / "approved-human-reachable"
            assert read_case(case, pins)["publicationReady"] is True
            rewrite_native(case, keys["service"], mutation)
            with caplog.at_level(logging.WARNING), pytest.raises(VerificationError) as error:
                read_case(case, pins)
            assert str(error.value) == reason
            assert "authority profile refused: " + reason in caplog.messages

        @pytest.mark.parametrize("mutation,reason", [
            ("terminal", "task terminal contradicts retained dispatch return"),
            ("deny-completed", "retained dispatch outcome differs"),
            ("empty-completion", "retained completed dispatch proof differs"),
            ("wrong-completion-binding", "retained completed dispatch proof differs"),
            ("coverage", "profile coverage exceeds selected boundary"),
            ("missing-field", "profile record fields differ"),
        ])
        def test_signed_profile_contradictions_are_refused(self, signable_case, mutation, reason, caplog):
            root, keys, pins = signable_case
            case_id = "approved-human-reachable" if mutation == "wrong-completion-binding" else "effect-committed-response-lost"
            _case(root, case_id, keys)
            case = root / case_id
            original = read_case(case, pins)
            assert original["effectObserved"] is True
            assert original["taskTerminal"] == ("completed" if mutation == "wrong-completion-binding" else "failed")
            record = json.loads((case / "record.json").read_text())
            payload = record["payload"]
            if mutation == "terminal":
                payload["taskTerminal"] = "completed"
            if mutation in {"deny-completed", "empty-completion"}:
                payload["taskTerminal"] = "completed"
                payload["attempts"][-1] = {"decision": "deny" if mutation == "deny-completed" else "allow",
                                          "returnStatus": "completed", "reason": None, "receipt": {}}
            if mutation == "coverage":
                payload["coverage"] = "all-effects"
            if mutation == "wrong-completion-binding":
                receipt = payload["attempts"][-1]["receipt"]["payload"]
                receipt["grantDigest"] = "0" * 64
                payload["attempts"][-1]["receipt"] = sign_record(receipt, keys["service"], DOMAIN)
            if mutation == "missing-field":
                payload.pop("faultInjection")
            (case / "record.json").write_bytes(canonical(sign_record(payload, keys["record"], RECORD_DOMAIN)))
            with caplog.at_level(logging.WARNING), pytest.raises(VerificationError) as error:
                read_case(case, pins)
            assert str(error.value) == reason
            assert "authority profile refused: " + reason in caplog.messages

