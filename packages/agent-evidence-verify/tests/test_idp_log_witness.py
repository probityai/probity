"""idp_log_witness/v1 over signed audit records and identity-provider log exports.

The records are members PR1 (a user principal), PR2 (a client-credentials principal) and PR4 (a
principal whose key thumbprint does not match) of the agent audit record corpus, copied in
tests/data/audit-principal. The exports follow the published shapes: Auth0 tenant log events
(the ``seccft``, ``success_on_behalf_of_token_exchange`` and ``feccft`` schemas, including
``agent_id``, ``external_agent_id`` and the on-behalf-of ``details.actor`` chain) and Okta System
Log ``LogEvent`` objects (``uuid``, ``published``, ``eventType``, ``actor``, ``target``,
``outcome``) for the event type ``app.oauth2.as.token.grant.access_token``.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from agent_evidence_verify import adjudicate
from agent_evidence_verify.common import CaseError

DATA = Path(__file__).resolve().parent / "data" / "audit-principal"
MANIFEST = json.loads((DATA / "MANIFEST.json").read_text(encoding="utf-8"))
KEY = MANIFEST["keys"]["observer"]["publicKey"]
FILES = {e["draftId"]: e["file"] for e in MANIFEST["vectors"]}
ISSUER = "https://idp.example.org/oauth2/default"
WINDOW = {"start": "2026-09-19T10:00:00Z", "end": "2026-09-19T12:00:00Z"}


def auth0(log_id: str, kind: str, date: str = "2026-09-19T11:00:01.000Z", **fields: Any) -> dict:
    event = {"log_id": log_id, "type": kind, "date": date, "client_id": "reconciler",
             "hostname": "idp.example.org", "description": ""}
    event.update(fields)
    return event


def okta(uuid: str, actor_id: str, target_id: str, result: str = "SUCCESS",
         published: str = "2026-09-19T11:00:02.000Z", actor_type: str = "PublicClientApp") -> dict:
    return {"uuid": uuid, "published": published,
            "eventType": "app.oauth2.as.token.grant.access_token",
            "actor": {"id": actor_id, "type": actor_type, "alternateId": actor_id},
            "target": [{"id": target_id, "type": "User", "alternateId": target_id}],
            "outcome": {"result": result}}


def judge(tmp_path: Path, records: list[str], export: Any, provider: str = "auth0",
          raw: bytes | None = None, issuer: str = ISSUER, window: dict | None = None) -> dict:
    artifacts = {}
    names = []
    for draft in records:
        data = (DATA / FILES[draft]).read_bytes()
        name = f"{draft}.json"
        (tmp_path / name).write_bytes(data)
        artifacts[name] = {"path": name, "length": len(data),
                           "sha256": hashlib.sha256(data).hexdigest()}
        names.append(name)
    data = raw if raw is not None else json.dumps(export).encode()
    (tmp_path / "export.json").write_bytes(data)
    artifacts["export.json"] = {"path": "export.json", "length": len(data),
                                "sha256": hashlib.sha256(data).hexdigest()}
    case = {"schema_version": "probity-case/v1", "case_id": "c1", "artifacts": artifacts}
    policy = {"schema_version": "probity-policy/v1", "assessments": {"c1": {
        "claim_type": "idp_log_witness/v1", "envelopes": names, "observer_public_key": KEY,
        "idp_export": "export.json", "provider": provider, "issuer": issuer,
        "export_window": window or WINDOW}}}
    return adjudicate(case, policy, tmp_path)


def outcome(result: dict) -> tuple[str, str]:
    return result["decision"], result["reason"]


def test_auth0_user_and_agent_issuances_reconcile(tmp_path: Path) -> None:
    export = [auth0("a1", "success_on_behalf_of_token_exchange", user_id="user:alice@example.org",
                    agent_id="agt_1", details={"actor": {"sub": "agt_1", "act": {"sub": "spa-client"}}}),
              auth0("a2", "seccft", external_agent_id="reconciler", agent_id="agt_1")]
    result = judge(tmp_path, ["PR1", "PR2"], export)
    assert outcome(result) == ("supported", "issuances_reconciled")
    assert result["checks"][0]["backing_events"] == ["a1"]
    assert result["checks"][1]["backing_events"] == ["a2"]
    assert result["checks"][-1] == {"id": "unobserved_issuances", "status": "pass", "events": []}


def test_auth0_log_stream_batches_and_ndjson_are_read(tmp_path: Path) -> None:
    batch = [{"log_id": "a1", "data": auth0("a1", "sertft", user_id="user:alice@example.org")}]
    assert outcome(judge(tmp_path, ["PR1"], batch)) == ("supported", "issuances_reconciled")
    line = json.dumps(auth0("a1", "seccft", user_id="user:alice@example.org")).encode() + b"\n"
    assert outcome(judge(tmp_path, ["PR1"], None, raw=line)) == ("supported", "issuances_reconciled")


def test_record_without_logged_issuance_is_a_finding(tmp_path: Path) -> None:
    export = [auth0("a9", "seccft", client_id="other-client", user_id="user:alice@example.org")]
    result = judge(tmp_path, ["PR1"], export)
    assert outcome(result) == ("contradicted", "issuance-unlogged")


def test_issuance_to_another_subject_is_a_principal_mismatch(tmp_path: Path) -> None:
    export = [auth0("a1", "seccft", user_id="user:mallory@example.org")]
    assert outcome(judge(tmp_path, ["PR1"], export)) == ("contradicted", "issuance-principal-mismatch")


def test_only_refused_issuances_contradict(tmp_path: Path) -> None:
    export = [auth0("a1", "feccft", user_id="user:alice@example.org")]
    assert outcome(judge(tmp_path, ["PR1"], export)) == ("contradicted", "issuance-refused")


def test_issuance_outside_skew_is_unlogged(tmp_path: Path) -> None:
    export = [auth0("a1", "seccft", date="2026-09-19T11:05:01.000Z", user_id="user:alice@example.org")]
    assert outcome(judge(tmp_path, ["PR1"], export)) == ("contradicted", "issuance-unlogged")


def test_window_that_misses_the_issuance_leaves_the_claim_open(tmp_path: Path) -> None:
    window = {"start": "2026-09-19T11:10:00Z", "end": "2026-09-19T12:00:00Z"}
    result = judge(tmp_path, ["PR1"], [], window=window)
    assert outcome(result) == ("not_established", "issuance-outside-window")


def test_every_record_must_reconcile(tmp_path: Path) -> None:
    window = {"start": "2026-09-19T10:59:00Z", "end": "2026-09-19T12:00:00Z"}
    export = [auth0("a1", "seccft", user_id="user:mallory@example.org")]
    result = judge(tmp_path, ["PR1", "PR2"], export, window=window)
    assert outcome(result) == ("contradicted", "issuance-principal-mismatch")


def test_unpinned_issuer_is_a_finding(tmp_path: Path) -> None:
    export = [auth0("a1", "seccft", user_id="user:alice@example.org")]
    result = judge(tmp_path, ["PR1"], export, issuer="https://tenant.us.auth0.com/")
    assert outcome(result) == ("contradicted", "principal-issuer-unpinned")


def test_nonconforming_record_contradicts_with_its_rule(tmp_path: Path) -> None:
    export = [auth0("a1", "seccft", user_id="user:alice@example.org")]
    result = judge(tmp_path, ["PR4"], export)
    assert outcome(result) == ("contradicted", "principal-thumbprint-mismatch")


def test_agent_issuance_no_record_accounts_for_is_reported(tmp_path: Path) -> None:
    export = [auth0("a1", "seccft", user_id="user:alice@example.org"),
              auth0("a7", "seccft", date="2026-09-19T11:40:00.000Z", agent_id="agt_9",
                    sub_profile="ai_agent")]
    result = judge(tmp_path, ["PR1"], export)
    assert outcome(result) == ("supported", "issuances_reconciled")
    assert result["checks"][-1] == {"id": "unobserved_issuances", "status": "unknown", "events": ["a7"]}


def test_okta_system_log_grant_reconciles(tmp_path: Path) -> None:
    export = [okta("o1", "reconciler", "user:alice@example.org"),
              okta("o2", "reconciler", "reconciler", actor_type="AIAgent")]
    result = judge(tmp_path, ["PR1", "PR2"], export, provider="okta")
    assert outcome(result) == ("supported", "issuances_reconciled")


def test_okta_failed_grant_is_refused(tmp_path: Path) -> None:
    export = [okta("o1", "reconciler", "user:alice@example.org", result="FAILURE")]
    assert outcome(judge(tmp_path, ["PR1"], export, provider="okta")) == (
        "contradicted", "issuance-refused")


def test_okta_unrelated_event_types_are_ignored(tmp_path: Path) -> None:
    event = okta("o1", "reconciler", "user:alice@example.org")
    event["eventType"] = "user.session.start"
    assert outcome(judge(tmp_path, ["PR1"], [event], provider="okta")) == (
        "contradicted", "issuance-unlogged")


@pytest.mark.parametrize(("provider", "raw"), [
    ("auth0", b"{not json"),
    ("okta", b"{\"uuid\": \"o1\"}"),
    ("auth0", json.dumps([{"type": "seccft", "log_id": "a1", "date": "yesterday"}]).encode()),
    ("okta", json.dumps([{"eventType": "app.oauth2.as.token.grant.access_token",
                          "uuid": "o1", "published": "2026-09-19T11:00:00Z",
                          "actor": "x", "target": []}]).encode()),
])
def test_malformed_export_refuses_without_a_verdict(tmp_path: Path, provider: str, raw: bytes) -> None:
    with pytest.raises(CaseError):
        judge(tmp_path, ["PR1"], None, provider=provider, raw=raw)


def test_unknown_provider_refuses(tmp_path: Path) -> None:
    with pytest.raises(CaseError):
        judge(tmp_path, ["PR1"], [], provider="entra")
