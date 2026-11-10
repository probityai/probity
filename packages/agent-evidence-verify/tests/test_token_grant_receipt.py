"""token_grant_receipt/v1 over receipts built here in the shape the Keycloak evidence hook writes.

The end-to-end run in integrations/keycloak-evidence-hook/e2e checks receipts a real Keycloak
wrote; these tests pin each rule of the claim type, including the refusals.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from agent_evidence_verify import adjudicate
from agent_evidence_verify.adapters import token_grant_receipt as tgr
from agent_evidence_verify.common import CaseError
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

SEED = bytes(range(32))
KEY = Ed25519PrivateKey.from_private_bytes(SEED)
PUBLIC = KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
KEY_ID = hashlib.sha256(PUBLIC).hexdigest()
JTI_SHA = hashlib.sha256(b"onrtte:1").hexdigest()
SUBJECT_TOKEN_SHA = hashlib.sha256(b"subject-token").hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def statement(index: int = 0, previous: str | None = None, **changes: Any) -> dict:
    predicate = {
        "issuer": "http://127.0.0.1:8080/realms/agents",
        "grantType": "urn:ietf:params:oauth:grant-type:token-exchange",
        "eventId": f"ev-{index}", "issuedAt": "2026-11-10T06:00:00Z",
        "actor": {"clientId": "agent-gateway", "authMethod": "client-secret"},
        "subject": {"userId": "user-1"},
        "subjectToken": {"sha256": SUBJECT_TOKEN_SHA, "issuedTo": "agent-ui"},
        "actorTokenSha256": None,
        "requestedTokenType": "urn:ietf:params:oauth:token-type:access_token",
        "audience": ["tools-api"], "scope": ["tools:execute", "tools:read"],
        "refreshTokenIdSha256": None,
        "recorder": {"id": "keycloak-evidence-hook", "version": "0.1.0", "keyId": KEY_ID},
        "chain": {"stream": "node-a", "index": index, "previous": previous},
    }
    predicate.update(changes)
    return {"_type": tgr.STATEMENT_TYPE, "predicateType": tgr.PREDICATE_TYPE,
            "subject": [{"name": "access-token-id", "digest": {"sha256": JTI_SHA}}],
            "predicate": predicate}


def envelope(body: dict, key: Ed25519PrivateKey = KEY) -> bytes:
    payload = canonical(body)
    sig = key.sign(tgr.pae(tgr.PAYLOAD_TYPE, payload))
    return canonical({"payload": base64.b64encode(payload).decode("ascii"),
                      "payloadType": tgr.PAYLOAD_TYPE,
                      "signatures": [{"keyid": KEY_ID, "sig": base64.b64encode(sig).decode("ascii")}]})


EXPECTED = {"issuer": "http://127.0.0.1:8080/realms/agents",
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "actor_client_id": "agent-gateway", "access_token_id_sha256": JTI_SHA,
            "subject_user_id": "user-1", "subject_token_sha256": SUBJECT_TOKEN_SHA,
            "audience": ["tools-api"], "scope_allowed": ["tools:execute", "tools:read", "tools:write"]}


def judge(root: Path, raw: bytes, expected: dict | None = None, log: bytes | None = None,
          key: str = PUBLIC.hex()) -> dict:
    artifacts = {}
    for name, data in (("envelope", raw), ("log", log)):
        if data is None:
            continue
        (root / name).write_bytes(data)
        artifacts[name] = {"path": name, "length": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    assessment = {"claim_type": tgr.CLAIM_TYPE, "envelope": "envelope", "recorder_public_key": key,
                  "expected": EXPECTED if expected is None else expected}
    if log is not None:
        assessment["log"] = "log"
    case = {"schema_version": "probity-case/v1", "case_id": "c", "artifacts": artifacts}
    policy = {"schema_version": "probity-policy/v1", "assessments": {"c": assessment}}
    return adjudicate(case, policy, root)


def chained_log(count: int) -> list[bytes]:
    lines: list[bytes] = []
    previous = None
    for index in range(count):
        line = envelope(statement(index, previous))
        lines.append(line)
        previous = hashlib.sha256(line).hexdigest()
    return lines


def test_matching_receipt_is_supported(tmp_path: Path) -> None:
    result = judge(tmp_path, envelope(statement()))
    assert (result["decision"], result["reason"]) == ("supported", "grant_recorded_as_expected")
    assert all(check["status"] == "met" for check in result["checks"])


def test_changed_payload_is_not_established(tmp_path: Path) -> None:
    raw = json.loads(envelope(statement()))
    body = json.loads(base64.b64decode(raw["payload"]))
    body["predicate"]["scope"] = ["tools:admin"]
    raw["payload"] = base64.b64encode(canonical(body)).decode("ascii")
    result = judge(tmp_path, canonical(raw))
    assert (result["decision"], result["reason"]) == ("not_established", "receipt_signature_unverified")


def test_other_key_is_not_established(tmp_path: Path) -> None:
    other = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    result = judge(tmp_path, envelope(statement(), other))
    assert result["reason"] == "receipt_signature_unverified"


@pytest.mark.parametrize(("field", "value", "reason"), [
    ("actor_client_id", "someone-else", "grant_actor_mismatch"),
    ("grant_type", "client_credentials", "grant_type_mismatch"),
    ("subject_user_id", "user-2", "grant_subject_mismatch"),
    ("access_token_id_sha256", "0" * 64, "grant_token_mismatch"),
    ("subject_token_sha256", "1" * 64, "grant_subject_token_mismatch"),
    ("audience", ["other-api"], "grant_audience_mismatch"),
    ("scope_allowed", ["tools:read"], "grant_scope_exceeds_expected"),
])
def test_each_expectation_contradicts(tmp_path: Path, field: str, value: Any, reason: str) -> None:
    result = judge(tmp_path, envelope(statement()), {**EXPECTED, field: value})
    assert (result["decision"], result["reason"]) == ("contradicted", reason)


def test_unbound_envelope_is_not_established(tmp_path: Path) -> None:
    raw = envelope(statement())
    case = {"schema_version": "probity-case/v1", "case_id": "c", "artifacts": {"envelope": {
        "path": "missing", "length": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}}}
    policy = {"schema_version": "probity-policy/v1", "assessments": {"c": {
        "claim_type": tgr.CLAIM_TYPE, "envelope": "envelope", "recorder_public_key": PUBLIC.hex(),
        "expected": EXPECTED}}}
    assert adjudicate(case, policy, tmp_path)["reason"] == "envelope_unavailable"


@pytest.mark.parametrize("body", [
    {**statement(), "predicateType": "https://example.test/other"},
    statement(extra="member"),
    statement(scope=["tools:read", "tools:execute"]),
    statement(issuedAt="2026-11-10 06:00:00"),
    statement(recorder={"id": "keycloak-evidence-hook", "version": "0.1.0", "keyId": "0" * 64}),
])
def test_malformed_signed_receipt_is_refused(tmp_path: Path, body: dict) -> None:
    with pytest.raises(CaseError):
        judge(tmp_path, envelope(body))


def test_repeated_member_is_refused(tmp_path: Path) -> None:
    raw = envelope(statement()).replace(b'"payloadType"', b'"payloadType":"x","payloadType"', 1)
    with pytest.raises(CaseError):
        judge(tmp_path, raw)


def test_intact_log_is_supported(tmp_path: Path) -> None:
    lines = chained_log(3)
    result = judge(tmp_path, lines[0], log=b"\n".join(lines) + b"\n")
    assert result["decision"] == "supported"
    log_check = next(check for check in result["checks"] if check["id"] == "receipt_log")
    assert (log_check["lines"], log_check["head_sha256"]) == (3, hashlib.sha256(lines[2]).hexdigest())


@pytest.mark.parametrize("edit", ["remove-middle", "swap", "foreign-line", "receipt-absent"])
def test_broken_log_is_not_established(tmp_path: Path, edit: str) -> None:
    lines = chained_log(4)
    receipt = lines[0]
    if edit == "remove-middle":
        lines = [lines[0], lines[2], lines[3]]
    elif edit == "swap":
        lines = [lines[0], lines[2], lines[1], lines[3]]
    elif edit == "foreign-line":
        other = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
        lines[2] = envelope(statement(2, hashlib.sha256(lines[1]).hexdigest()), other)
    else:
        lines = lines[1:]
    result = judge(tmp_path, receipt, log=b"\n".join(lines) + b"\n")
    assert (result["decision"], result["reason"]) == ("not_established", "receipt_log_unestablished")
