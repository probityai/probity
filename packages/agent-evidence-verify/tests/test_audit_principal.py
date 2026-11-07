"""audit_principal/v1 over rows PR1 to PR11 of the agent audit record corpus.

Every expectation is read from tests/data/audit-principal/MANIFEST.json (a copy of the published
rows); none comes from the verifier. Members are judged through the kernel, as a consumer calls it.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from agent_evidence_verify import adjudicate
from agent_evidence_verify.adapters import audit_principal

DATA = Path(__file__).resolve().parent / "data" / "audit-principal"
MANIFEST = json.loads((DATA / "MANIFEST.json").read_text(encoding="utf-8"))
KEY = MANIFEST["keys"]["observer"]["publicKey"]


def _judge(root: Path, case_id: str, key: str = KEY) -> dict:
    data = (root / "envelope.json").read_bytes()
    artifact = {"path": "envelope.json", "length": len(data),
                "sha256": hashlib.sha256(data).hexdigest()}
    case = {"schema_version": "probity-case/v1", "case_id": case_id,
            "artifacts": {"envelope.json": artifact}}
    policy = {"schema_version": "probity-policy/v1", "assessments": {case_id: {
        "claim_type": "audit_principal/v1", "envelope": "envelope.json",
        "observer_public_key": key}}}
    return adjudicate(case, policy, root)


def _member(tmp_path: Path, entry: dict[str, Any]) -> dict:
    (tmp_path / "envelope.json").write_bytes((DATA / entry["file"]).read_bytes())
    return _judge(tmp_path, entry["id"])


def test_manifest_is_complete() -> None:
    assert [e["draftId"] for e in MANIFEST["vectors"]] == [f"PR{n}" for n in range(1, 12)]
    assert {e["kind"] for e in MANIFEST["vectors"]} == {"accept", "reject"}


@pytest.mark.parametrize("entry", MANIFEST["vectors"], ids=lambda e: e["draftId"])
def test_member(tmp_path: Path, entry: dict[str, Any]) -> None:
    result = _member(tmp_path, entry)
    check = result["checks"][0]
    expected = entry["expected"]
    if expected["verdict"] == "valid":
        assert (result["decision"], result["reason"]) == ("supported", "principal_conforms")
        assert check["verdict"] == "valid"
    else:
        assert result["decision"] == "contradicted"
        assert check["verdict"] == expected["verdict"]
        assert check["codes"] == expected["codes"]
        assert result["reason"] == expected["codes"][0]


def test_a_wrong_pinned_key_fails_the_signature(tmp_path: Path) -> None:
    entry = MANIFEST["vectors"][0]
    (tmp_path / "envelope.json").write_bytes((DATA / entry["file"]).read_bytes())
    result = _judge(tmp_path, entry["id"], key="00" * 32)
    assert result["decision"] == "contradicted"
    assert result["checks"][0]["verdict"] == "invalid"
    assert result["reason"] == "envelope-signature-invalid"


def test_a_tampered_principal_is_refused_before_the_signature(tmp_path: Path) -> None:
    """A principal edit that breaks a rule is reported by the rule, not by the signature."""
    entry = MANIFEST["vectors"][0]
    envelope = json.loads((DATA / entry["file"]).read_text(encoding="utf-8"))
    statement = json.loads(base64.b64decode(envelope["payload"]))
    statement["predicate"]["principal"]["clientId"] = ""
    envelope["payload"] = base64.b64encode(json.dumps(statement).encode("utf-8")).decode("ascii")
    (tmp_path / "envelope.json").write_text(json.dumps(envelope), encoding="utf-8")
    result = _judge(tmp_path, entry["id"])
    assert result["reason"] == "principal-malformed"


def test_a_record_without_a_principal_is_not_established(tmp_path: Path) -> None:
    entry = MANIFEST["vectors"][0]
    envelope = json.loads((DATA / entry["file"]).read_text(encoding="utf-8"))
    statement = json.loads(base64.b64decode(envelope["payload"]))
    del statement["predicate"]["principal"]
    envelope["payload"] = base64.b64encode(json.dumps(statement).encode("utf-8")).decode("ascii")
    (tmp_path / "envelope.json").write_text(json.dumps(envelope), encoding="utf-8")
    result = _judge(tmp_path, entry["id"])
    assert (result["decision"], result["reason"]) == ("not_established", "principal_absent")


def test_a_repeated_member_name_is_refused(tmp_path: Path) -> None:
    text = (DATA / MANIFEST["vectors"][0]["file"]).read_text(encoding="utf-8")
    (tmp_path / "envelope.json").write_text(
        text.replace('{', '{"payloadType": "x", ', 1), encoding="utf-8")
    result = _judge(tmp_path, "dup")
    assert result["reason"] == "duplicate-member"


def test_thumbprint_reproduces_the_rfc_7638_example() -> None:
    key = {"kty": "RSA", "e": "AQAB", "n": (
        "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_"
        "BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_"
        "FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI"
        "4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw")}
    assert audit_principal.jwk_thumbprint(key) == "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
