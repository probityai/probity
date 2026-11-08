"""Sealing a governance export: census with denominators, offline re-check, silent-change detection."""

from __future__ import annotations

import json

from probity_records import Signer, compare_seals, seal_export, verify_export_seal
from probity_records.__main__ import main

ENTITIES = {"content": [
    {"id": "a1", "type": "AI_SYSTEM", "stage": "Approved", "createdBy": "u1", "lastModifiedBy": "u2",
     "createdDate": "2026-10-01T00:00:00Z", "lastUpdatedDate": "2026-10-05T00:00:00Z"},
    {"id": "a2", "type": "AI_AGENT", "stage": "Under Review", "createdBy": "u1",
     "createdDate": "2026-10-02T00:00:00Z"},
    {"id": "a2", "type": "AI_AGENT", "stage": "Approved", "createdBy": "u3"},
    {"type": "MODEL", "stage": "Intake"},
]}


def _bytes(doc) -> bytes:
    return json.dumps(doc).encode()


def test_census_reports_denominators_and_defects() -> None:
    signer = Signer.generate()
    data = _bytes(ENTITIES)
    seal = seal_export(signer, data, source="governance-tenant-x", kind="entities", captured_at="2026-11-08T00:00:00Z")
    report = verify_export_seal(seal, data, [signer.public_pem()])
    assert report["verdict"] == "PASS", report["failures"]
    c = report["census"]
    assert (c["records"], c["missingIds"], c["duplicateIds"]) == (4, 1, ["a2"])
    assert c["fieldsPresent"]["modified_by"] == {"of": 4, "present": 1}
    assert c["byStage"] == {"Approved": 2, "Intake": 1, "Under Review": 1}


def test_any_change_to_the_export_or_seal_fails() -> None:
    signer = Signer.generate()
    data = _bytes(ENTITIES)
    seal = seal_export(signer, data, source="t", kind="entities", captured_at="2026-11-08T00:00:00Z")
    edited = json.loads(data)
    edited["content"][0]["stage"] = "Rejected"
    assert "export_bytes_differ_from_seal" in verify_export_seal(seal, _bytes(edited), [signer.public_pem()])["failures"]
    assert verify_export_seal(seal, data, [Signer.generate().public_pem()])["verdict"] == "FAIL"
    assert verify_export_seal(seal, b'{"content": [{"id": 1, "id": 2}]}', [signer.public_pem()])["verdict"] == "FAIL"


def test_compare_seals_finds_silent_edits_and_deletions() -> None:
    signer = Signer.generate()
    old = seal_export(signer, _bytes(ENTITIES), source="t", kind="entities", captured_at="2026-11-01T00:00:00Z")
    later = json.loads(_bytes(ENTITIES))
    later["content"][0]["stage"] = "Rejected"
    later["content"] = [r for r in later["content"] if r.get("id") != "a2"] + [{"id": "a9", "stage": "Intake"}]
    new = seal_export(signer, _bytes(later), source="t", kind="entities", captured_at="2026-11-08T00:00:00Z")
    assert compare_seals(old, new) == {"added": ["a9"], "changed": ["a1"], "removed": ["a2"]}


def test_cli_seals_and_verifies(tmp_path, capsys) -> None:
    signer = Signer.generate()
    (tmp_path / "key.pem").write_bytes(signer.private_pem())
    (tmp_path / "pub.pem").write_bytes(signer.public_pem())
    (tmp_path / "export.json").write_bytes(_bytes(ENTITIES))
    assert main(["seal-export", str(tmp_path / "export.json"), "--key", str(tmp_path / "key.pem"), "--source", "t",
                 "--kind", "entities", "--out", str(tmp_path / "seal.json")]) == 0
    assert main(["verify-export", str(tmp_path / "export.json"), str(tmp_path / "seal.json"),
                 "--pub", str(tmp_path / "pub.pem")]) == 0
    assert '"verdict": "PASS"' in capsys.readouterr().out
