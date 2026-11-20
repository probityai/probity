"""``a2a_signed_card/v1`` on its vectors: valid, tampered, wrong-kid, signatures-included, forged-key.

tests/data/a2a-signed-card is written by scripts/gen-signed-card-and-receipt-vectors.py from fixed
test keys; cases.json pins each case's decision and reason. The foreign-key cases are the
counter-example the conformance matrix found in signed discovery records, applied to Agent Cards:
a stranger signs under the owner's kid and serves the key set the reader fetches.
"""

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from agent_evidence_verify import adjudicate
from agent_evidence_verify.adapters import a2a_signed_card as reader
from agent_evidence_verify.common import CaseError

ROOT = Path(__file__).resolve().parents[1]
DATA = Path(__file__).parent / "data" / "a2a-signed-card"
INDEX = json.loads((DATA / "cases.json").read_text(encoding="utf-8"))
CASES = {case["id"]: case for case in INDEX["cases"]}


def _bind(directory: Path) -> dict:
    out = {}
    for path in sorted(directory.iterdir()):
        body = path.read_bytes()
        out[path.name] = {"path": path.name, "length": len(body),
                          "sha256": hashlib.sha256(body).hexdigest()}
    return out


def _run(directory: Path, assessment: dict) -> dict:
    case = {"schema_version": "probity-case/v1", "case_id": directory.name,
            "artifacts": _bind(directory)}
    policy = {"schema_version": "probity-policy/v1",
              "assessments": {directory.name: dict(assessment, claim_type=reader.CLAIM_TYPE)}}
    return adjudicate(case, policy, directory)


@pytest.mark.parametrize("name", sorted(CASES))
def test_vector(name: str) -> None:
    case = CASES[name]
    result = _run(DATA / name, case["assessment"])
    assert (result["decision"], result["reason"]) == (case["expect"]["decision"],
                                                       case["expect"]["reason"]), case["description"]


def test_every_refusal_code_has_a_vector() -> None:
    pinned = {case["expect"]["reason"] for case in INDEX["cases"]}
    assert set(reader.REASONS) <= pinned, sorted(set(reader.REASONS) - pinned)


def test_vectors_regenerate_byte_for_byte() -> None:
    script = ROOT / "scripts" / "gen-signed-card-and-receipt-vectors.py"
    run = subprocess.run([sys.executable, "-I", str(script), "--check"], capture_output=True,
                         text=True, check=False)
    assert run.returncode == 0, run.stderr


def test_supported_card_reports_the_extension_and_the_key_set() -> None:
    result = _run(DATA / "valid-conformance-extension",
                  CASES["valid-conformance-extension"]["assessment"])
    card_check, authority = result["checks"]
    assert card_check["conformance_extension"] == {
        "corpus": "agent-evidence-vectors", "corpus_version": "0.37.0",
        "verifier": "agent-evidence-verify", "verifier_version": "0.7.0"}
    assert card_check["signers"] == ["did:web:agent.example.test#ed25519"]
    assert authority["kind"] == "pin" and authority["outcome"] == "authorized"
    assert len(authority["key_set_sha256"]) == 64
    assert result["reference"]["verifier"]["id"].endswith("/agent-evidence-verify")


def test_extension_removed_from_a_signed_card_breaks_its_signature(tmp_path: Path) -> None:
    """Rung 7 in one test: the extension is covered by the card's own JWS."""
    source = DATA / "valid-conformance-extension"
    shutil.copytree(source, tmp_path / "case")
    card = json.loads((tmp_path / "case" / "card.json").read_text(encoding="utf-8"))
    card["capabilities"]["extensions"] = []
    (tmp_path / "case" / "card.json").write_text(json.dumps(card), encoding="utf-8")
    result = _run(tmp_path / "case", CASES["valid-conformance-extension"]["assessment"])
    assert (result["decision"], result["reason"]) == ("contradicted", "signature_invalid")


def test_card_did_must_be_a_did() -> None:
    assessment = dict(CASES["valid-eddsa-pinned"]["assessment"], card_did="agent.example.test")
    with pytest.raises(CaseError, match="card_did"):
        _run(DATA / "valid-eddsa-pinned", assessment)


def test_missing_card_is_not_established(tmp_path: Path) -> None:
    shutil.copytree(DATA / "valid-eddsa-pinned", tmp_path / "case")
    case = {"schema_version": "probity-case/v1", "case_id": "c",
            "artifacts": _bind(tmp_path / "case")}
    (tmp_path / "case" / "card.json").unlink()
    policy = {"schema_version": "probity-policy/v1", "assessments": {"c": dict(
        CASES["valid-eddsa-pinned"]["assessment"], claim_type=reader.CLAIM_TYPE)}}
    result = adjudicate(case, policy, tmp_path / "case")
    assert (result["decision"], result["reason"]) == ("not_established", "card_unavailable")


#: (version, exact). PEP 440 normalized public versions and SemVer 2.0.0 without build metadata.
VERSIONS = (
    ("0.7.0", True), ("1", True), ("1.0rc1", True), ("1.0a0", True), ("0.7.0.post1", True),
    ("2.0.dev3", True), ("1.0rc1.post2.dev3", True), ("1.0.0-rc.1", True),
    ("1.0.0-alpha.beta-1", True), ("1.0.0-0", True),
    ("01.0", False), ("0.037.0", False), ("1.0-rc1", False), ("1.0.0alpha", False),
    ("1.0.0-01", False), ("1.0.0+build", False), ("1!1.0", False), ("1.0+local", False),
    (">=0.37", False), ("^1.2", False), ("~1.2", False), ("1.2.*", False), ("1.x", False),
    ("1.0.0 ", False), ("1.0.0\n", False), ("", False), ("1..0", False), ("v1.0.0", False),
    ("1.0,2.0", False), ("1.0.0-", False), ("١.0", False),
)


@pytest.mark.parametrize(("version", "exact"), VERSIONS)
def test_extension_version_is_one_exact_release(version: str, exact: bool) -> None:
    assert bool(reader._EXACT_VERSION.fullmatch(version)) is exact


@pytest.mark.parametrize("shape", [True, 7, "x", {"id": "#k"}, None, [1, "a", None]])
def test_a_did_document_of_any_shape_names_a_key_or_none(shape: object) -> None:
    """The document is case evidence, read before the authority checks its pin: never a crash."""
    for member in ("verificationMethod", "assertionMethod", "authentication"):
        document = json.dumps({"id": "did:web:a.test", member: shape}).encode()
        assert reader._document_key(document, "did:web:a.test", "did:web:a.test#k") is None


def _evidence(directory: Path) -> tuple:
    return tuple(sorted((p.name, p.read_bytes()) for p in directory.iterdir()))


@pytest.mark.parametrize("family", ["a2a-signed-card", "co-signed-receipt"])
def test_cases_with_different_verdicts_hold_different_evidence(family: str) -> None:
    """A mutation the generator failed to apply leaves a copy of a valid case pinned to a refusal;
    the signatures-included card was once byte-identical to valid-eddsa-pinned."""
    root = Path(__file__).parent / "data" / family
    index = json.loads((root / "cases.json").read_text(encoding="utf-8"))["cases"]
    seen: dict[tuple, tuple] = {}
    for case in index:
        key = (_evidence(root / case["id"]), json.dumps(case["assessment"], sort_keys=True))
        verdict = (case["expect"]["decision"], case["expect"]["reason"])
        assert seen.setdefault(key, verdict) == verdict, case["id"]
