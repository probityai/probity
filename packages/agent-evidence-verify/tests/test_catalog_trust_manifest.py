"""``catalog_trust_manifest/v1`` against the reference reader's own corpus, case by case.

tests/data/catalog-trust-manifest/cases is the catalog-trust-manifest corpus of
probityai/agent-evidence-vectors at commit 01086cf076f276a1704e9a2022aa3a641902f2dc, with its
MANIFEST.json. Each case pins the reference reader's decision and reason; the adapter must give the
same on every case. tests/data/catalog-trust-manifest/break holds the nine matrix row 11 break
vectors as case directories, each with the reference reader's answer in expected.json and the break
author's own note in break-expected.txt.
"""

import hashlib
import json
import shutil
from pathlib import Path, PurePosixPath

import pytest
from agent_evidence_verify import adjudicate
from agent_evidence_verify.adapters import catalog_trust_manifest as reader
from agent_evidence_verify.common import CaseError
from agent_evidence_verify.key_authority import jwk_key_bytes

DATA = Path(__file__).parent / "data" / "catalog-trust-manifest"
MANIFEST = json.loads((DATA / "MANIFEST.json").read_text(encoding="utf-8"))
VECTORS = MANIFEST["vectors"]
BREAKS = sorted(p for p in (DATA / "break").iterdir() if p.is_dir())
SOURCE = "01086cf076f276a1704e9a2022aa3a641902f2dc"


def _bind(root: Path, path: str) -> dict:
    body = (root / path).read_bytes()
    return {"path": path, "length": len(body), "sha256": hashlib.sha256(body).hexdigest()}


def _normal(name: str) -> bool:
    path = PurePosixPath(name)
    return name == str(path) and not path.is_absolute() and \
        not any(part in (".", "..") for part in name.split("/"))


def _asserted_keys(documents: dict) -> list[str]:
    """The SHA-256 of every JWK the offline DID documents carry: the resolver output, pinned."""
    out = []
    for document in documents.values():
        if not isinstance(document, dict):
            continue
        for member in ("verificationMethod", "assertionMethod"):
            for method in document.get(member, []) if isinstance(document.get(member), list) else []:
                if isinstance(method, dict) and "publicKeyJwk" in method:
                    try:
                        out.append(hashlib.sha256(jwk_key_bytes(method["publicKeyJwk"])).hexdigest())
                    except CaseError:
                        continue
    return sorted(set(out))


def _pin_all(case_dir: Path) -> dict | None:
    try:
        documents = json.loads((case_dir / "did-documents.json").read_text(encoding="utf-8"))
    except ValueError:
        return None
    keys = _asserted_keys(documents) if isinstance(documents, dict) else []
    return {"kind": "pin", "keys": [{"public_key_sha256": k} for k in keys]} if keys else None


def _inputs(root: Path, name: str, key_authority="pin-all", **changes) -> tuple[dict, dict]:
    """A probity case and policy over the case directory ``root/name``."""
    case_dir = root / name
    context = json.loads((case_dir / "context.json").read_text(encoding="utf-8"))
    artifacts = {"catalog": _bind(root, f"{name}/catalog.json"),
                 "did-documents": _bind(root, f"{name}/did-documents.json")}
    assessment = {"claim_type": reader.CLAIM_TYPE, "catalog": "catalog",
                  "did_documents": "did-documents", "construction": context["construction"],
                  "role": context["role"], "at": context["at"]}
    for member in ("entry", "manifest"):
        if member in context:
            assessment[member] = context[member]
    if (case_dir / "artifact.json").is_file():
        artifacts["artifact"] = _bind(root, f"{name}/artifact.json")
        assessment["artifact"] = "artifact"
    named = []
    for index, file in enumerate(context.get("attestationFiles") or []):
        if not file:
            named.append(None)
            continue
        label = f"attestation-{index}"
        path = f"{name}/{file}"
        body = (case_dir / file).read_bytes() if (case_dir / file).is_file() else b""
        artifacts[label] = {"path": path, "length": len(body),
                            "sha256": hashlib.sha256(body).hexdigest()}
        named.append(label)
    if named:
        assessment["attestations"] = named
    authority = _pin_all(case_dir) if key_authority == "pin-all" else key_authority
    if authority is not None:
        assessment["key_authority"] = authority
    assessment.update(changes)
    case = {"schema_version": "probity-case/v1", "case_id": "c", "artifacts": artifacts}
    policy = {"schema_version": "probity-policy/v1", "assessments": {"c": assessment}}
    return case, policy


def _expect(result: dict, expected: dict) -> None:
    if expected["decision"] == "accept":
        assert (result["decision"], result["reason"]) == ("supported", expected["reason"])
    else:
        assert (result["decision"], result["reason"]) == ("contradicted", expected["reason"])
    check = result["checks"][0]
    assert (check["decision"], check["reason"]) == (expected["decision"], expected["reason"])


def test_the_corpus_is_the_pinned_copy() -> None:
    entries = (json.dumps(VECTORS, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()
    assert hashlib.sha256(entries).hexdigest() == MANIFEST["corpusDigest"]
    assert MANIFEST["suite"] == "catalog-trust-manifest/v1" and len(VECTORS) == 115
    for vector in VECTORS:
        directory = DATA / vector["path"]
        assert {p.name for p in directory.iterdir()} == set(vector["files"]), vector["id"]
        for name, digest in vector["files"].items():
            assert hashlib.sha256((directory / name).read_bytes()).hexdigest() == digest
    assert {p.name for p in (DATA / "cases").iterdir()} == {v["id"] for v in VECTORS}


def test_every_check_of_the_reader_is_a_code_of_the_port() -> None:
    reasons = {v["expected"]["reason"] for v in VECTORS}
    assert reasons <= set(reader.REASONS) | set(reader.PASS_REASON.values())
    assert set(reader.CHECKS) - reasons == set(), "a check no corpus case forces"


@pytest.mark.parametrize("vector", VECTORS, ids=[v["id"] for v in VECTORS])
def test_parity_with_the_reference_reader(vector: dict) -> None:
    root = DATA / "cases"
    name = vector["id"]
    expected = vector["expected"]
    case, policy = _inputs(root, name)
    context = json.loads((root / name / "context.json").read_text(encoding="utf-8"))
    files = [f for f in context.get("attestationFiles") or [] if f]
    if expected["reason"] in ("construction_unknown", "role_unknown"):
        # The consumer's own question is malformed: no verdict, and the error names the code.
        with pytest.raises(CaseError, match=expected["reason"]):
            adjudicate(case, policy, root)
        return
    if not all(_normal(f) for f in files):
        # The reader refuses a vendored file outside one path segment of its case directory as
        # attestation_digest_mismatch; here the artifact binder refuses the path before any read.
        assert expected["reason"] == "attestation_digest_mismatch"
        with pytest.raises(CaseError, match="normalized relative path"):
            adjudicate(case, policy, root)
        return
    _expect(adjudicate(case, policy, root), expected)


@pytest.mark.parametrize("case_dir", BREAKS, ids=[p.name for p in BREAKS])
def test_break_vectors_get_the_reference_readers_answer(case_dir: Path) -> None:
    expected = json.loads((case_dir / "expected.json").read_text(encoding="utf-8"))
    case, policy = _inputs(case_dir.parent, case_dir.name)
    _expect(adjudicate(case, policy, case_dir.parent), expected)


#: What each break vector was written to show, in the reader's vocabulary. 05's
#: ``crit_unsupported`` is ``jws_crit_unsupported`` here; 08's record carries 2**53 + 1 in the
#: signed bytes, which this profile refuses as ``number_not_interoperable`` before canonical form;
#: 09's manifest carries no signature, so the read ends at that gate before any attestation.
BREAK_CLASS = {
    "01-duplicate-identifier-live": "duplicate_member",
    "02-kid-not-under-identity": "kid_not_under_identity",
    "03-key-not-assertion-method": "key_not_assertion_method",
    "04-b64-without-crit": "b64_without_crit",
    "05-unknown-crit": "jws_crit_unsupported",
    "06-alg-key-mismatch": "alg_key_mismatch",
    "08-inexact-integer": "number_not_interoperable",
    "09-transplanted-attestation": "signature_missing",
}


def test_each_break_vector_is_refused_for_the_class_it_was_written_for() -> None:
    root = DATA / "break"
    assert [p.name for p in BREAKS] == sorted([*BREAK_CLASS, "07-utf16-member-order-valid"])
    for name, code in BREAK_CLASS.items():
        case, policy = _inputs(root, name)
        assert adjudicate(case, policy, root)["reason"] == code, name
    # 07 signs RFC 8785 bytes whose members sort by UTF-16 code units: the signature verifies, and
    # the read goes on past signature_invalid to the subject the vector does not carry.
    case, policy = _inputs(root, "07-utf16-member-order-valid")
    reason = adjudicate(case, policy, root)["reason"]
    assert reader.CHECKS.index(reason) > reader.CHECKS.index("signature_invalid")


# --------------------------------------------------------------------------- key authority

def _copy(tmp_path: Path, name: str) -> Path:
    shutil.copytree(DATA / "cases" / name, tmp_path / name)
    return tmp_path


def test_an_accepted_catalog_with_no_key_authority_is_not_established(tmp_path: Path) -> None:
    root = DATA / "cases"
    case, policy = _inputs(root, "accept-draft-es256", key_authority=None)
    result = adjudicate(case, policy, root)
    assert (result["decision"], result["reason"]) == ("not_established",
                                                      "no_key_authority_in_policy")
    assert result["checks"][0]["decision"] == "accept"


def test_a_signer_key_the_consumer_did_not_pin_is_contradicted() -> None:
    root = DATA / "cases"
    other = {"kind": "pin", "keys": [{"public_key_sha256": "0" * 64}]}
    case, policy = _inputs(root, "accept-draft-eddsa", key_authority=other)
    result = adjudicate(case, policy, root)
    assert (result["decision"], result["reason"]) == ("contradicted", "key_not_pinned")


def test_every_attestation_signer_goes_through_the_key_authority() -> None:
    """Pinning only the manifest signer leaves the attestation signer unauthorised."""
    root = DATA / "cases"
    name = "accept-attestations-dsse-bound"
    case, policy = _inputs(root, name)
    accepted = adjudicate(case, policy, root)
    assert accepted["decision"] == "supported"
    signers = accepted["checks"][0]["signers"]
    assert signers[0]["role"] == "manifest" and len(signers) > 1
    documents = json.loads((root / name / "did-documents.json").read_text(encoding="utf-8"))
    catalog = json.loads((root / name / "catalog.json").read_text(encoding="utf-8"))
    signer = catalog["entries"][0]["trustManifest"]["identity"]
    manifest_keys = _asserted_keys({signer: documents[signer]})
    attestation_dids = {s["kid"].split("#", 1)[0] for s in signers[1:]}
    assert signer not in attestation_dids, "the corpus case must sign attestations with another DID"
    only_manifest = {"kind": "pin", "keys": [{"public_key_sha256": k} for k in manifest_keys]}
    case, policy = _inputs(root, name, key_authority=only_manifest)
    result = adjudicate(case, policy, root)
    assert (result["decision"], result["reason"]) == ("contradicted", "key_not_pinned")


def test_a_did_web_authority_over_the_signers_pinned_document_supports(tmp_path: Path) -> None:
    name = "accept-draft-eddsa"
    root = _copy(tmp_path, name)
    documents = json.loads((root / name / "did-documents.json").read_text(encoding="utf-8"))
    catalog = json.loads((root / name / "catalog.json").read_text(encoding="utf-8"))
    signer = catalog["entries"][0]["trustManifest"]["identity"]
    body = json.dumps(documents[signer]).encode()
    (root / name / "did.json").write_bytes(body)
    authority = {"kind": "did-web", "did": signer, "document": "did",
                 "document_sha256": hashlib.sha256(body).hexdigest()}
    case, policy = _inputs(root, name, key_authority=authority)
    case["artifacts"]["did"] = _bind(root, f"{name}/did.json")
    result = adjudicate(case, policy, root)
    assert (result["decision"], result["reason"]) == ("supported", "signature_covers_release")
    assert result["checks"][1]["kind"] == "did-web"


# --------------------------------------------------------------------------- missing evidence

def test_a_url_entry_whose_artifact_is_not_supplied_is_not_established(tmp_path: Path) -> None:
    root = DATA / "cases"
    case, policy = _inputs(root, "accept-draft-es256")
    del policy["assessments"]["c"]["artifact"]
    result = adjudicate(case, policy, root)
    assert (result["decision"], result["reason"]) == ("not_established", "artifact_unavailable")


def test_an_unbound_catalog_is_not_established(tmp_path: Path) -> None:
    name = "accept-draft-es256"
    root = _copy(tmp_path, name)
    case, policy = _inputs(root, name)
    (root / name / "catalog.json").unlink()
    result = adjudicate(case, policy, root)
    assert (result["decision"], result["reason"]) == ("not_established", "catalog_unavailable")


def test_an_unbound_vendored_attestation_is_not_established(tmp_path: Path) -> None:
    name = "accept-attestations-dsse-bound"
    root = _copy(tmp_path, name)
    case, policy = _inputs(root, name)
    (root / name / "attestation-1.dsse.json").unlink()
    result = adjudicate(case, policy, root)
    assert (result["decision"], result["reason"]) == ("not_established",
                                                      "attestation_unavailable")


def test_a_check_time_that_is_not_rfc3339_is_a_case_error() -> None:
    root = DATA / "cases"
    case, policy = _inputs(root, "accept-draft-es256", at="2026-11-16 00:00:00Z")
    with pytest.raises(CaseError, match="assessment.at"):
        adjudicate(case, policy, root)


# --------------------------------------------------------------------------- reading rules

def test_a_number_outside_the_signed_bytes_does_not_refuse(tmp_path: Path) -> None:
    """The profile reads unsafe integers and lone surrogates in the signed bytes only: the same
    value in a DID document the signature does not cover changes nothing."""
    name = "accept-draft-eddsa"
    root = _copy(tmp_path, name)
    path = root / name / "did-documents.json"
    documents = json.loads(path.read_text(encoding="utf-8"))
    text = json.dumps(documents)[:-1] + ', "x-big": 9007199254740993, "x-s": "\\ud800"}'
    path.write_text(text, encoding="utf-8")
    case, policy = _inputs(root, name)
    result = adjudicate(case, policy, root)
    assert (result["decision"], result["reason"]) == ("supported", "signature_covers_release")


def test_the_der_reader_refuses_a_non_minimal_integer() -> None:
    raw = bytes([0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01])
    assert reader.der_signature(raw) is None
    minimal = bytes([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01])
    assert reader.der_signature(minimal) == (1).to_bytes(32, "big") + (1).to_bytes(32, "big")


@pytest.mark.parametrize("text,ok", [
    ("2016-12-31T23:59:60Z", True), ("2017-01-01T00:59:60+01:00", True),
    ("2017-12-31T23:59:60Z", False), ("2026-11-16t00:00:00z", True),
    ("2026-02-29T00:00:00Z", False), ("2026-11-16T00:00:00", False),
    ("2026-11-16T00:00:00١Z", False),
])
def test_instants_are_read_exactly(text: str, ok: bool) -> None:
    assert (reader.instant(text) is not None) is ok
