"""The tool bodies. Each is a thin function over one library call, with bounded output."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import subprocess
import sys
import tempfile
from importlib import resources
from pathlib import Path, PurePosixPath
from typing import Any

import jcs_admit
import yaml
from jcs_admit import dsse
from agent_evidence_admission.digest_check import check, parse_document
from probity_verify.core import CaseError, adjudicate, render_packet

MAX_ARTIFACT_CHARS = 2_000_000
MAX_VECTOR_BYTES = 16_384
MAX_DOCUMENT_CHARS = 1_000_000
MAX_TRUSTED_KEYS = 16
MAX_PAYLOAD_PREVIEW_BYTES = 16_384
MAX_PAGE = 200
HARNESS_TIMEOUT_SECONDS = 300
OUTPUT_TAIL_CHARS = 2000

SAMPLES = {
    "contradicted": ("case.json", "policy-june.json"),
    "not_established": ("case.json", "policy-april.json"),
    "supported": ("case-complete.json", "policy-complete.json"),
}


def _samples_dir() -> Path:
    return Path(str(resources.files("probity_verify") / "samples"))


def _corpora_dir() -> Path:
    return Path(str(resources.files("agent_evidence_vectors") / "corpora"))


def _error(message: str) -> dict[str, Any]:
    return {"ok": False, "error": message}


def _summarize(result: dict) -> dict[str, Any]:
    return {
        "ok": True,
        "decision": result["decision"],
        "reason": result["reason"],
        "claim_type": result["claim_type"],
        "case_id": result["case_id"],
        "policy_sha256": result["policy_sha256"],
        "checks": result["checks"],
        "scope": result["scope"],
        "packet": render_packet(result),
    }


def _safe_relative(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or not path.parts or "\x00" in name:
        raise CaseError(f"artifact path must be relative and stay inside the case: {name!r}")
    return path


def verify_claim(case: dict, policy: dict, artifacts: dict[str, str] | None = None) -> dict[str, Any]:
    """Decide one claim against evidence bytes the caller supplies, with probity-verify."""
    artifacts = artifacts or {}
    try:
        with tempfile.TemporaryDirectory(prefix="aemcp-") as tmp:
            root = Path(tmp)
            total = 0
            for name, text in artifacts.items():
                relative = _safe_relative(name)
                total += len(text)
                if total > MAX_ARTIFACT_CHARS:
                    return _error("artifacts exceed the size limit")
                target = root.joinpath(*relative.parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(text.encode("utf-8"))
            return _summarize(adjudicate(case, policy, root))
    except CaseError as exc:
        return _error(str(exc))


def verify_sample(scenario: str) -> dict[str, Any]:
    """Run a bundled sample claim: contradicted, not_established or supported."""
    if scenario not in SAMPLES:
        return _error(f"scenario must be one of {sorted(SAMPLES)}")
    case_name, policy_name = SAMPLES[scenario]
    directory = _samples_dir()
    case = json.loads((directory / case_name).read_text(encoding="utf-8"))
    policy = json.loads((directory / policy_name).read_text(encoding="utf-8"))
    try:
        return _summarize(adjudicate(case, policy, directory))
    except CaseError as exc:
        return _error(str(exc))


def _harness(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "agent_evidence_vectors.run_vectors", *args],
        capture_output=True, text=True, timeout=HARNESS_TIMEOUT_SECONDS, check=False,
    )


def _corpus_names() -> list[str]:
    done = _harness("--list-corpora")
    return [line.strip() for line in done.stdout.splitlines() if line.strip()]


def list_vector_corpora() -> dict[str, Any]:
    """Name every shipped corpus with its suite revision and vector counts where it declares them."""
    names = _corpus_names()
    rows = []
    for name in names:
        row: dict[str, Any] = {"corpus": name}
        manifest = _corpora_dir() / name / "MANIFEST.json"
        if manifest.is_file():
            data = json.loads(manifest.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                row["suite_revision"] = data.get("suiteRevision")
                vectors = data.get("vectors")
                if isinstance(vectors, list):
                    row["vectors"] = len(vectors)
        rows.append(row)
    return {"ok": True, "total": len(rows), "corpora": rows}


def run_vectors(corpus: str = "vectors", offset: int = 0, limit: int = 50) -> dict[str, Any]:
    """Replay one corpus with the bundled reference verifier; per-vector rows come back in pages."""
    if corpus not in _corpus_names():
        return _error(f"unknown corpus {corpus!r}; call list_vector_corpora")
    limit = max(1, min(limit, MAX_PAGE))
    offset = max(0, offset)
    with tempfile.TemporaryDirectory(prefix="aemcp-") as tmp:
        report_path = Path(tmp) / "report.json"
        done = _harness("--corpus", corpus, "--report", str(report_path))
        if not report_path.is_file():
            # Some corpora print a text verdict and write no report; some need an external verifier.
            return {
                "ok": done.returncode == 0,
                "corpus": corpus,
                "exit_code": done.returncode,
                "report": None,
                "output": done.stdout[-OUTPUT_TAIL_CHARS:],
                "error": done.stderr[-OUTPUT_TAIL_CHARS:] if done.returncode else None,
            }
        report = json.loads(report_path.read_text(encoding="utf-8"))
    rows = [
        {"id": v.get("id"), "kind": v.get("kind"), "status": v.get("status"),
         "expected": v.get("expected"), "observed_verdict": (v.get("observed") or {}).get("verdict")}
        for v in report.get("vectors", [])
    ]
    return {
        "ok": True,
        "corpus": corpus,
        "exit_code": done.returncode,
        "release": report.get("corpus", {}).get("release"),
        "corpus_digest": report.get("corpus", {}).get("corpusDigest"),
        "totals": report.get("totals"),
        "offset": offset,
        "page": rows[offset:offset + limit],
        "next_offset": offset + limit if offset + limit < len(rows) else None,
    }


def explain_vector(vector_id: str, corpus: str = "vectors") -> dict[str, Any]:
    """Return one vector: its manifest entry, the conditions it tests, and its input bytes."""
    if corpus not in _corpus_names():
        return _error(f"unknown corpus {corpus!r}; call list_vector_corpora")
    base = (_corpora_dir() / corpus).resolve()
    manifest_path = base / "MANIFEST.json"
    if not manifest_path.is_file():
        return _error(f"corpus {corpus!r} has no top-level MANIFEST.json to explain from")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    entries = manifest.get("vectors") if isinstance(manifest, dict) else None
    entry = next((e for e in entries or [] if isinstance(e, dict) and e.get("id") == vector_id), None)
    if entry is None:
        return _error(f"no vector {vector_id!r} in corpus {corpus!r}")
    result: dict[str, Any] = {"ok": True, "corpus": corpus, "entry": entry, "spec_path": manifest.get("specPath")}
    relative = entry.get("file")
    if isinstance(relative, str):
        path = (base / relative).resolve()
        if base in path.parents and path.is_file():
            raw = path.read_bytes()
            result["input_bytes"] = len(raw)
            result["input_truncated"] = len(raw) > MAX_VECTOR_BYTES
            result["input"] = raw[:MAX_VECTOR_BYTES].decode("utf-8", errors="replace")
    return result


def _vocabulary() -> dict[str, Any]:
    text = (resources.files("agent_evidence_vocabulary") / "vocabulary.yaml").read_text(encoding="utf-8")
    return yaml.safe_load(text)


def lookup_term(term: str) -> dict[str, Any]:
    """Look a term up in the released vocabulary by exact key; otherwise suggest close keys."""
    vocab = _vocabulary()
    meta = vocab.get("meta", {})
    found = []
    for section, body in vocab.items():
        if section == "meta" or not isinstance(body, dict):
            continue
        entry = body.get(term)
        if isinstance(entry, dict) and "definition" in entry:
            found.append({
                "term": term, "section": section, "status": entry.get("status"),
                "values": entry.get("values"), "definition": " ".join(str(entry["definition"]).split()),
                "source_path": entry.get("source_path"),
            })
    if found:
        return {"ok": True, "vocabulary_version": meta.get("version"), "spec_anchor": meta.get("spec_anchor"),
                "spec_anchor_repo": meta.get("spec_anchor_repo"), "matches": found}
    needle = term.lower()
    close = sorted(
        key for body in vocab.values() if isinstance(body, dict)
        for key, value in body.items() if isinstance(value, dict) and "definition" in value
        and (needle in key.lower() or key.lower() in needle)
    )
    return {"ok": False, "error": f"no term {term!r}", "close_terms": close[:20]}


def check_artifact_digest(document: str, artifact_text: str | None = None,
                          artifact_base64: str | None = None) -> dict[str, Any]:
    """Check that an artifact has a digest a TEA, CycloneDX or in-toto document names."""
    if (artifact_text is None) == (artifact_base64 is None):
        return _error("pass exactly one of artifact_text and artifact_base64")
    try:
        raw = artifact_text.encode("utf-8") if artifact_text is not None else base64.b64decode(
            artifact_base64 or "", validate=True)
    except (binascii.Error, ValueError) as exc:
        return _error(f"artifact_base64 is not valid base64: {exc}")
    if len(raw) > MAX_ARTIFACT_CHARS:
        return _error("artifact exceeds the size limit")
    try:
        result = check(parse_document(document.encode("utf-8")), raw)
    except ValueError as exc:
        return _error(f"document could not be read: {exc}")
    return {
        "ok": True,
        "admitted": result.ok,
        "reason": result.reason or "digest-matched",
        "matched": {"algorithm": result.matched[0], "digest": result.matched[1]} if result.matched else None,
        "declared": [{"algorithm": a, "digest": d} for a, d in result.declared],
    }


def canonicalize_json(document: str, profile: str = "rfc8785") -> dict[str, Any]:
    """Admit one JSON document and return its RFC 8785 canonical bytes, with the jcs-admit crate."""
    if profile not in ("rfc8785", "ijson"):
        return _error("profile must be 'rfc8785' or 'ijson'")
    if len(document) > MAX_DOCUMENT_CHARS:
        return _error("document exceeds the size limit")
    admit = jcs_admit.admit if profile == "rfc8785" else jcs_admit.admit_ijson
    try:
        canonical = admit(document.encode("utf-8"))
    except jcs_admit.JcsError as exc:
        return {"ok": False, "error": exc.variant, "fields": exc.fields, "profile": profile}
    return {
        "ok": True,
        "profile": profile,
        "canonical": canonical.decode("utf-8"),
        "canonical_hex": canonical.hex(),
        "sha256": hashlib.sha256(canonical).hexdigest(),
        "bytes": len(canonical),
    }


def _verifiers(trusted_keys: list[dict[str, str]]) -> list[Any]:
    if not trusted_keys or len(trusted_keys) > MAX_TRUSTED_KEYS:
        raise ValueError(f"trusted_keys must hold between 1 and {MAX_TRUSTED_KEYS} keys")
    verifiers = []
    for entry in trusted_keys:
        raw = bytes.fromhex(entry["public_key_hex"])
        verifiers.append(dsse.Ed25519Verifier(raw, key_id=entry.get("key_id")))
    return verifiers


def verify_dsse(envelope: str, trusted_keys: list[dict[str, str]], threshold: int = 1) -> dict[str, Any]:
    """Verify a DSSE envelope against Ed25519 keys the caller trusts, with the dsse crate."""
    try:
        keys = _verifiers(trusted_keys)
    except (ValueError, KeyError, TypeError) as exc:
        return _error(f"trusted_keys invalid: {exc}")
    try:
        verified = dsse.verify_threshold(envelope.encode("utf-8"), keys, threshold)
    except dsse.DsseError as exc:
        return {"ok": False, "verified": False, "error": exc.variant, "fields": exc.fields}
    payload = bytes(verified.payload)
    return {
        "ok": True,
        "verified": True,
        "payload_type": verified.payload_type,
        "accepted_keys": list(verified.accepted_keys),
        "payload_bytes": len(payload),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "payload_truncated": len(payload) > MAX_PAYLOAD_PREVIEW_BYTES,
        "payload_base64": base64.b64encode(payload[:MAX_PAYLOAD_PREVIEW_BYTES]).decode("ascii"),
    }
