"""evidence_digest/v1 and event_log_completeness/v1: the four consumed-copy breaks and the six log edits.

Records are built here from neutral, deterministic keys and judged through the kernel, as a consumer
calls it. The four digest breaks are the shapes a hash-recomputing check passes: an inline copy edited
while the hashed copy is not, every reference removed, a body with a repeated member, and a manifest
signed by a key it carries for itself. The six log edits are drop, swap, status flip, link rewrite,
body edit and tail truncation; each must fail with its own named reason.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from agent_evidence_verify import adjudicate
from agent_evidence_verify.adapters import telemetry_evidence as te
from agent_evidence_verify.adapters.jcs_canonical import canonical
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def _key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"telemetry-evidence-test/" + label.encode()).digest())


def _pub(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


WITNESS, FORGER = _key("witness"), _key("forger")
PIN = {"kind": "pin", "keys": [{"public_key_sha256": hashlib.sha256(_pub(WITNESS)).hexdigest()}]}
BODIES = {f"e{i:03d}": {"route": "A" if i % 2 else "B", "status": "ok", "step": i} for i in range(1, 6)}


def _bind(name: str, blob: bytes) -> dict:
    return {"path": name, "length": len(blob), "sha256": hashlib.sha256(blob).hexdigest()}


def _run(tmp_path: Path, files: dict[str, bytes], assessment: dict) -> dict:
    for name, blob in files.items():
        (tmp_path / name).write_bytes(blob)
    case = {"schema_version": "probity-case/v1", "case_id": "c",
            "artifacts": {name: _bind(name, blob) for name, blob in files.items()}}
    policy = {"schema_version": "probity-policy/v1", "assessments": {"c": assessment}}
    return adjudicate(case, policy, tmp_path)


def _ref(item: str, body: bytes, form: str = "rfc8785", alg: str = "sha-256") -> dict:
    data = canonical("rfc8785", body.decode()) if form == "rfc8785" else body
    return {"id": item, "hash_alg": alg, "canonicalization": form,
            "digest": te.HASHES[alg](data).hexdigest()}


def _manifest(refs: list[dict], signer: Ed25519PrivateKey | None = None) -> bytes:
    body: dict[str, Any] = {"schema_version": te.MANIFEST_SCHEMA, "refs": refs}
    if signer is not None:
        message = te.MANIFEST_SCHEMA.encode() + b"\x00" + canonical("rfc8785", json.dumps(body)).rstrip(b"\n")
        body["signature"] = {"alg": "Ed25519", "public_key": _b64u(_pub(signer)),
                             "value": _b64u(signer.sign(message))}
    return json.dumps(body).encode()


def _digest_case(tmp_path: Path, consumed: dict[str, bytes], manifest: bytes, **extra: Any) -> dict:
    files = {"manifest.json": manifest, **{f"{k}.json": v for k, v in consumed.items()}}
    assessment = {"claim_type": "evidence_digest/v1", "manifest": "manifest.json",
                  "consumed": {k: f"{k}.json" for k in consumed}, **extra}
    return _run(tmp_path, files, assessment)


def _clean() -> tuple[dict[str, bytes], list[dict]]:
    consumed = {k: json.dumps(v).encode() for k, v in BODIES.items()}
    return consumed, [_ref(k, v) for k, v in consumed.items()]


def _verdict(result: dict) -> tuple[str, str]:
    return result["decision"], result["reason"]


def test_clean_unsigned_manifest_binds_every_consumed_copy(tmp_path: Path) -> None:
    consumed, refs = _clean()
    result = _digest_case(tmp_path, consumed, _manifest(refs))
    assert _verdict(result) == ("supported", "digests_bind_consumed_copy")
    assert result["scope"]["items"] == 5


def test_break_inline_copy_edited_is_refused(tmp_path: Path) -> None:
    consumed, refs = _clean()
    consumed["e004"] = consumed["e004"].replace(b'"B"', b'"A"')
    assert _verdict(_digest_case(tmp_path, consumed, _manifest(refs))) == ("contradicted", "consumed_copy_bound")


def test_break_every_reference_removed_is_refused_with_a_denominator(tmp_path: Path) -> None:
    consumed, _ = _clean()
    result = _digest_case(tmp_path, consumed, _manifest([]))
    assert _verdict(result) == ("contradicted", "coverage")
    assert "0 of 5" in result["checks"][-1]["detail"]


def test_break_repeated_member_in_the_consumed_copy_is_refused(tmp_path: Path) -> None:
    consumed, refs = _clean()
    consumed["e004"] = b'{"route":"A","route":"B","status":"ok","step":4}'
    assert _verdict(_digest_case(tmp_path, consumed, _manifest(refs))) == ("contradicted", "no_duplicate_member")


def test_repeated_member_in_the_manifest_is_refused(tmp_path: Path) -> None:
    consumed, refs = _clean()
    raw = _manifest(refs).replace(b'{"schema_version"', b'{"refs": [], "schema_version"', 1)
    assert _verdict(_digest_case(tmp_path, consumed, raw)) == ("contradicted", "no_duplicate_member")


def test_break_self_carried_key_is_refused_and_the_pinned_key_control_agrees(tmp_path: Path) -> None:
    consumed, refs = _clean()
    (tmp_path / "f").mkdir()
    forged = _digest_case(tmp_path / "f", consumed, _manifest(refs, FORGER), authority=PIN)
    assert _verdict(forged) == ("contradicted", "signer_pinned")
    assert [c["reason"] for c in forged["checks"] if c["id"] == "key_authority"] == ["key_not_pinned"]
    (tmp_path / "p").mkdir()
    control = _digest_case(tmp_path / "p", consumed, _manifest(refs, WITNESS), authority=PIN,
                           require_signature=True)
    assert _verdict(control) == ("supported", "digests_bind_consumed_copy")


def test_signed_manifest_with_no_authority_is_not_established(tmp_path: Path) -> None:
    consumed, refs = _clean()
    result = _digest_case(tmp_path, consumed, _manifest(refs, WITNESS))
    assert _verdict(result) == ("not_established", "signer_not_established")


def test_required_signature_absent_is_not_established(tmp_path: Path) -> None:
    consumed, refs = _clean()
    assert _verdict(_digest_case(tmp_path, consumed, _manifest(refs), require_signature=True)) == \
        ("not_established", "unsigned_manifest")


def test_flipped_manifest_signature_is_refused(tmp_path: Path) -> None:
    consumed, refs = _clean()
    raw = json.loads(_manifest(refs, WITNESS))
    raw["refs"][0]["digest"] = "0" * 64
    result = _digest_case(tmp_path, consumed, json.dumps(raw).encode(), authority=PIN)
    assert _verdict(result) == ("contradicted", "signature")


def test_empty_denominator_is_never_a_pass(tmp_path: Path) -> None:
    assert _verdict(_digest_case(tmp_path, {}, _manifest([]))) == ("not_established", "empty_denominator")


def test_undeclared_canonical_form_is_not_established(tmp_path: Path) -> None:
    consumed, refs = _clean()
    del refs[2]["canonicalization"]
    assert _verdict(_digest_case(tmp_path, consumed, _manifest(refs))) == \
        ("not_established", "undeclared_canonical_form")


def test_duplicate_reference_is_refused(tmp_path: Path) -> None:
    consumed, refs = _clean()
    assert _verdict(_digest_case(tmp_path, consumed, _manifest(refs + refs[:1]))) == \
        ("contradicted", "no_duplicate_reference")


def test_python_default_separators_do_not_bind_rfc8785(tmp_path: Path) -> None:
    consumed, refs = _clean()
    refs[0]["digest"] = hashlib.sha256(json.dumps(BODIES["e001"], sort_keys=True).encode()).hexdigest()
    assert _verdict(_digest_case(tmp_path, consumed, _manifest(refs))) == ("contradicted", "consumed_copy_bound")


@pytest.mark.parametrize("alg", ["sha-256", "sha-384", "sha-512"])
def test_raw_form_hashes_the_bytes(tmp_path: Path, alg: str) -> None:
    consumed = {"blob": b"\x00\xffnot json"}
    result = _digest_case(tmp_path, consumed, _manifest([_ref("blob", consumed["blob"], "raw", alg)]))
    assert _verdict(result) == ("supported", "digests_bind_consumed_copy")


def test_cbor_deterministic_form(tmp_path: Path) -> None:
    good = te.cbor_encode({"b": 2, "a": [1, b"\x01", "x", None, True]})
    (tmp_path / "g").mkdir()
    ok = _digest_case(tmp_path / "g", {"r": good}, _manifest([_ref("r", good, "cbor-deterministic")]))
    assert _verdict(ok) == ("supported", "digests_bind_consumed_copy")
    loose = b"\xa1\x61a\x18\x01"  # the integer 1 in a two-byte argument: not the deterministic encoding
    (tmp_path / "l").mkdir()
    bad = _digest_case(tmp_path / "l", {"r": loose}, _manifest([_ref("r", loose, "cbor-deterministic")]))
    assert _verdict(bad) == ("contradicted", "canonical_form")
    repeated = b"\xa2\x61a\x01\x61a\x02"
    (tmp_path / "d").mkdir()
    dup = _digest_case(tmp_path / "d", {"r": repeated}, _manifest([_ref("r", repeated, "cbor-deterministic")]))
    assert _verdict(dup) == ("contradicted", "no_duplicate_member")


def test_unavailable_consumed_copy_is_not_established(tmp_path: Path) -> None:
    consumed, refs = _clean()
    files = {"manifest.json": _manifest(refs), **{f"{k}.json": v for k, v in consumed.items()}}
    for name, blob in files.items():
        (tmp_path / name).write_bytes(blob)
    (tmp_path / "e003.json").unlink()
    case = {"schema_version": "probity-case/v1", "case_id": "c",
            "artifacts": {name: _bind(name, blob) for name, blob in files.items()}}
    policy = {"schema_version": "probity-policy/v1", "assessments": {"c": {
        "claim_type": "evidence_digest/v1", "manifest": "manifest.json",
        "consumed": {k: f"{k}.json" for k in consumed}}}}
    assert _verdict(adjudicate(case, policy, tmp_path)) == ("not_established", "consumed_copy_unavailable")


# --- event_log_completeness/v1: the six edits --------------------------------------------------------

FIRST = hashlib.sha256(b"telemetry-evidence-test/genesis").hexdigest()


def _log(count: int = 6, session: str = "s1") -> list[dict]:
    events, prev = [], FIRST
    for seq in range(1, count + 1):
        event = {"seq": seq, "prev": prev, "session": session, "name": f"step-{seq}", "status": "ok"}
        events.append(event)
        prev = te.event_digest(event)
    return events


def _relink(events: list[dict]) -> list[dict]:
    prev = FIRST
    for event in events:
        event["prev"] = prev
        prev = te.event_digest(event)
    return events


def _head(events: list[dict], key: Ed25519PrivateKey = WITNESS) -> bytes:
    payload = {"format": te.HEAD_FORMAT, "count": len(events), "head": te.event_digest(events[-1])}
    message = te.HEAD_FORMAT.encode() + b"\x00" + canonical("rfc8785", json.dumps(payload))
    return json.dumps({**payload, "keyid": _pub(key).hex(),
                       "signature": base64.b64encode(key.sign(message)).decode()}).encode()


def _log_case(tmp_path: Path, events: list[dict], head: bytes | None, **extra: Any) -> dict:
    files = {"events.jsonl": "".join(json.dumps(e) + "\n" for e in events).encode()}
    assessment = {"claim_type": "event_log_completeness/v1", "records": "events.jsonl",
                  "first_prev": FIRST, "coverage": {"session": "s1", "first_seq": 1}, "authority": PIN, **extra}
    if head is not None:
        files["head.json"] = head
        assessment["head"] = "head.json"
    return _run(tmp_path, files, assessment)


def test_clean_log_with_retained_head_is_supported(tmp_path: Path) -> None:
    events = _log()
    assert _verdict(_log_case(tmp_path, events, _head(events))) == ("supported", "event_log_complete")


def _edited(name: str) -> tuple[list[dict], bytes]:
    clean = _log()
    head = _head(clean)
    events = [dict(e) for e in clean]
    if name == "drop":
        del events[2]
    elif name == "swap":
        events[2], events[3] = events[3], events[2]
    elif name == "status_flip":
        events[2]["status"] = "error"
    elif name == "link_rewrite":
        events[3]["prev"] = te.event_digest(events[1])
    elif name == "body_edit":
        events[4]["name"] = "step-x"
    elif name == "tail_truncation":
        events = events[:-1]
    return events, head


SIX_EDITS = {"drop": "sequence", "swap": "sequence", "status_flip": "chain_order",
             "link_rewrite": "chain_order", "body_edit": "chain_order", "tail_truncation": "head_anchor"}


@pytest.mark.parametrize("edit", sorted(SIX_EDITS))
def test_each_of_the_six_edits_fails_with_its_reason(tmp_path: Path, edit: str) -> None:
    events, head = _edited(edit)
    assert _verdict(_log_case(tmp_path, events, head)) == ("contradicted", SIX_EDITS[edit])


def test_six_edit_harness_counts_six_of_six(tmp_path: Path) -> None:
    caught = 0
    for i, edit in enumerate(sorted(SIX_EDITS)):
        (tmp_path / str(i)).mkdir()
        events, head = _edited(edit)
        caught += _log_case(tmp_path / str(i), events, head)["decision"] == "contradicted"
    assert caught == 6


def test_relinked_rewrite_is_caught_by_the_retained_head(tmp_path: Path) -> None:
    events, head = _edited("body_edit")
    assert _verdict(_log_case(tmp_path, _relink(events), head)) == ("contradicted", "head_anchor")


def test_rewritten_log_resigned_by_another_key_is_refused(tmp_path: Path) -> None:
    events = _relink(_edited("body_edit")[0])
    assert _verdict(_log_case(tmp_path, events, _head(events, FORGER))) == ("contradicted", "signer_pinned")


def test_no_head_is_not_established(tmp_path: Path) -> None:
    assert _verdict(_log_case(tmp_path, _log(), None)) == ("not_established", "head_not_anchored")


def test_empty_log_is_not_established(tmp_path: Path) -> None:
    files = {"events.jsonl": b"\n"}
    result = _run(tmp_path, files, {"claim_type": "event_log_completeness/v1", "records": "events.jsonl",
                                    "first_prev": FIRST, "coverage": {"first_seq": 1}})
    assert _verdict(result) == ("not_established", "empty_denominator")


def test_event_outside_the_coverage_boundary_is_refused(tmp_path: Path) -> None:
    events = _log()
    events[5]["session"] = "s2"
    events = _relink(events)
    assert _verdict(_log_case(tmp_path, events, _head(events))) == ("contradicted", "coverage_boundary")


def test_repeated_member_in_an_event_is_refused(tmp_path: Path) -> None:
    events = _log()
    files = {"events.jsonl": "".join(json.dumps(e) + "\n" for e in events).encode()
             .replace(b'"status": "ok"}', b'"status": "ok", "status": "error"}', 1)}
    result = _run(tmp_path, files, {"claim_type": "event_log_completeness/v1", "records": "events.jsonl",
                                    "first_prev": FIRST, "coverage": {"first_seq": 1}})
    assert _verdict(result) == ("contradicted", "no_duplicate_member")


def test_repeated_event_is_refused(tmp_path: Path) -> None:
    events = _log()
    assert _verdict(_log_case(tmp_path, events + events[-1:], _head(events))) == \
        ("contradicted", "no_duplicate_event")


def test_check_order_matches_the_receipt_chain() -> None:
    """The shared prefix of check ids appears in the receipt chain's order."""
    order = ["record_shape", "signature", "key_authority", "signer_pinned", "no_duplicate_event",
             "sequence", "chain_order", "head_anchor"]
    checks: list[dict] = []
    events = _log()
    te.check_log("".join(json.dumps(e) + "\n" for e in events).encode(), _head(events), FIRST,
                 {"session": "s1", "first_seq": 1}, PIN, checks)
    assert [c["id"] for c in checks] == order
