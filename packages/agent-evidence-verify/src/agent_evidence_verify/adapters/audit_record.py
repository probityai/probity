"""``agent_audit_record/v1``: does this signed agent audit record conform, by the published rules?

An agent audit record (draft-gilda-audit-agent-audit-record) is one in-toto Statement in a DSSE
envelope signed by the observer. A retaining party may keep it beside a retention entry whose
anchors date it, and several records may be judged together as a set under one consumption ledger.
The claim: the bound record, read under the consumer's trust document (the observer key, the
predicate type it accepts, and the tree heads and block headers it already holds), reaches the
verdict the reader computes, with its first refusal code, its recomputed tier, its consumption
limit and, for a retained record, the dating check of Section 4.7.1.

The rules are ``_audit_record_reader``, a port of the reference reader of
``corpora/vectors-agent-audit-record`` in probityai/agent-evidence-vectors. Every comparison that
dates a record keeps its own bound: the future side takes the 300 second skew tolerance only, the
past side the entry's ``maxAge``, the late anchor bound ``anchorWithin`` plus the tolerance, and an
OpenTimestamps time the 7200 second allowance on both the ``receivedAt`` and the late bound. Every
integer is read inside the I-JSON range before any arithmetic, so 2^53 and above is refused.

The assessment names the ``shape`` the consumer holds (``envelope``, ``retained`` or ``set``), and
the record never chooses it: a reader that took the shape off the bytes would let a presenter strip
a retention entry whose dating fails and be judged as a bare envelope that passes. The trust
document is any JSON object carrying ``keys.observer.publicKey``, ``predicateType`` and, for a
retained record, ``anchorTrust``; the corpus MANIFEST.json is one. Nothing the record carries
chooses its own key, its own trusted heads or the rules it is judged under.

Decisions: a record the reader finds valid, with a well-formed retention entry where it has one and
a valid joint result where it is a set, is ``supported`` / ``record_conforms``; anything else is
``contradicted`` with the first refusal code as the reason. The check carries every field a
corpus member declares, so a caller can compare it member for member.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..common import CaseError
from . import _audit_record_reader as reader
from .bound_records import assessment_for, bound, decision

CLAIM_TYPE = "agent_audit_record/v1"
LIMIT = ("Checks the record's signature under the pinned observer key, its JSON profile, members "
         "and recomputes, and, for a retained record, its dating against the tree heads and block "
         "headers the trust document pins. It does not establish that the decision was right, that "
         "the observer saw every write, or that a dated anchor was obtained when it says.")


def _trust(raw: bytes | None) -> tuple[dict[str, Any], reader.AnchorTrust]:
    """The consumer's trust document and the tree heads and block headers it pins. A
    document the reader cannot read is the consumer's error, refused before any record."""
    if raw is None:
        raise CaseError("assessment.trust: the trust document is not available")
    try:
        trust = json.loads(raw)
    except (UnicodeDecodeError, ValueError, RecursionError) as error:
        raise CaseError(f"assessment.trust: not JSON: {error}") from error
    if not isinstance(trust, dict):
        raise CaseError("assessment.trust: expected a JSON object")
    keys = trust.get("keys")
    observer = keys.get("observer") if isinstance(keys, dict) else None
    if not isinstance(observer, dict) or not isinstance(observer.get("publicKey"), str):
        raise CaseError("assessment.trust: keys.observer.publicKey: expected a string")
    if not isinstance(trust.get("predicateType", ""), str):
        raise CaseError("assessment.trust: predicateType: expected a string")
    try:
        heads = reader.tree_heads(trust)
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError) as error:
        raise CaseError(f"assessment.trust: anchorTrust unreadable: {error!r}") from error
    return trust, heads


SHAPES = ("envelope", "retained", "set")


def _within_limit(envelope: bytes) -> bool | None:
    try:
        predicate = json.loads(reader._envelope_payload(envelope)[1])["predicate"]
        return reader.within_limit(predicate)
    except (reader.Malformed, KeyError, TypeError, ValueError, RecursionError):
        return None


def _retained_envelope(raw: bytes) -> bytes:
    """The envelope a retained record carries, re-serialized; empty when it cannot be read."""
    try:
        return json.dumps(json.loads(raw)["envelope"]).encode()
    except (UnicodeDecodeError, ValueError, KeyError, TypeError, RecursionError):
        return b""


def _record(report: reader.Report, envelope: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {"verdict": report.verdict, "codes": list(report.codes)}
    if report.verdict == "valid":
        out["derivedTier"] = report.derived_tier
    limit = _within_limit(envelope)
    if limit is not None:
        out["withinLimit"] = limit
    return out


def judge(raw: bytes, trust: dict[str, Any], heads: reader.AnchorTrust, shape: str,
          predicate_type: str | None = None) -> dict[str, Any]:
    """The reader's result for one record, retained record or set, as one check. ``shape`` is
    what the consumer says it holds; a retained record or set whose bytes cannot be read is
    then refused as that shape, never re-read as a bare envelope."""
    if shape not in SHAPES:
        raise CaseError(f"assessment.shape: expected one of {', '.join(SHAPES)}")
    configured = {"predicateType": predicate_type} if predicate_type else None
    policy = reader.policy_for(trust, configured)
    check: dict[str, Any] = {"id": "agent_audit_record_rules", "shape": shape}
    if shape == "retained":
        report, dated = reader.verify_retained(raw, policy, heads)
        check.update(_record(report, _retained_envelope(raw)))
        check["dating"] = reader.dating_dict(dated)
        ok = report.verdict == "valid" and dated.entry == "well-formed"
        first = report.codes[:1] or dated.codes[:1]
    elif shape == "set":
        reports, joint = reader.verify_set(raw, policy)
        try:
            envelopes = reader.set_records(raw)
        except (reader.Malformed, ValueError, KeyError, TypeError):
            envelopes = []
        check["records"] = [_record(r, e) for r, e in zip(reports, envelopes, strict=True)]
        check["set"] = {"verdict": joint.verdict, "codes": list(joint.codes),
                        "missing": joint.missing}
        check["verdict"], check["codes"] = joint.verdict, list(joint.codes)
        ok = joint.verdict == "valid"
        first = list(joint.codes[:1])
    else:
        report = reader.verify(raw, policy)
        check.update(_record(report, raw))
        ok = report.verdict == "valid"
        first = list(report.codes[:1])
    check["status"] = "pass" if ok else "fail"
    check["first_code"] = first[0] if first else ("" if ok else check.get("verdict", "refused"))
    return check


def adjudicate(case: Any, policy: Any, artifact_root: Path) -> dict:
    """Judge one bound agent audit record under the consumer's pinned trust document."""
    case_id, artifacts, assessment = assessment_for(
        case, policy, CLAIM_TYPE, {"record", "trust", "shape"}, {"predicate_type"})
    raw, binding = bound(artifacts, artifact_root, assessment["record"], "assessment.record")
    trust_raw, trust_binding = bound(artifacts, artifact_root, assessment["trust"],
                                     "assessment.trust")
    predicate_type = assessment.get("predicate_type")
    if predicate_type is not None and not isinstance(predicate_type, str):
        raise CaseError("assessment.predicate_type: expected a string")
    shape = assessment["shape"]
    if shape not in SHAPES:
        raise CaseError(f"assessment.shape: expected one of {', '.join(SHAPES)}")
    scope = {"record": binding, "trust": trust_binding, "limit": LIMIT}
    if raw is None:
        return decision(case_id, CLAIM_TYPE, scope, "not_established", "record_unavailable")
    trust, heads = _trust(trust_raw)
    scope["predicate_type"] = predicate_type or trust.get("predicateType", "")
    scope["shape"] = shape
    check = judge(raw, trust, heads, shape, predicate_type)
    if check["status"] == "pass":
        return decision(case_id, CLAIM_TYPE, scope, "supported", "record_conforms", [check])
    return decision(case_id, CLAIM_TYPE, scope, "contradicted", check["first_code"], [check])
