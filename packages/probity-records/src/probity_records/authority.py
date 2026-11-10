"""Offline re-check of the authority a tool-call ``authorize`` record rests on.

An ``authorize`` record whose ``reason`` is one of the authority reasons below carries an
``authority`` object, and the verifier re-runs the matching check from the record alone plus the
trust the auditor pins (``Trust``): grant issuers, approver keys and quorum policies, revocations.
"""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from . import governance, grants, quorum
from .revocation import RevocationState

GRANT_ALLOW = "grant"
QUORUM_ALLOW = "quorum"


@dataclass(frozen=True)
class Trust:
    """What an auditor pins before verifying: nothing here is read from the records themselves."""

    grant_root_key_ids: frozenset[str] = frozenset()
    quorum_policies: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    revocations: RevocationState | None = None
    #: issuer URL -> the RFC 7638 thumbprints the auditor pins for that issuer's signing keys
    identity_issuers: Mapping[str, frozenset[str]] = field(default_factory=dict)
    #: "basic" accepts a principals block without an act chain (graded); "strict" refuses it
    identity_profile: str = "basic"
    #: Signing key id -> the custody backend its checkpoint must name ("aws-kms", "vault-transit", ...).
    key_custody: Mapping[str, str] = field(default_factory=dict)
    #: A c2sp.org/tlog-policy (text): when set, a journal verifies only with a checkpoint its quorum
    #: of witnesses (keys the customer holds) cosigned.
    witness_policy: str | None = None

    def key_revoked(self, kid: str, at: str) -> bool:
        return self.revocations is not None and self.revocations.key_revoked(kid, at)

    def permit_revoked(self, pid: str, at: str) -> bool:
        return self.revocations is not None and self.revocations.permit_revoked(pid, at)

    def revoked_grants(self) -> frozenset[str]:
        return self.revocations.revoked_grants() if self.revocations else frozenset()


def _args(evidence: Mapping[str, Any], pred: Mapping[str, Any], problems: list[str], where: str) -> Any:
    raw = base64.b64decode(evidence.get("argsB64", ""))
    if hashlib.sha256(raw).hexdigest() != pred.get("argsSha256"):
        problems.append(f"{where}:authority_args_are_not_the_call_arguments")
    import json  # noqa: PLC0415

    return json.loads(raw) if raw else None


def _check_grant(pred: Mapping[str, Any], evidence: Mapping[str, Any], trust: Trust, at: str,
                 problems: list[str], where: str) -> None:
    args = _args(evidence, pred, problems, where)
    verdict = grants.verify_grant_allow(list(evidence.get("chain", [])), str(pred.get("tool")), args, at,
                               set(trust.grant_root_key_ids), set(trust.revoked_grants()), trust.key_revoked,
                               evidence.get("ctx") or {})
    if verdict["decision"] == "needs_approval" and isinstance(evidence.get("quorum"), Mapping):
        leaf = evidence["chain"][-1]["body"]
        carried = leaf["tools"][str(pred.get("tool"))].get("quorum")
        outcome = _quorum_outcome(pred, evidence["quorum"], trust, at, carried)
        if outcome != "ok":
            problems.append(f"{where}:grant_approval_{outcome}")
    elif verdict["decision"] != "allow":
        problems.append(f"{where}:grant_{verdict['decision']}:{verdict['reason']}")
    if verdict["grantDigest"] and verdict["grantDigest"] != pred.get("grantDigest"):
        problems.append(f"{where}:grant_digest_differs_from_record")


def _quorum_outcome(pred: Mapping[str, Any], evidence: Mapping[str, Any], trust: Trust, at: str,
                    carried: Mapping[str, Any] | None = None) -> str:
    """A grant that carries its own approval policy is trusted through the verified chain (rooted in
    a pinned issuer); otherwise the policy must be the one the auditor pinned under its id."""
    request = quorum.request_hash(str(pred.get("tool")), str(pred.get("argsSha256")), str(pred.get("permitId")),
                                  proposer=evidence.get("proposer"), history=evidence.get("historyDigest"))
    pinned = dict(trust.quorum_policies)
    if carried is not None:
        pinned[str(carried.get("policyId"))] = carried
    return quorum.verify_evidence(evidence, pinned, request, at, trust.key_revoked)


def _check_quorum(pred: Mapping[str, Any], evidence: Mapping[str, Any], trust: Trust, at: str,
                  problems: list[str], where: str) -> None:
    outcome = _quorum_outcome(pred, evidence, trust, at)
    if outcome != "ok":
        problems.append(f"{where}:{outcome}")


def _check_exception(pred: Mapping[str, Any], evidence: Mapping[str, Any], trust: Trust, at: str,
                     problems: list[str], where: str) -> None:
    for problem in governance.verify_exception_evidence(pred, evidence, trust.quorum_policies, at, trust.key_revoked):
        problems.append(f"{where}:{problem}")


CHECKS: dict[str, Callable[..., None]] = {GRANT_ALLOW: _check_grant, QUORUM_ALLOW: _check_quorum,
                                          governance.EXCEPTION_ALLOW: _check_exception}


def check_authority(pred: Mapping[str, Any], trust: Trust | None, problems: list[str], where: str) -> bool:
    """Run the authority check an allow record names. Returns True when the reason was handled."""
    reason = pred.get("reason")
    if reason not in CHECKS:
        return False
    evidence = pred.get("authority")
    if not isinstance(evidence, Mapping) or evidence.get("kind") != reason:
        problems.append(f"{where}:{reason}_allow_without_authority_evidence")
        return True
    if trust is None:
        problems.append(f"{where}:{reason}_allow_but_no_trust_pinned")
        return True
    CHECKS[reason](pred, evidence, trust, str(pred.get("at")), problems, where)
    return True
