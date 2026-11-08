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

from . import grants

GRANT_ALLOW = "grant"


@dataclass(frozen=True)
class Trust:
    """What an auditor pins before verifying: nothing here is read from the records themselves."""

    grant_root_key_ids: frozenset[str] = frozenset()
    revoked_grants: frozenset[str] = frozenset()
    key_revoked: Callable[[str, str], bool] | None = None
    extra: Mapping[str, Any] = field(default_factory=dict)


def _args(evidence: Mapping[str, Any], pred: Mapping[str, Any], problems: list[str], where: str) -> Any:
    raw = base64.b64decode(evidence.get("argsB64", ""))
    if hashlib.sha256(raw).hexdigest() != pred.get("argsSha256"):
        problems.append(f"{where}:authority_args_are_not_the_call_arguments")
    import json  # noqa: PLC0415

    return json.loads(raw) if raw else None


def _check_grant(pred: Mapping[str, Any], evidence: Mapping[str, Any], trust: Trust, at: str,
                 problems: list[str], where: str) -> None:
    args = _args(evidence, pred, problems, where)
    verdict = grants.authorize(list(evidence.get("chain", [])), str(pred.get("tool")), args, at,
                               set(trust.grant_root_key_ids), set(trust.revoked_grants), trust.key_revoked)
    if verdict["decision"] != "allow":
        problems.append(f"{where}:grant_{verdict['decision']}:{verdict['reason']}")
    if verdict["grantDigest"] and verdict["grantDigest"] != pred.get("grantDigest"):
        problems.append(f"{where}:grant_digest_differs_from_record")


CHECKS: dict[str, Callable[..., None]] = {GRANT_ALLOW: _check_grant}


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
