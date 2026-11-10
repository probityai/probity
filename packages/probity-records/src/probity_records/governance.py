"""Governance workflow as signed records: intake, risk routing, approvals, attestations, sign-off and
exceptions with an owner, a rationale and an expiry bound to the permit.

An exception lets calls outside standing policy run for a bounded time. Its body names the owner,
the rationale, the scope (a tool and closed-world argument constraints, as in a grant), the window
and the quorum policy that must approve it. The approving votes sign the exception digest; the
permit and the tool-call record carry the exception digest, so an outsider re-checks scope, window
and quorum offline, and a call after expiry fails.

Each workflow step is a journal statement of type ``GOVERNANCE_STEP`` with a kind from ``STEPS``.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Mapping
from typing import Any

from . import constraints, quorum
from .core import canonical, sha256_hex
from .grants import ts

GOVERNANCE_EXCEPTION = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/governance-exception"
GOVERNANCE_STEP = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/governance-step"
EXCEPTION_ALLOW = "exception"
STEPS = ("intake", "risk_route", "approval", "attestation", "signoff", "exception")
STEP_FIELDS = ("actor", "kind", "subjectDigest")


def exception_body(*, exception_id: str, owner: str, rationale: str, tool: str, args: Mapping[str, Any],
                   not_before: str, expires_at: str, policy_id: str, requested_by: str) -> dict[str, Any]:
    if not owner or not rationale.strip():
        raise ValueError("exception_needs_owner_and_rationale")
    if ts(expires_at) <= ts(not_before):
        raise ValueError("exception_window_empty")
    for c in args.values():
        constraints.validate(c)
    return {"exceptionId": exception_id, "expiresAt": expires_at, "notBefore": not_before, "owner": owner,
            "policyId": policy_id, "rationale": rationale, "requestedBy": requested_by,
            "scope": {"args": dict(args), "tool": tool}}


def exception_digest(body: Mapping[str, Any]) -> str:
    return sha256_hex(canonical(dict(body)))


def exception_evidence(body: Mapping[str, Any], votes: quorum.QuorumResult, policy: Mapping[str, Any],
                       args: Any) -> dict[str, Any]:
    """What the permit names (``exceptionDigest``) and the tool-call record carries."""
    return {"argsB64": base64.b64encode(canonical(args)).decode("ascii"), "exception": dict(body),
            "exceptionDigest": exception_digest(body), "kind": EXCEPTION_ALLOW,
            "quorum": votes.evidence(policy, exception_digest(body))}


def check_exception_call(body: Mapping[str, Any], tool: str, args: Any, at: str) -> str:
    """``ok`` or why this call is outside the exception."""
    if not ts(body["notBefore"]) <= ts(at) <= ts(body["expiresAt"]):
        return "exception_expired" if ts(at) > ts(body["expiresAt"]) else "exception_not_yet_valid"
    scope = body["scope"]
    if scope["tool"] != tool:
        return "exception_tool_mismatch"
    if not isinstance(args, dict):
        return "arguments_not_an_object"
    extra = sorted(set(args) - set(scope["args"]))
    if extra:
        return f"argument_outside_exception:{extra[0]}"
    for name, c in scope["args"].items():
        if not constraints.check(c, args.get(name)):
            return f"exception_constraint_violation:{name}"
    return "ok"


def verify_exception_evidence(pred: Mapping[str, Any], evidence: Mapping[str, Any],
                              policies: Mapping[str, Mapping[str, Any]], at: str,
                              key_revoked: Any = None) -> list[str]:
    """Offline re-check of an exception allow: digest, scope, window and quorum."""
    problems: list[str] = []
    body = evidence.get("exception")
    if not isinstance(body, dict):
        return ["exception_missing"]
    digest = exception_digest(body)
    if digest != evidence.get("exceptionDigest") or digest != pred.get("exceptionDigest"):
        problems.append("exception_digest_differs_from_record")
    raw = base64.b64decode(evidence.get("argsB64", ""))
    if hashlib.sha256(raw).hexdigest() != pred.get("argsSha256"):
        problems.append("authority_args_are_not_the_call_arguments")
    verdict = check_exception_call(body, str(pred.get("tool")), json.loads(raw) if raw else None, at)
    if verdict != "ok":
        problems.append(verdict)
    q = evidence.get("quorum") or {}
    if (q.get("policy") or {}).get("policyId") != body.get("policyId"):
        problems.append("exception_approved_under_another_policy")
    outcome = quorum.verify_evidence(q, policies, digest, at, key_revoked)
    if outcome != "ok":
        problems.append(f"exception_{outcome}")
    return problems


def route_by_risk(tier: str, routes: Mapping[str, str]) -> str:
    """The quorum policy id for a risk tier; an unknown tier is refused, never defaulted."""
    if tier not in routes:
        raise ValueError(f"no_route_for_risk_tier:{tier}")
    return routes[tier]


def step_predicate(*, kind: str, subject_digest: str, actor: str, decision: str | None = None,
                   rationale: str | None = None, risk_tier: str | None = None, policy_id: str | None = None,
                   owner: str | None = None, expires_at: str | None = None,
                   refs: Mapping[str, str] | None = None, quorum_evidence: Mapping[str, Any] | None = None) -> dict:
    """One workflow step. ``subject_digest`` is the digest of what the step is about (an intake form, a
    system card, an exception); ``refs`` link earlier steps by journal sequence or digest."""
    if kind not in STEPS:
        raise ValueError(f"step kind must be one of {STEPS}")
    return {"actor": actor, "decision": decision, "expiresAt": expires_at, "kind": kind, "owner": owner,
            "policyId": policy_id, "quorum": dict(quorum_evidence) if quorum_evidence else None,
            "rationale": rationale, "refs": dict(refs or {}), "riskTier": risk_tier,
            "subjectDigest": subject_digest}


def check_step(pred: Mapping[str, Any], policies: Mapping[str, Mapping[str, Any]] | None, at: str,
               key_revoked: Any = None) -> list[str]:
    """Shape of a workflow step, and its quorum when it carries one."""
    problems = [f"step_missing_{f}" for f in STEP_FIELDS if not pred.get(f)]
    if pred.get("kind") not in STEPS:
        problems.append("step_kind_unknown")
    if pred.get("kind") == "exception" and not (pred.get("owner") and pred.get("rationale") and pred.get("expiresAt")):
        problems.append("exception_step_needs_owner_rationale_expiry")
    if pred.get("quorum"):
        outcome = quorum.verify_evidence(pred["quorum"], policies or {}, str(pred.get("subjectDigest")), at,
                                         key_revoked)
        if outcome != "ok":
            problems.append(f"step_{outcome}")
    return problems
