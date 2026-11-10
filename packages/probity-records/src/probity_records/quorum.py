"""M-of-N signed approvals bound to one request hash.

A quorum policy names N approvers, each with its own Ed25519 key, and the threshold M. Each
approver signs a vote over the request hash (the tool, the argument digest and the permit id, or
the digest of any other governed object such as an exception). Votes arrive supplied with the call,
from a fetch handler at check time, or both; a handler that has no quorum yet is retried, and the
answer "still pending" is never read as an approval. The authority records every counted vote in
the permit and the tool-call record, so an outsider re-counts them offline.

Policy::

    {"policyId": str, "threshold": M, "approvers": {principal: b64 raw Ed25519},
     "roles": {role: {"members": [principal], "min": k}}}          # roles optional

Vote body::

    {"approver": principal, "decision": "approve" | "reject", "expiresAt": iso,
     "issuedAt": iso, "policyId": str, "requestHash": hex, "role": role (when the policy has roles),
     "onBehalfOf": principal (a deputy's vote)}

Segregation of duties, enforced by the count and re-run by the verifier: the request hash binds the
proposer, and a vote by the proposer (or by a deputy of anyone, cast by the proposer) is never
counted; each approver counts once and fills exactly one role, so one person cannot satisfy two
required roles; every role's minimum must be met as well as the threshold.

Deputies: an approver may sign a time-bounded delegation naming a deputy key for one policy and a
subset of their roles. The deputy's vote counts as the delegator's (so the pair is still one vote),
and a deputy who is already an approver in the policy is refused (one person, two votes).

Add-only delegation of the policy itself: a grant delegated under a parent that requires a quorum
keeps every parent approver with the same key and every parent role, and may only add approvers or
roles and raise the threshold, by at least one for every approver added (``widening_problem``).
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature

from .core import _b64, _unb64, canonical, key_id, load_public, sha256_hex, Signer
from .grants import ts

VOTE_DOMAIN = b"probity-quorum-vote-v1\x00"
DEPUTY_DOMAIN = b"probity-quorum-deputy-v1\x00"
APPROVAL_QUORUM = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/approval-quorum"
APPROVED, REFUSED, PENDING = "approved", "refused", "pending"


def request_hash(tool: str, args_sha256_hex: str, permit: str, *, proposer: str | None = None,
                 history: str | None = None) -> str:
    """The hash every vote for one call signs: the tool, the argument digest, the permit, and when
    given the proposer principal and the digest of the model response that proposed the call."""
    body: dict[str, Any] = {"argsSha256": args_sha256_hex, "permitId": permit, "tool": tool}
    if proposer is not None:
        body["proposer"] = proposer
    if history is not None:
        body["historyDigest"] = history
    return sha256_hex(canonical(body))


def policy_digest(policy: Mapping[str, Any]) -> str:
    return sha256_hex(canonical(dict(policy)))


def validate_policy(policy: Mapping[str, Any]) -> None:
    approvers = policy.get("approvers")
    m = policy.get("threshold")
    if not isinstance(approvers, dict) or not approvers:
        raise ValueError("quorum_policy_without_approvers")
    if not isinstance(m, int) or isinstance(m, bool) or not 1 <= m <= len(approvers):
        raise ValueError("quorum_threshold_out_of_range")
    if len({str(v) for v in approvers.values()}) != len(approvers):
        raise ValueError("quorum_approvers_share_a_key")
    if not isinstance(policy.get("proposerBound", False), bool):
        raise ValueError("quorum_proposer_bound_shape")
    roles = policy.get("roles", {})
    if not isinstance(roles, dict):
        raise ValueError("quorum_roles_shape")
    for role, spec in roles.items():
        members, k = (spec or {}).get("members"), (spec or {}).get("min")
        if (not isinstance(members, list) or not members or not set(members) <= set(approvers)
                or not isinstance(k, int) or isinstance(k, bool) or not 1 <= k <= len(members)):
            raise ValueError(f"quorum_role_invalid:{role}")
    if sum(spec["min"] for spec in roles.values()) > len(approvers):
        raise ValueError("quorum_roles_unsatisfiable")


def widening_problem(child: Mapping[str, Any] | None, parent: Mapping[str, Any]) -> str | None:
    """None when ``child`` is an add-only extension of ``parent``; otherwise the widening found."""
    if child is None:
        return "child_drops_quorum"
    if parent.get("proposerBound") and not child.get("proposerBound"):
        return "child_unbinds_proposer"
    for who, key in parent["approvers"].items():
        if child["approvers"].get(who) != key:
            return "child_removes_approver"
    added = len(set(child["approvers"]) - set(parent["approvers"]))
    if child["threshold"] < parent["threshold"] + added:
        return "child_lowers_threshold"
    for role, spec in parent.get("roles", {}).items():
        cspec = child.get("roles", {}).get(role)
        if cspec is None:
            return f"child_drops_role:{role}"
        if cspec["min"] < spec["min"] or not set(cspec["members"]) <= set(spec["members"]):
            return f"child_widens_role:{role}"
    return None


def sign_deputy(delegator_signer: Signer, *, delegator: str, deputy: str, deputy_key: str, policy_id: str,
                roles: list[str], not_before: str, expires_at: str) -> dict[str, Any]:
    """A delegator's signed hand-off of their vote to a deputy key, bounded in time and roles."""
    body = {"delegator": delegator, "deputy": deputy, "deputyKey": deputy_key, "expiresAt": expires_at,
            "notBefore": not_before, "policyId": policy_id, "roles": sorted(roles)}
    return {"body": body, "sig": _b64(delegator_signer.sign(DEPUTY_DOMAIN + canonical(body)))}


def sign_vote(signer: Signer, *, approver: str, policy_id: str, request: str, issued_at: str,
              expires_at: str, decision: str = "approve", role: str | None = None,
              deputy_for: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """One vote. A deputy passes ``deputy_for`` (the delegator's signed ``sign_deputy`` record) and
    signs with the deputy key; ``approver`` is then the deputy's own principal."""
    if decision not in ("approve", "reject"):
        raise ValueError("vote decision must be approve or reject")
    body: dict[str, Any] = {"approver": approver, "decision": decision, "expiresAt": expires_at,
                            "issuedAt": issued_at, "policyId": policy_id, "requestHash": request}
    if role is not None:
        body["role"] = role
    if deputy_for is not None:
        body["onBehalfOf"] = deputy_for["body"]["delegator"]
    vote = {"body": body, "sig": _b64(signer.sign(VOTE_DOMAIN + canonical(body)))}
    if deputy_for is not None:
        vote["delegation"] = dict(deputy_for)
    return vote


@dataclass(frozen=True)
class QuorumResult:
    status: str
    approvers: tuple[str, ...]
    rejecters: tuple[str, ...]
    votes: tuple[dict[str, Any], ...]
    ignored: tuple[str, ...] = field(default=())

    def evidence(self, policy: Mapping[str, Any], request: str, *, proposer: str | None = None,
                 history: str | None = None) -> dict[str, Any]:
        """What the permit and the tool-call record carry."""
        out = {"kind": "quorum", "policy": dict(policy), "policyDigest": policy_digest(policy),
               "requestHash": request, "votes": [dict(v) for v in self.votes]}
        if proposer is not None:
            out["proposer"] = proposer
        if history is not None:
            out["historyDigest"] = history
        return out


def _deputy_problem(vote: Mapping[str, Any], policy: Mapping[str, Any], at: str) -> tuple[str | None, str | None]:
    """(problem, deputy key) for a vote cast on behalf of an approver."""
    body = vote["body"]
    delegation = vote.get("delegation")
    dbody = delegation.get("body") if isinstance(delegation, Mapping) else None
    if not isinstance(dbody, dict):
        return "deputy_without_delegation", None
    who = str(body.get("onBehalfOf"))
    raw = policy["approvers"].get(who)
    if raw is None or dbody.get("delegator") != who:
        return "deputy_for_unknown_approver", None
    try:
        load_public(_unb64(raw)).verify(_unb64(delegation.get("sig")), DEPUTY_DOMAIN + canonical(dbody))
    except (InvalidSignature, ValueError, TypeError):
        return "deputy_delegation_unverified", None
    if dbody.get("policyId") != policy["policyId"] or dbody.get("deputy") != body.get("approver"):
        return "deputy_delegation_mismatch", None
    if dbody.get("deputy") in policy["approvers"] or dbody.get("deputyKey") in policy["approvers"].values():
        return "deputy_is_an_approver", None
    if "role" in body and body["role"] not in dbody.get("roles", []):
        return "deputy_role_not_delegated", None
    try:
        if not ts(dbody["notBefore"]) <= ts(at) <= ts(dbody["expiresAt"]):
            return "deputy_delegation_outside_window", None
    except (KeyError, ValueError, TypeError):
        return "deputy_delegation_outside_window", None
    return None, str(dbody.get("deputyKey"))


def _vote_problem(vote: Any, policy: Mapping[str, Any], request: str, at: str,
                  key_revoked: Callable[[str, str], bool] | None, proposer: str | None = None) -> str | None:
    body = vote.get("body") if isinstance(vote, Mapping) else None
    if not isinstance(body, dict):
        return "vote_shape"
    if "onBehalfOf" in body:
        problem, raw = _deputy_problem(vote, policy, at)
        if problem:
            return problem
        counted_as = str(body["onBehalfOf"])
    else:
        raw = policy["approvers"].get(str(body.get("approver")))
        counted_as = str(body.get("approver"))
    if raw is None:
        return "vote_from_unknown_approver"
    if proposer is not None and proposer in (counted_as, str(body.get("approver"))):
        return "vote_by_proposer"
    try:
        key = load_public(_unb64(raw))
        key.verify(_unb64(vote.get("sig")), VOTE_DOMAIN + canonical(body))
    except (InvalidSignature, ValueError, TypeError):
        return "vote_signature_unverified"
    if body.get("policyId") != policy["policyId"]:
        return "vote_for_another_policy"
    if body.get("requestHash") != request:
        return "vote_for_another_request"
    roles = policy.get("roles", {})
    if roles:
        role = body.get("role")
        if role not in roles or counted_as not in roles[role]["members"]:
            return "vote_role_not_held"
    try:
        live = ts(body["issuedAt"]) <= ts(at) <= ts(body["expiresAt"])
    except (KeyError, ValueError, TypeError):
        return "vote_time_invalid"
    if not live:
        return "vote_outside_window"
    if key_revoked is not None and key_revoked(key_id(key), at):
        return "vote_key_revoked"
    return None


def count(policy: Mapping[str, Any], request: str, votes: Iterable[Any], at: str,
          key_revoked: Callable[[str, str], bool] | None = None, proposer: str | None = None) -> QuorumResult:
    """Count distinct approvers' valid votes. Approved at M approvals with every role's minimum met;
    refused once that can no longer be reached; pending otherwise. A second vote for one approver
    (theirs or their deputy's) is ignored, so one person never counts twice, and the proposer's own
    vote never counts."""
    validate_policy(policy)
    seen: dict[str, dict[str, Any]] = {}
    ignored: list[str] = []
    for vote in votes:
        problem = _vote_problem(vote, policy, request, at, key_revoked, proposer)
        if problem:
            ignored.append(problem)
            continue
        who = vote["body"].get("onBehalfOf", vote["body"]["approver"])
        if who in seen:
            ignored.append("vote_duplicate_approver")
            continue
        seen[who] = dict(vote)
    yes = tuple(sorted(w for w, v in seen.items() if v["body"]["decision"] == "approve"))
    no = tuple(sorted(w for w, v in seen.items() if v["body"]["decision"] == "reject"))
    m, n = policy["threshold"], len(policy["approvers"])
    roles = policy.get("roles", {})
    filled = {r: sum(1 for w in yes if seen[w]["body"].get("role") == r) for r in roles}
    lost = {r: sum(1 for w in no if seen[w]["body"].get("role") == r) for r in roles}
    roles_met = all(filled[r] >= spec["min"] for r, spec in roles.items())
    roles_dead = any(len(spec["members"]) - lost[r] < spec["min"] for r, spec in roles.items())
    if proposer is not None:
        n -= 1 if proposer in policy["approvers"] else 0
    if len(yes) >= m and roles_met:
        status = APPROVED
    elif n - len(no) < m or roles_dead:
        status = REFUSED
    else:
        status = PENDING
    counted = tuple(seen[w] for w in sorted(seen))
    return QuorumResult(status, yes, no, counted, tuple(ignored))


def verify_evidence(evidence: Mapping[str, Any], pinned: Mapping[str, Mapping[str, Any]], request: str,
                    at: str, key_revoked: Callable[[str, str], bool] | None = None) -> str:
    """See below; the proposer named in the evidence is bound by the request hash the caller
    recomputed, so a record cannot drop it to let the proposer's own vote count."""
    return _verify_evidence(evidence, pinned, request, at, key_revoked)


def _verify_evidence(evidence: Mapping[str, Any], pinned: Mapping[str, Mapping[str, Any]], request: str,
                     at: str, key_revoked: Callable[[str, str], bool] | None = None) -> str:
    """Offline: ``ok`` or the reason the recorded quorum does not hold. The policy is the one the
    auditor pinned under its id, compared by digest, never the copy inside the record."""
    policy = evidence.get("policy") or {}
    trusted = pinned.get(str(policy.get("policyId")))
    if trusted is None:
        return "quorum_policy_not_pinned"
    if policy_digest(trusted) != evidence.get("policyDigest") or policy_digest(policy) != policy_digest(trusted):
        return "quorum_policy_differs_from_pinned"
    if evidence.get("requestHash") != request:
        return "quorum_for_another_request"
    if trusted.get("proposerBound") and not evidence.get("proposer"):
        return "quorum_proposer_unbound"
    result = count(trusted, request, evidence.get("votes") or [], at, key_revoked, evidence.get("proposer"))
    if result.ignored:
        return f"quorum_vote_invalid:{result.ignored[0]}"
    return "ok" if result.status == APPROVED else f"quorum_{result.status}"


def approval_policy(policy_id: str, approver_pems: Mapping[str, bytes], threshold: int) -> dict[str, Any]:
    """A quorum policy for signed human approvals, from each approver's public key (PEM or raw)."""
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: PLC0415

    def raw(pem: bytes) -> str:
        return _b64(load_public(pem).public_bytes(Encoding.Raw, PublicFormat.Raw))

    policy = {"approvers": {who: raw(pem) for who, pem in approver_pems.items()},
              "policyId": policy_id, "threshold": threshold}
    validate_policy(policy)
    return policy


def count_bindings(policy: Mapping[str, Any], bindings: Iterable[Mapping[str, Any]], at: str,
                   key_revoked: Callable[[str, str], bool] | None = None) -> tuple[set[str], list[str]]:
    """The distinct approvers whose embedded approval-binding record carries a human approval signed
    by the key ``policy`` pins for that approver, and the problems found.

    This is the one M-of-N count for human approvals: the authority and an offline auditor run the
    same function, the auditor with the policy it pinned (never one read from the records). Each
    binding carries ``approvalSig``, the approver's signature over the approval body, so the count
    re-verifies the human's signature rather than trusting the authority's word for it. The
    published approval-binding reader is judged separately by the caller.
    """
    from .core import APPROVAL_DOMAIN  # noqa: PLC0415

    validate_policy(policy)
    counted: set[str] = set()
    problems: list[str] = []
    for n, embedded in enumerate(bindings):
        approval = (embedded.get("record") or {}).get("approval") or {}
        who = str(approval.get("approver", ""))
        raw = policy["approvers"].get(who)
        if raw is None:
            problems.append(f"binding_{n}:approver_not_in_policy")
            continue
        try:
            key = load_public(_unb64(raw))
            key.verify(_unb64(embedded.get("approvalSig")), APPROVAL_DOMAIN + canonical(approval))
        except (InvalidSignature, ValueError, TypeError):
            problems.append(f"binding_{n}:approval_signature_unverified")
            continue
        if approval.get("keyId") != key_id(key):
            problems.append(f"binding_{n}:approval_key_id_is_not_the_pinned_key")
            continue
        if key_revoked is not None and key_revoked(key_id(key), at):
            problems.append(f"binding_{n}:approver_key_revoked")
            continue
        if who in counted:
            problems.append(f"binding_{n}:duplicate_approver")
            continue
        counted.add(who)
    return counted, problems
