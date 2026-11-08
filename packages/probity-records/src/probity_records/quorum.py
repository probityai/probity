"""M-of-N signed approvals bound to one request hash.

A quorum policy names N approvers, each with its own Ed25519 key, and the threshold M. Each
approver signs a vote over the request hash (the tool, the argument digest and the permit id, or
the digest of any other governed object such as an exception). Votes arrive supplied with the call,
from a fetch handler at check time, or both; a handler that has no quorum yet is retried, and the
answer "still pending" is never read as an approval. The authority records every counted vote in
the permit and the tool-call record, so an outsider re-counts them offline.

Policy::

    {"policyId": str, "threshold": M, "approvers": {principal: b64 raw Ed25519}}

Vote body::

    {"approver": principal, "decision": "approve" | "reject", "expiresAt": iso,
     "issuedAt": iso, "policyId": str, "requestHash": hex}
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
APPROVAL_QUORUM = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/approval-quorum"
APPROVED, REFUSED, PENDING = "approved", "refused", "pending"


def request_hash(tool: str, args_sha256_hex: str, permit: str) -> str:
    """The hash every vote for one call signs."""
    return sha256_hex(canonical({"argsSha256": args_sha256_hex, "permitId": permit, "tool": tool}))


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


def sign_vote(signer: Signer, *, approver: str, policy_id: str, request: str, issued_at: str,
              expires_at: str, decision: str = "approve") -> dict[str, Any]:
    if decision not in ("approve", "reject"):
        raise ValueError("vote decision must be approve or reject")
    body = {"approver": approver, "decision": decision, "expiresAt": expires_at, "issuedAt": issued_at,
            "policyId": policy_id, "requestHash": request}
    return {"body": body, "sig": _b64(signer.sign(VOTE_DOMAIN + canonical(body)))}


@dataclass(frozen=True)
class QuorumResult:
    status: str
    approvers: tuple[str, ...]
    rejecters: tuple[str, ...]
    votes: tuple[dict[str, Any], ...]
    ignored: tuple[str, ...] = field(default=())

    def evidence(self, policy: Mapping[str, Any], request: str) -> dict[str, Any]:
        """What the permit and the tool-call record carry."""
        return {"kind": "quorum", "policy": dict(policy), "policyDigest": policy_digest(policy),
                "requestHash": request, "votes": [dict(v) for v in self.votes]}


def _vote_problem(vote: Any, policy: Mapping[str, Any], request: str, at: str,
                  key_revoked: Callable[[str, str], bool] | None) -> str | None:
    body = vote.get("body") if isinstance(vote, Mapping) else None
    if not isinstance(body, dict):
        return "vote_shape"
    raw = policy["approvers"].get(str(body.get("approver")))
    if raw is None:
        return "vote_from_unknown_approver"
    try:
        key = load_public(_unb64(raw))
        key.verify(_unb64(vote.get("sig")), VOTE_DOMAIN + canonical(body))
    except (InvalidSignature, ValueError, TypeError):
        return "vote_signature_unverified"
    if body.get("policyId") != policy["policyId"]:
        return "vote_for_another_policy"
    if body.get("requestHash") != request:
        return "vote_for_another_request"
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
          key_revoked: Callable[[str, str], bool] | None = None) -> QuorumResult:
    """Count distinct approvers' valid votes. Approved at M approvals; refused once M can no longer
    be reached (rejections plus the threshold exceed N); pending otherwise. A second vote from one
    approver is ignored, so one key can never count twice."""
    validate_policy(policy)
    seen: dict[str, dict[str, Any]] = {}
    ignored: list[str] = []
    for vote in votes:
        problem = _vote_problem(vote, policy, request, at, key_revoked)
        if problem:
            ignored.append(problem)
            continue
        who = vote["body"]["approver"]
        if who in seen:
            ignored.append("vote_duplicate_approver")
            continue
        seen[who] = dict(vote)
    yes = tuple(sorted(w for w, v in seen.items() if v["body"]["decision"] == "approve"))
    no = tuple(sorted(w for w, v in seen.items() if v["body"]["decision"] == "reject"))
    m, n = policy["threshold"], len(policy["approvers"])
    if len(yes) >= m:
        status = APPROVED
    elif n - len(no) < m:
        status = REFUSED
    else:
        status = PENDING
    counted = tuple(seen[w] for w in sorted(seen))
    return QuorumResult(status, yes, no, counted, tuple(ignored))


class StillPending(Exception):
    """A fetch handler's answer that votes are still being collected."""


def await_quorum(policy: Mapping[str, Any], request: str, *, supplied: Iterable[Any] = (),
                 fetch: Callable[[str], Iterable[Any]] | None = None, clock: Callable[[], str],
                 attempts: int = 1, wait_seconds: float = 0.0,
                 sleep: Callable[[float], None] = time.sleep,
                 key_revoked: Callable[[str, str], bool] | None = None) -> QuorumResult:
    """Supplied votes plus whatever ``fetch(request)`` returns, retried up to ``attempts`` times while
    the count is pending. A handler raising ``StillPending`` counts as no new votes."""
    supplied = list(supplied)
    fetched: list[Any] = []
    result = count(policy, request, supplied, clock(), key_revoked)
    for attempt in range(attempts if fetch else 0):
        if result.status != PENDING:
            break
        try:
            fetched = list(fetch(request))  # type: ignore[misc]
        except StillPending:
            pass
        result = count(policy, request, supplied + fetched, clock(), key_revoked)
        if result.status == PENDING and attempt + 1 < attempts:
            sleep(wait_seconds)
    return result


def verify_evidence(evidence: Mapping[str, Any], pinned: Mapping[str, Mapping[str, Any]], request: str,
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
    result = count(trusted, request, evidence.get("votes") or [], at, key_revoked)
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
