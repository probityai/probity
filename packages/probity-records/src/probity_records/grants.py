"""Signed capability grants: task-scoped authority checked per call, with no human per call.

A grant names the tools its holder may call and, per tool, a constraint on every argument it
admits. Arguments are closed-world: a call carrying an argument the grant does not name is refused.
A holder may delegate a child grant signed with its own key; the child must narrow the parent on
every axis (tools, arguments, constraint, window, approval requirement), and the verifier proves
that, so authority can only shrink down a chain.

Grant body::

    {"grantId": str, "issuerKey": b64 raw Ed25519, "holderKey": b64 raw Ed25519,
     "parent": sha256 hex of the parent body or None, "notBefore": iso, "expiresAt": iso,
     "maxDepth": int,                       # further delegations allowed below this grant
     "context": {key: constraint},          # the call context the permit names (workflowId, runId, agent...)
     "budget": {"uses": int, "spend": {"arg": name, "max": number}},   # optional, both parts optional
     "tools": {tool: {"args": {name: constraint}, "approval": "none" | "required",
                      "when": [CEL expression over args, tool, ctx],
                      "quorum": approval policy (see quorum.py)}}}

Every axis narrows down a chain: tools, arguments, constraints, window, depth, context, budget,
``when`` conditions (a child keeps every parent condition and may add more) and the approval
requirement (a child keeps every parent approver and threshold and may add more: add-only).

A budget is shared down the chain: every use under a descendant also spends from every ancestor, so
two children of a ten-use grant cannot spend twenty. The verifier re-counts spend from the journal.

The grant digest (SHA-256 of the JCS body) goes into the permit claims (``grantDigest``), into the
authorize, intent and effect records, so an outsider walks grant to permit to effect offline.
"""

from __future__ import annotations

import base64
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from cryptography.exceptions import InvalidSignature

from . import celexpr, constraints
from .core import _b64, _unb64, canonical, key_id, load_public, sha256_hex, Signer

GRANT_DOMAIN = b"probity-grant-v1\x00"
CAPABILITY_GRANT = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/capability-grant"
APPROVAL_LEVELS = ("none", "required")


def ts(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def raw_public(signer: Signer) -> str:
    """The base64 raw public key a grant names as issuer or holder."""
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: PLC0415

    return _b64(signer.public.public_bytes(Encoding.Raw, PublicFormat.Raw))


def grant_digest(body: Mapping[str, Any]) -> str:
    return sha256_hex(canonical(dict(body)))


def _int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _validate_budget(budget: Any) -> None:
    if budget is None:
        return
    if not isinstance(budget, dict) or not budget or set(budget) - {"uses", "spend"}:
        raise ValueError("grant_budget_shape")
    if "uses" in budget and not _int(budget["uses"]):
        raise ValueError("grant_budget_uses")
    spend = budget.get("spend")
    if spend is not None and (not isinstance(spend, dict) or set(spend) != {"arg", "max"}
                              or not isinstance(spend["arg"], str)
                              or not isinstance(spend["max"], (int, float)) or isinstance(spend["max"], bool)
                              or spend["max"] < 0):
        raise ValueError("grant_budget_spend")


def _validate_tools(tools: Any) -> None:
    if not isinstance(tools, dict) or not tools:
        raise ValueError("grant_tools_empty")
    for tool, spec in tools.items():
        if not isinstance(spec, dict) or not isinstance(spec.get("args"), dict):
            raise ValueError(f"grant_tool_shape:{tool}")
        if spec.get("approval", "none") not in APPROVAL_LEVELS:
            raise ValueError(f"grant_approval_level:{tool}")
        for c in spec["args"].values():
            constraints.validate(c)
        when = spec.get("when", [])
        if not isinstance(when, list) or not all(isinstance(w, str) for w in when):
            raise ValueError(f"grant_when_shape:{tool}")
        for w in when:
            celexpr.compile_expr(w)
        if "quorum" in spec:
            from .quorum import validate_policy  # noqa: PLC0415 - quorum imports this module

            validate_policy(spec["quorum"])
            if not spec["quorum"].get("proposerBound"):
                raise ValueError(f"grant_quorum_must_bind_proposer:{tool}")
            if spec.get("approval") != "required":
                raise ValueError(f"grant_quorum_without_required_approval:{tool}")


def validate_body(body: Mapping[str, Any]) -> None:
    """Shape of a grant body on every axis; ValueError naming the first defect."""
    _validate_tools(body.get("tools"))
    if not _int(body.get("maxDepth")):
        raise ValueError("grant_max_depth")
    ctx = body.get("context")
    if not isinstance(ctx, dict):
        raise ValueError("grant_context_shape")
    for c in ctx.values():
        constraints.validate(c)
    _validate_budget(body.get("budget"))


def issue_grant(issuer: Signer, *, grant_id: str, holder_key: str, tools: Mapping[str, Any],
                not_before: str, expires_at: str, parent: Mapping[str, Any] | None = None,
                max_depth: int | None = None, context: Mapping[str, Any] | None = None,
                budget: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Sign a grant. With ``parent`` (a signed grant), ``issuer`` must be the parent's holder and the
    new grant must narrow it; both are checked here and again by every verifier. ``max_depth``
    defaults to 0 (no further delegation) for a child, and to 0 for a root unless given."""
    body = {"context": dict(context or {}), "expiresAt": expires_at, "grantId": grant_id,
            "holderKey": holder_key, "issuerKey": raw_public(issuer),
            "maxDepth": 0 if max_depth is None else max_depth, "notBefore": not_before,
            "parent": grant_digest(parent["body"]) if parent else None, "tools": dict(tools)}
    if budget is not None:
        body["budget"] = dict(budget)
    validate_body(body)
    if parent is not None:
        problem = narrowing_problem(body, parent["body"])
        if problem:
            raise ValueError(problem)
    return {"body": body, "sig": _b64(issuer.sign(GRANT_DOMAIN + canonical(body)))}


def narrowing_problem(child: Mapping[str, Any], parent: Mapping[str, Any]) -> str | None:
    """None when ``child`` provably narrows ``parent``; otherwise the first widening found."""
    if child.get("issuerKey") != parent.get("holderKey"):
        return "child_not_issued_by_parent_holder"
    if ts(child["notBefore"]) < ts(parent["notBefore"]) or ts(child["expiresAt"]) > ts(parent["expiresAt"]):
        return "child_window_wider_than_parent"
    if parent.get("maxDepth", 0) < 1:
        return "parent_forbids_delegation"
    if child.get("maxDepth", 0) > parent["maxDepth"] - 1:
        return "child_depth_wider_than_parent"
    for key, c in parent.get("context", {}).items():
        if key not in child.get("context", {}):
            return f"child_drops_context:{key}"
        if not constraints.narrows(child["context"][key], c):
            return f"child_widens_context:{key}"
    problem = _budget_narrowing(child.get("budget"), parent.get("budget"))
    if problem:
        return problem
    for tool, spec in child["tools"].items():
        pspec = parent["tools"].get(tool)
        if pspec is None:
            return f"child_adds_tool:{tool}"
        if pspec.get("approval", "none") == "required" and spec.get("approval", "none") != "required":
            return f"child_drops_approval:{tool}"
        missing = [w for w in pspec.get("when", []) if w not in spec.get("when", [])]
        if missing:
            return f"child_drops_condition:{tool}"
        if "quorum" in pspec:
            from .quorum import widening_problem  # noqa: PLC0415 - quorum imports this module

            problem = widening_problem(spec.get("quorum"), pspec["quorum"])
            if problem:
                return f"{problem}:{tool}"
        added = sorted(set(spec["args"]) - set(pspec["args"]))
        if added:
            return f"child_adds_argument:{tool}.{added[0]}"
        dropped = sorted(set(pspec["args"]) - set(spec["args"]))
        if dropped:  # a call without the argument would leave it to the tool's default, unbounded
            return f"child_drops_argument:{tool}.{dropped[0]}"
        for name, c in spec["args"].items():
            if not constraints.narrows(c, pspec["args"][name]):
                return f"child_widens_constraint:{tool}.{name}"
    return None


def _budget_narrowing(child: Any, parent: Any) -> str | None:
    if parent is None:
        return None
    if child is None:
        return "child_drops_budget"
    if "uses" in parent and child.get("uses", parent["uses"] + 1) > parent["uses"]:
        return "child_budget_wider_than_parent"
    if "spend" in parent:
        cs = child.get("spend")
        if cs is None or cs["arg"] != parent["spend"]["arg"] or cs["max"] > parent["spend"]["max"]:
            return "child_spend_wider_than_parent"
    return None


def _verify_sig(signed: Mapping[str, Any], raw_key_b64: str) -> bool:
    try:
        load_public(_unb64(raw_key_b64)).verify(_unb64(signed.get("sig")), GRANT_DOMAIN + canonical(signed["body"]))
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


_STRUCTURE: dict[tuple[str, frozenset[str]], tuple[tuple[str, ...], tuple[str, ...], str]] = {}
_STRUCTURE_MAX = 4096


def _structure(chain: list[Mapping[str, Any]], root_key_ids: frozenset[str]) -> tuple[tuple[str, ...], tuple[str, ...], str]:
    """The time-independent half of a chain check: shapes, signatures, root trust, parent links and
    the narrowing proof. Returns (issuer key ids, grant digests, "ok" or the refusal). Memoised on
    the exact chain content and the pinned roots, so an altered byte anywhere misses the cache."""
    import json  # noqa: PLC0415

    try:
        cache_key = (json.dumps(chain, sort_keys=True, separators=(",", ":")), root_key_ids)
    except (TypeError, ValueError):
        cache_key = None
    if cache_key is not None and cache_key in _STRUCTURE:
        return _STRUCTURE[cache_key]
    issuers: list[str] = []
    digests: list[str] = []
    result = "ok"
    prev: Mapping[str, Any] | None = None
    for depth, signed in enumerate(chain):
        body = signed.get("body") if isinstance(signed, Mapping) else None
        if not isinstance(body, dict):
            result = f"grant_shape:{depth}"
            break
        try:
            validate_body(body)
            issuer_id = key_id(load_public(base64.b64decode(body["issuerKey"])))
        except (ValueError, KeyError, TypeError) as exc:
            result = f"grant_invalid:{depth}:{exc}"
            break
        if not _verify_sig(signed, body["issuerKey"]):
            result = f"grant_signature_unverified:{depth}"
            break
        if prev is None:
            if body.get("parent") is not None or issuer_id not in root_key_ids:
                result = "grant_root_untrusted"
                break
        else:
            if body.get("parent") != digests[-1]:
                result = f"grant_parent_mismatch:{depth}"
                break
            problem = narrowing_problem(body, prev)
            if problem:
                result = f"{problem}:{depth}"
                break
        issuers.append(issuer_id)
        digests.append(grant_digest(body))
        prev = body
    out = (tuple(issuers), tuple(digests), result)
    if cache_key is not None:
        if len(_STRUCTURE) >= _STRUCTURE_MAX:
            _STRUCTURE.clear()
        _STRUCTURE[cache_key] = out
    return out


def verify_chain(chain: list[Mapping[str, Any]], root_key_ids: set[str], at: str,
                 revoked_grants: set[str] | None = None,
                 key_revoked: Any = None) -> tuple[dict[str, Any] | None, str]:
    """Verify a root-to-leaf grant chain at time ``at``.

    Returns ``(leaf_body, "ok")`` or ``(None, reason)``. ``root_key_ids`` are the key ids of the
    trusted grant issuers. A revoked grant anywhere in the chain revokes every descendant.
    ``key_revoked(key_id, at) -> bool`` reports signer keys revoked at that time. Revocation and the
    validity window are checked on every call; the signature and narrowing proof are memoised.
    """
    if not chain:
        return None, "grant_chain_empty"
    revoked_grants = revoked_grants or set()
    issuers, digests, result = _structure(chain, frozenset(root_key_ids))
    when = ts(at)
    for depth, (issuer_id, digest) in enumerate(zip(issuers, digests, strict=True)):
        if key_revoked is not None and key_revoked(issuer_id, at):
            return None, f"grant_issuer_key_revoked:{depth}"
        if digest in revoked_grants:
            return None, f"grant_revoked:{depth}"
        body = chain[depth]["body"]
        if not ts(body["notBefore"]) <= when <= ts(body["expiresAt"]):
            return None, f"grant_outside_window:{depth}"
    if result != "ok":
        return None, result
    return dict(chain[-1]["body"]), "ok"


def verify_call_under_grant(leaf: Mapping[str, Any], tool: str, args: Any, ctx: Mapping[str, Any] | None = None) -> str:
    """``ok``, ``approval_required``, or the refusal reason for one call under the leaf grant.

    ``ctx`` is the call context the permit names; every context key the grant constrains must be
    present and satisfy its constraint (the chain proof makes the leaf at least as strict as every
    ancestor, so the leaf alone decides)."""
    ctx = dict(ctx or {})
    for key, c in leaf.get("context", {}).items():
        if key not in ctx or not constraints.check(c, ctx[key]):
            return f"context_violation:{key}"
    spec = leaf["tools"].get(tool)
    if spec is None:
        return "tool_not_granted"
    if not isinstance(args, dict):
        return "arguments_not_an_object"
    extra = sorted(set(args) - set(spec["args"]))
    if extra:
        return f"argument_not_granted:{extra[0]}"
    for name, c in spec["args"].items():
        if not constraints.check(c, args.get(name)):
            return f"constraint_violation:{name}"
    for n, expr in enumerate(spec.get("when", [])):
        if not celexpr.holds(expr, {"args": args, "tool": tool, "ctx": ctx}):
            return f"condition_violation:{n}"
    return "approval_required" if spec.get("approval", "none") == "required" else "ok"


def verify_grant_allow(chain: list[Mapping[str, Any]], tool: str, args: Any, at: str, root_key_ids: set[str],
              revoked_grants: set[str] | None = None, key_revoked: Any = None,
              ctx: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Re-derive, offline, what a grant chain allows for one recorded call: ``{"decision", "reason", "grantDigest", "chain"}``.

    ``decision`` is ``allow`` (no human needed), ``needs_approval`` or ``deny``. ``chain`` lists
    the digest of every grant from root to leaf: each one is charged for the use (budgets).
    """
    leaf, reason = verify_chain(chain, root_key_ids, at, revoked_grants, key_revoked)
    if leaf is None:
        return {"decision": "deny", "reason": reason, "grantDigest": None, "chain": []}
    verdict = verify_call_under_grant(leaf, tool, args, ctx)
    decision = {"ok": "allow", "approval_required": "needs_approval"}.get(verdict, "deny")
    return {"decision": decision, "reason": verdict, "grantDigest": grant_digest(leaf),
            "chain": [grant_digest(g["body"]) for g in chain]}


def grant_evidence(chain: list[Mapping[str, Any]], args: Any, ctx: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """What a tool-call record carries so an outsider re-runs the grant check offline."""
    return {"argsB64": _b64(canonical(args)), "chain": [dict(g) for g in chain], "kind": "grant",
            "ctx": dict(ctx or {}), "grantDigest": grant_digest(chain[-1]["body"])}


def spend_of(budget: Mapping[str, Any] | None, args: Any) -> float:
    """What one call spends against a budget's ``spend`` axis (0 when it has none)."""
    if not budget or "spend" not in budget or not isinstance(args, dict):
        return 0
    value = args.get(budget["spend"]["arg"], 0)
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else float("inf")
