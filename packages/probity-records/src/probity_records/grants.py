"""Signed capability grants: task-scoped authority checked per call, with no human per call.

A grant names the tools its holder may call and, per tool, a constraint on every argument it
admits. Arguments are closed-world: a call carrying an argument the grant does not name is refused.
A holder may delegate a child grant signed with its own key; the child must narrow the parent on
every axis (tools, arguments, constraint, window, approval requirement), and the verifier proves
that, so authority can only shrink down a chain.

Grant body::

    {"grantId": str, "issuerKey": b64 raw Ed25519, "holderKey": b64 raw Ed25519,
     "parent": sha256 hex of the parent body or None, "notBefore": iso, "expiresAt": iso,
     "tools": {tool: {"args": {name: constraint}, "approval": "none" | "required"}}}

The grant digest (SHA-256 of the JCS body) goes into the permit claims (``grantDigest``) and into
the tool-call record, so an outsider re-runs the whole check offline from the record alone.
"""

from __future__ import annotations

import base64
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from cryptography.exceptions import InvalidSignature

from . import constraints
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


def issue_grant(issuer: Signer, *, grant_id: str, holder_key: str, tools: Mapping[str, Any],
                not_before: str, expires_at: str, parent: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Sign a grant. With ``parent`` (a signed grant), ``issuer`` must be the parent's holder and the
    new grant must narrow it; both are checked here and again by every verifier."""
    body = {"expiresAt": expires_at, "grantId": grant_id, "holderKey": holder_key,
            "issuerKey": raw_public(issuer), "notBefore": not_before,
            "parent": grant_digest(parent["body"]) if parent else None, "tools": dict(tools)}
    _validate_tools(body["tools"])
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
    for tool, spec in child["tools"].items():
        pspec = parent["tools"].get(tool)
        if pspec is None:
            return f"child_adds_tool:{tool}"
        if pspec.get("approval", "none") == "required" and spec.get("approval", "none") != "required":
            return f"child_drops_approval:{tool}"
        for name, c in spec["args"].items():
            if name not in pspec["args"]:
                return f"child_adds_argument:{tool}.{name}"
            if not constraints.narrows(c, pspec["args"][name]):
                return f"child_widens_constraint:{tool}.{name}"
    return None


def _verify_sig(signed: Mapping[str, Any], raw_key_b64: str) -> bool:
    try:
        load_public(_unb64(raw_key_b64)).verify(_unb64(signed.get("sig")), GRANT_DOMAIN + canonical(signed["body"]))
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


def verify_chain(chain: list[Mapping[str, Any]], root_key_ids: set[str], at: str,
                 revoked_grants: set[str] | None = None,
                 key_revoked: Any = None) -> tuple[dict[str, Any] | None, str]:
    """Verify a root-to-leaf grant chain at time ``at``.

    Returns ``(leaf_body, "ok")`` or ``(None, reason)``. ``root_key_ids`` are the key ids of the
    trusted grant issuers. A revoked grant anywhere in the chain revokes every descendant.
    ``key_revoked(key_id, at) -> bool`` reports signer keys revoked at that time.
    """
    if not chain:
        return None, "grant_chain_empty"
    revoked_grants = revoked_grants or set()
    when = ts(at)
    prev: Mapping[str, Any] | None = None
    for depth, signed in enumerate(chain):
        body = signed.get("body") if isinstance(signed, Mapping) else None
        if not isinstance(body, dict):
            return None, f"grant_shape:{depth}"
        try:
            _validate_tools(body.get("tools"))
            issuer_id = key_id(load_public(base64.b64decode(body["issuerKey"])))
        except (ValueError, KeyError, TypeError) as exc:
            return None, f"grant_invalid:{depth}:{exc}"
        if not _verify_sig(signed, body["issuerKey"]):
            return None, f"grant_signature_unverified:{depth}"
        if key_revoked is not None and key_revoked(issuer_id, at):
            return None, f"grant_issuer_key_revoked:{depth}"
        if grant_digest(body) in revoked_grants:
            return None, f"grant_revoked:{depth}"
        if prev is None:
            if body.get("parent") is not None or issuer_id not in root_key_ids:
                return None, "grant_root_untrusted"
        else:
            if body.get("parent") != grant_digest(prev):
                return None, f"grant_parent_mismatch:{depth}"
            problem = narrowing_problem(body, prev)
            if problem:
                return None, f"{problem}:{depth}"
        if not ts(body["notBefore"]) <= when <= ts(body["expiresAt"]):
            return None, f"grant_outside_window:{depth}"
        prev = body
    assert prev is not None
    return dict(prev), "ok"


def check_call(leaf: Mapping[str, Any], tool: str, args: Any) -> str:
    """``ok``, ``approval_required``, or the refusal reason for one call under the leaf grant."""
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
    return "approval_required" if spec.get("approval", "none") == "required" else "ok"


def authorize(chain: list[Mapping[str, Any]], tool: str, args: Any, at: str, root_key_ids: set[str],
              revoked_grants: set[str] | None = None, key_revoked: Any = None) -> dict[str, Any]:
    """The decision for one call under a grant chain: ``{"decision", "reason", "grantDigest"}``.

    ``decision`` is ``allow`` (no human needed), ``needs_approval`` or ``deny``.
    """
    leaf, reason = verify_chain(chain, root_key_ids, at, revoked_grants, key_revoked)
    if leaf is None:
        return {"decision": "deny", "reason": reason, "grantDigest": None}
    verdict = check_call(leaf, tool, args)
    decision = {"ok": "allow", "approval_required": "needs_approval"}.get(verdict, "deny")
    return {"decision": decision, "reason": verdict, "grantDigest": grant_digest(leaf)}


def grant_evidence(chain: list[Mapping[str, Any]], args: Any) -> dict[str, Any]:
    """What a tool-call record carries so an outsider re-runs the grant check offline."""
    return {"argsB64": _b64(canonical(args)), "chain": [dict(g) for g in chain], "kind": "grant",
            "grantDigest": grant_digest(chain[-1]["body"])}
