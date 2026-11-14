"""Grant to effect, offline: the chain of authority behind one effect, link by link.

``grant_walk`` takes a verified journal's statements and one permit id and returns every hop an
auditor needs: the grant chain (root to leaf, by digest), the authorize record that minted the
permit under the leaf grant, the intent record that let the call leave the worker, and the effect
record with its outcome. Each link is checked against the next: the permit names the leaf grant, the
intent and effect name the same permit and the same grant, and the arguments digest is the same at
every hop. A missing or disagreeing link is named, never skipped.

Run ``verify_journal`` first: the walk reads statements, it does not re-verify signatures.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from .core import sign_permit, Signer
from .grants import grant_digest
from .records import TOOL_CALL_RECORD


def grant_permit_claims(*, permit: str, tool: str, args_sha256_hex: str, chain: list[Mapping[str, Any]],
                        ctx: Mapping[str, Any], issued_at: str, revocation_seq: int | None = None) -> dict[str, Any]:
    """The claims of a permit minted under a grant: the leaf grant digest, every ancestor's digest,
    and the call context (workflow, run, call id) the grant's context constraints were checked on."""
    return {"argsSha256": args_sha256_hex, "ctx": dict(ctx), "grantChain": [grant_digest(g["body"]) for g in chain],
            "grantDigest": grant_digest(chain[-1]["body"]), "issuedAt": issued_at, "permitId": permit,
            "revocationSeq": revocation_seq, "tool": tool}


def mint_grant_permit(authority: Signer, **claims: Any) -> dict[str, Any]:
    """A permit signed by the authority over ``grant_permit_claims``."""
    return sign_permit(authority, grant_permit_claims(**claims))


def grant_walk(statements: Iterable[Mapping[str, Any]], permit: str) -> dict[str, Any]:
    """``{"ok", "problems", "grantChain", "grantDigest", "authorize", "intent", "effect", "outcome"}``.

    ``authorize``, ``intent`` and ``effect`` are the journal ``seq`` of each hop (None when absent).
    """
    problems: list[str] = []
    hops: dict[str, Mapping[str, Any]] = {}
    for body in statements:
        if body.get("predicateType") != TOOL_CALL_RECORD:
            continue
        pred = body.get("predicate", {})
        if pred.get("permitId") != permit:
            continue
        phase = pred.get("phase")
        if phase == "authorize" and pred.get("decision") == "allow":
            hops.setdefault("authorize", pred)
        elif phase in ("intent", "effect"):
            hops[phase] = pred
    allow = hops.get("authorize")
    chain: list[str] = []
    leaf = None
    if allow is None:
        problems.append("no_allow_for_permit")
    else:
        evidence = allow.get("authority") or {}
        if evidence.get("kind") != "grant":
            problems.append("allow_not_under_a_grant")
        else:
            chain = [grant_digest(g["body"]) for g in evidence.get("chain", [])]
            leaf = chain[-1] if chain else None
            if leaf != allow.get("grantDigest") or leaf != evidence.get("grantDigest"):
                problems.append("permit_grant_is_not_the_leaf")
            for depth in range(1, len(chain)):
                if evidence["chain"][depth]["body"].get("parent") != chain[depth - 1]:
                    problems.append(f"chain_parent_link_broken:{depth}")
    for phase in ("intent", "effect"):
        pred = hops.get(phase)
        if pred is None:
            problems.append(f"no_{phase}_record")
            continue
        if allow is not None and pred.get("grantDigest") != allow.get("grantDigest"):
            problems.append(f"{phase}_names_another_grant")
        if allow is not None and pred.get("argsSha256") != allow.get("argsSha256"):
            problems.append(f"{phase}_arguments_differ")
    effect = hops.get("effect")
    return {"ok": not problems, "problems": problems, "grantChain": chain, "grantDigest": leaf,
            "authorize": allow.get("seq") if allow else None,
            "intent": hops["intent"].get("seq") if "intent" in hops else None,
            "effect": effect.get("seq") if effect else None,
            "outcome": effect.get("outcome") if effect else None}
