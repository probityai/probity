"""Signed capability grants: task-scoped authority checked per call, with no human per call.

A grant names the tools its holder may call and, per tool, a constraint on every argument it
admits. Arguments are closed-world: a call carrying an argument the grant does not name is refused.
A holder may delegate a child grant signed with its own key; the child must narrow the parent on
every axis (tools, arguments, constraint, window, approval requirement), and the verifier proves
that, so authority can only shrink down a chain.

Grant body::

    {"grantId": str, "issuerKey": b64 raw Ed25519, "holderKey": b64 raw Ed25519,
     "cnf": {"jkt": RFC 7638 thumbprint} | {"x5t#S256": certificate thumbprint},   # RFC 7800 confirmation
     "parent": sha256 hex of the parent body or None, "notBefore": time, "expiresAt": time,
     "maxDepth": int,                       # further delegations allowed below this grant
     "context": {key: constraint},          # the call context the permit names (workflowId, runId, agent...)
     "budget": {"uses": int, "spend": {"arg": name, "max": number}},   # optional, both parts optional
     "tools": {tool: {"args": {name: constraint}, "approval": "none" | "required",
                      "when": [CEL expression over args, tool, ctx],
                      "quorum": approval policy (see quorum.py)}},
     "sponsor": {"issuer": https URL, "subject": str},   # optional, with reviewBy: a standing grant
     "reviewBy": time}                                   # notBefore < reviewBy <= expiresAt

Every ``time`` is an RFC 3339 date-time with an explicit offset, in the one grammar both verifiers parse (``ts``):
``YYYY-MM-DDTHH:MM:SS``, up to six fraction digits, then ``Z`` or ``+HH:MM`` / ``-HH:MM``. A time with no offset names
no instant, so a body carrying one is refused (``grant_timestamp_offset_missing``), and any other form is refused
(``grant_timestamp_invalid``): a verifier never guesses a zone and never throws on a grant it was handed.

A standing grant is the authority an agent holds with no person in its session: it names the ``sponsor`` who
answers for it and the instant (``reviewBy``) by which a person must review it. The two members come together or
not at all. From ``reviewBy`` on, the grant and every grant delegated under it admit nothing
(``grant_review_overdue``); a review is a fresh issue with a later ``reviewBy``. A child of a standing grant keeps
its sponsor and reviews no later; a child of a plain grant never becomes one (``child_adds_sponsor``): who answers
for a standing grant is named by the pinned root that issues it, never by a delegate.

``holderKey`` signs the child grants its holder delegates. ``cnf`` names the key that presents the grant on a
request (a DPoP key or a TLS client certificate, possibly the same key as ``holderKey``); the verifier accepts
a presentation only with proof of possession of that key (``possession.check_possession``), and an allow record
carries the proof it rested on (``grant_evidence(..., possession=...)``). A grant without ``cnf`` would be a
bearer token, so none can be issued or verified.

Every axis narrows down a chain: tools, arguments, constraints, window, review date, sponsor, depth, context, budget,
``when`` conditions (a child keeps every parent condition and may add more) and the approval
requirement (a child keeps every parent approver and threshold and may add more: add-only).

A budget is shared down the chain: every use under a descendant also spends from every ancestor, so
two children of a ten-use grant cannot spend twenty. The verifier re-counts spend from the journal.

The grant digest (SHA-256 of the JCS body) goes into the permit claims (``grantDigest``), into the
authorize, intent and effect records, so an outsider walks grant to permit to effect offline.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature

from . import celexpr, constraints
from .core import Signer, _b64, canonical, key_id, load_public, sha256_hex, unb64
from .identifiers import identifier

GRANT_DOMAIN = b"probity-grant-v1\x00"
CAPABILITY_GRANT = identifier("agent-evidence-vectors/predicate/v1/capability-grant")
APPROVAL_LEVELS = ("none", "required")


#: The one timestamp grammar (``grammar/timestamp.json``: RFC 3339 section 5.6 date-time, at most microseconds, years
#: 0001 to 9999), the same as ``ts`` in the TypeScript verifier. The digits are 0 to 9 only: ``\d`` in a Python
#: pattern also matches the digits of every other script, and ``int`` reads them, so one instant would have many
#: spellings. The offset group is optional here only so that its absence is named, never accepted.
TIMESTAMP = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,6}))?(Z|[+-][0-9]{2}:[0-9]{2})?")
_DECIMAL = re.compile(r"[0-9]{1,15}")
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_MICROSECOND = timedelta(microseconds=1)


def decimal(text: str) -> int:
    """The number a run of the digits 0 to 9 writes (at most 15 of them); ``ValueError`` for any other text.

    Every number a reader takes from received text comes through here, after the text matched its grammar: ``int`` alone
    also reads other scripts' digits, a sign, spaces and underscores, and refuses a run of more than 4300 digits."""
    if not isinstance(text, str) or not _DECIMAL.fullmatch(text):
        raise ValueError("not_decimal_digits")
    return int(text)


def micros_of(moment: datetime) -> int:
    """An aware datetime as integer microseconds since 1970-01-01T00:00:00Z, exactly (``timestamp()`` is a float)."""
    return (moment - _EPOCH) // _MICROSECOND


def micros(text: Any) -> int:
    """The instant an RFC 3339 timestamp names, as integer microseconds since the epoch; ``ValueError`` as ``ts``."""
    return micros_of(ts(text))


def ts(text: Any) -> datetime:
    """The instant an RFC 3339 timestamp names, as an aware datetime.

    ValueError ``grant_timestamp_offset_missing`` for a date-time with no offset (it names no instant), and
    ``grant_timestamp_invalid`` for anything else outside the grammar, including a field out of range (month 13, hour 24,
    second 60): ``datetime.fromisoformat`` accepts forms the TypeScript verifier refuses, so it is not used."""
    m = TIMESTAMP.fullmatch(text) if isinstance(text, str) else None
    if m is None:
        raise ValueError("grant_timestamp_invalid")
    year, month, day, hour, minute, second, fraction, offset = m.groups()
    if offset is None:
        raise ValueError("grant_timestamp_offset_missing")
    if offset == "Z":
        zone = UTC
    else:
        hours, minutes = decimal(offset[1:3]), decimal(offset[4:6])
        if hours > 23 or minutes > 59:
            raise ValueError("grant_timestamp_invalid")
        zone = timezone((-1 if offset[0] == "-" else 1) * timedelta(hours=hours, minutes=minutes))
    try:
        return datetime(decimal(year), decimal(month), decimal(day), decimal(hour), decimal(minute), decimal(second),
                        decimal((fraction or "").ljust(6, "0")), zone)
    except ValueError:
        raise ValueError("grant_timestamp_invalid") from None


def _validate_times(body: Mapping[str, Any]) -> None:
    """Every instant a grant names parses as one (``ts``); ValueError ``<code>:<member>`` for the first that does not."""
    members = ("notBefore", "expiresAt", "reviewBy") if "reviewBy" in body else ("notBefore", "expiresAt")
    for member in members:
        try:
            ts(body.get(member))
        except ValueError as exc:
            raise ValueError(f"{exc}:{member}") from None


def raw_public(signer: Signer) -> str:
    """The base64 raw public key a grant names as issuer or holder."""
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

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
    if "spend" in budget and (not isinstance(spend, dict) or set(spend) != {"arg", "max"}
                              or not isinstance(spend["arg"], str)
                              or not isinstance(spend["max"], (int, float)) or isinstance(spend["max"], bool)
                              or spend["max"] < 0):  # a null spend is refused: narrowing and spend_of read its members
        raise ValueError("grant_budget_spend")


def _validate_tools(tools: Any) -> None:
    """Every tool entry, in code point order of the tool names (and of the argument names inside one), so both
    verifiers name the same defect first whatever order the JSON members were written in."""
    if not isinstance(tools, dict) or not tools:
        raise ValueError("grant_tools_empty")
    for tool in sorted(tools):
        spec = tools[tool]
        if not isinstance(spec, dict) or not isinstance(spec.get("args"), dict):
            raise ValueError(f"grant_tool_shape:{tool}")
        if spec.get("approval", "none") not in APPROVAL_LEVELS:
            raise ValueError(f"grant_approval_level:{tool}")
        for arg in sorted(spec["args"]):
            found = constraints.problem(spec["args"][arg])
            if found:
                raise ValueError(f"grant_arg_constraint_invalid:{tool}.{arg}:{found}")
        when = spec.get("when", [])
        if not isinstance(when, list) or not all(isinstance(w, str) for w in when):
            raise ValueError(f"grant_when_shape:{tool}")
        for n, w in enumerate(when):
            found = celexpr.syntax_problem(w)
            if found:
                raise ValueError(f"grant_when_invalid:{tool}.{n}:{found}")
        if "quorum" in spec:
            from .quorum import policy_problem

            found = policy_problem(spec["quorum"])
            if found:
                raise ValueError(f"grant_quorum_invalid:{tool}:{found}")
            if not spec["quorum"].get("proposerBound"):
                raise ValueError(f"grant_quorum_must_bind_proposer:{tool}")
            if spec.get("approval") != "required":
                raise ValueError(f"grant_quorum_without_required_approval:{tool}")


def _issuer_key_ok(text: Any) -> bool:
    """``issuerKey`` is the canonical base64 of a 32-byte raw Ed25519 public key (the one the signature names)."""
    try:
        raw = unb64(text)
        load_public(raw)
    except (ValueError, TypeError):
        return False
    return len(raw) == 32


def _validate_standing(body: Mapping[str, Any]) -> None:
    if ("sponsor" in body) != ("reviewBy" in body):
        raise ValueError("grant_standing_incomplete")
    if "sponsor" not in body:
        return
    sponsor = body["sponsor"]
    if (not isinstance(sponsor, dict) or set(sponsor) != {"issuer", "subject"}
            or not all(isinstance(v, str) and v for v in sponsor.values())):  # fmt: skip
        raise ValueError("grant_sponsor_invalid")
    from .identity import sponsor_id

    try:
        sponsor_id(sponsor["issuer"], sponsor["subject"])
    except ValueError:
        raise ValueError("grant_sponsor_invalid") from None
    if not ts(body["notBefore"]) < ts(body["reviewBy"]) <= ts(body["expiresAt"]):  # each parsed by _validate_times
        raise ValueError("grant_review_invalid")


def validate_body(body: Mapping[str, Any]) -> None:
    """Shape of a grant body on every axis; ValueError naming the first defect, in this order: ``cnf``, the times,
    the tools, ``maxDepth``, ``context``, ``budget``, the standing members, ``issuerKey``. The TypeScript verifier's
    ``bodyProblem`` is this function, code for code; the shared vectors in ``grant_bodies.json`` hold the two to it."""
    from .possession import cnf_problem

    problem = cnf_problem(body.get("cnf"))
    if problem:
        raise ValueError(problem)
    _validate_times(body)
    _validate_tools(body.get("tools"))
    if not _int(body.get("maxDepth")):
        raise ValueError("grant_max_depth")
    ctx = body.get("context")
    if not isinstance(ctx, dict):
        raise ValueError("grant_context_shape")
    for key in sorted(ctx):
        found = constraints.problem(ctx[key])
        if found:
            raise ValueError(f"grant_context_constraint_invalid:{key}:{found}")
    _validate_budget(body.get("budget"))
    _validate_standing(body)
    if not _issuer_key_ok(body.get("issuerKey")):
        raise ValueError("grant_issuer_key_invalid")


def body_problem(body: Any) -> str | None:
    """None for a well-formed grant body; otherwise the code ``validate_body`` names (``grant_shape`` when it is not
    an object)."""
    if not isinstance(body, dict):
        return "grant_shape"
    try:
        validate_body(body)
    except ValueError as exc:
        return str(exc)
    return None


def _typecheck_conditions(body: Mapping[str, Any]) -> None:
    """The issuer's own check, beyond what a verifier runs: every CEL expression the grant signs type-checks under
    cel-cpp, so an issuer never signs a condition that can never hold. ValueError ``<where>:cel_type_check_failed``."""
    def exprs(c: Any) -> list[str]:
        if c["type"] == "cel":
            return [c["expr"]]
        nested = c["of"] if c["type"] in ("all", "any") else [c["of"]] if c["type"] == "not" else []
        return [e for x in nested for e in exprs(x)]

    sites = [(f"grant_context_constraint_invalid:{k}", e) for k in sorted(body["context"]) for e in exprs(body["context"][k])]
    for tool in sorted(body["tools"]):
        spec = body["tools"][tool]
        sites += [(f"grant_arg_constraint_invalid:{tool}.{a}", e) for a in sorted(spec["args"]) for e in exprs(spec["args"][a])]
        sites += [(f"grant_when_invalid:{tool}.{n}", w) for n, w in enumerate(spec.get("when", []))]
    for where, expr in sites:
        try:
            celexpr.compile_expr(expr)
        except ValueError as exc:
            raise ValueError(f"{where}:{exc}") from None


def is_standing(body: Mapping[str, Any]) -> bool:
    """Whether a grant body is a standing grant: it names a sponsor and a review date."""
    return "sponsor" in body and "reviewBy" in body


def issue_grant(issuer: Signer, *, grant_id: str, holder_key: str, cnf: Mapping[str, str], tools: Mapping[str, Any],
                not_before: str, expires_at: str, parent: Mapping[str, Any] | None = None,
                max_depth: int | None = None, context: Mapping[str, Any] | None = None,
                budget: Mapping[str, Any] | None = None, sponsor: Mapping[str, str] | None = None,
                review_by: str | None = None) -> dict[str, Any]:
    """Sign a grant held by ``holder_key`` and presented by the key ``cnf`` confirms (see
    ``possession.cnf_for_jwk``, ``cnf_for_certificate``, ``cnf_for_signer``). With ``parent`` (a signed grant),
    ``issuer`` must be the parent's holder and the
    new grant must narrow it; both are checked here and again by every verifier. ``max_depth``
    defaults to 0 (no further delegation) for a child, and to 0 for a root unless given. ``sponsor`` and
    ``review_by`` together make it a standing grant (see the module docstring)."""
    body = {"cnf": dict(cnf), "context": dict(context or {}), "expiresAt": expires_at, "grantId": grant_id,
            "holderKey": holder_key, "issuerKey": raw_public(issuer),
            "maxDepth": 0 if max_depth is None else max_depth, "notBefore": not_before,
            "parent": grant_digest(parent["body"]) if parent else None, "tools": dict(tools)}
    if budget is not None:
        body["budget"] = dict(budget)
    if sponsor is not None:
        body["sponsor"] = dict(sponsor)
    if review_by is not None:
        body["reviewBy"] = review_by
    validate_body(body)
    _typecheck_conditions(body)
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
    if "sponsor" in parent:
        if child.get("sponsor") != parent["sponsor"]:
            return "child_changes_sponsor"
        if ts(child["reviewBy"]) > ts(parent["reviewBy"]):
            return "child_review_later_than_parent"
    elif "sponsor" in child:
        return "child_adds_sponsor"
    if parent.get("maxDepth", 0) < 1:
        return "parent_forbids_delegation"
    if child.get("maxDepth", 0) > parent["maxDepth"] - 1:
        return "child_depth_wider_than_parent"
    for key in sorted(parent.get("context", {})):
        c = parent["context"][key]
        if key not in child.get("context", {}):
            return f"child_drops_context:{key}"
        if not constraints.narrows(child["context"][key], c):
            return f"child_widens_context:{key}"
    problem = _budget_narrowing(child.get("budget"), parent.get("budget"))
    if problem:
        return problem
    for tool in sorted(child["tools"]):  # code point order, as in validate_body and the TypeScript verifier
        spec = child["tools"][tool]
        pspec = parent["tools"].get(tool)
        if pspec is None:
            return f"child_adds_tool:{tool}"
        if pspec.get("approval", "none") == "required" and spec.get("approval", "none") != "required":
            return f"child_drops_approval:{tool}"
        missing = [w for w in pspec.get("when", []) if w not in spec.get("when", [])]
        if missing:
            return f"child_drops_condition:{tool}"
        if "quorum" in pspec:
            from .quorum import widening_problem

            problem = widening_problem(spec.get("quorum"), pspec["quorum"])
            if problem:
                return f"{problem}:{tool}"
        added = sorted(set(spec["args"]) - set(pspec["args"]))
        if added:
            return f"child_adds_argument:{tool}.{added[0]}"
        dropped = sorted(set(pspec["args"]) - set(spec["args"]))
        if dropped:  # a call without the argument would leave it to the tool's default, unbounded
            return f"child_drops_argument:{tool}.{dropped[0]}"
        for name in sorted(spec["args"]):
            if not constraints.narrows(spec["args"][name], pspec["args"][name]):
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
        load_public(unb64(raw_key_b64)).verify(unb64(signed.get("sig")), GRANT_DOMAIN + canonical(signed["body"]))
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


_STRUCTURE: dict[tuple[str, frozenset[str]], tuple[tuple[str, ...], tuple[str, ...], str]] = {}
_STRUCTURE_MAX = 4096


def _structure(chain: list[Mapping[str, Any]], root_key_ids: frozenset[str]) -> tuple[tuple[str, ...], tuple[str, ...], str]:
    """The time-independent half of a chain check: shapes, signatures, root trust, parent links and
    the narrowing proof. Returns (issuer key ids, grant digests, "ok" or the refusal). Memoised on
    the exact chain content and the pinned roots, so an altered byte anywhere misses the cache."""
    import json

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
            issuer_id = key_id(load_public(unb64(body["issuerKey"])))
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
    try:
        when = ts(at)
    except ValueError:
        return None, "grant_use_time_invalid"
    revoked_grants = revoked_grants or set()
    issuers, digests, result = _structure(chain, frozenset(root_key_ids))
    for depth, (issuer_id, digest) in enumerate(zip(issuers, digests, strict=True)):
        if key_revoked is not None and key_revoked(issuer_id, at):
            return None, f"grant_issuer_key_revoked:{depth}"
        if digest in revoked_grants:
            return None, f"grant_revoked:{depth}"
        body = chain[depth]["body"]
        if not ts(body["notBefore"]) <= when <= ts(body["expiresAt"]):
            return None, f"grant_outside_window:{depth}"
        if "reviewBy" in body and when >= ts(body["reviewBy"]):
            return None, f"grant_review_overdue:{depth}"
    if result != "ok":
        return None, result
    return dict(chain[-1]["body"]), "ok"


def chain_problem(chain: list[Mapping[str, Any]], root_key_ids: set[str] | frozenset[str]) -> str | None:
    """None when ``chain`` is a well-formed chain rooted in a pinned issuer whose every link verifies and narrows
    its parent; otherwise the first defect. Time-independent: the window, the review date and revocation are
    judged per use (``verify_chain``)."""
    if not chain:
        return "grant_chain_empty"
    _, _, result = _structure(chain, frozenset(root_key_ids))
    return None if result == "ok" else result


def chain_digests(chain: list[Mapping[str, Any]], root_key_ids: set[str] | frozenset[str]) -> dict[str, dict[str, Any]]:
    """Every grant body of a structurally verified chain, by digest; empty when the chain does not verify."""
    if not chain:
        return {}
    _, digests, result = _structure(chain, frozenset(root_key_ids))
    if result != "ok":
        return {}
    return {d: dict(signed["body"]) for d, signed in zip(digests, chain, strict=True)}


def verify_call_under_grant(leaf: Mapping[str, Any], tool: str, args: Any, ctx: Mapping[str, Any] | None = None) -> str:
    """``ok``, ``approval_required``, or the refusal reason for one call under the leaf grant.

    ``ctx`` is the call context the permit names; every context key the grant constrains must be
    present and satisfy its constraint (the chain proof makes the leaf at least as strict as every
    ancestor, so the leaf alone decides)."""
    ctx = dict(ctx or {})
    for key in sorted(leaf.get("context", {})):
        c = leaf["context"][key]
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
    for name in sorted(spec["args"]):
        if not constraints.check(spec["args"][name], args.get(name)):
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


def grant_evidence(chain: list[Mapping[str, Any]], args: Any, ctx: Mapping[str, Any] | None = None,
                   possession: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """What a tool-call record carries so an outsider re-runs the grant check offline. ``possession`` is the
    record of the proof the presenter gave (``possession.possession_record``): the verifier checks it names the
    leaf grant's ``cnf`` and that no other permit spent the same DPoP proof inside its lifetime."""
    evidence = {"argsB64": _b64(canonical(args)), "chain": [dict(g) for g in chain], "kind": "grant",
                "ctx": dict(ctx or {}), "grantDigest": grant_digest(chain[-1]["body"])}
    if possession is not None:
        evidence["possession"] = dict(possession)
    return evidence


def spend_of(budget: Mapping[str, Any] | None, args: Any) -> float:
    """What one call spends against a budget's ``spend`` axis (0 when it has none)."""
    if not budget or "spend" not in budget or not isinstance(args, dict):
        return 0
    value = args.get(budget["spend"]["arg"], 0)
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else float("inf")
