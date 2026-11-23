"""Conformance vectors for the grant body grammar (``grants.validate_body``) and for the per-call check.

``bodies()`` gives ``{"id", "description", "body", "expected"}``: ``expected`` is null for a body every verifier
admits, or the refusal code ``validate_body`` names (the TypeScript verifier's ``bodyProblem`` names the same). One
case per axis (tools, approval level, argument and context constraints, conditions, quorum, depth, context, budget,
issuer key, the order of the axes), plus every input on which the two verifiers once disagreed.

``calls()`` gives ``{"id", "description", "chain", "roots", "tool", "args", "ctx", "at", "expected"}``, ``expected``
being ``{"decision", "reason"}`` of ``verify_grant_allow``: tool names a JavaScript object inherits, and the order in
which several failing members are judged.

The JSON is written with ``json.dumps``, not canonicalised, so ``1.0`` stays a float: read it with a parser that keeps
that distinction (``parsePy`` in the TypeScript verifier).
"""

from __future__ import annotations

import copy
import hashlib
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .core import Signer, _b64
from .grants import issue_grant, raw_public
from .possession import cnf_for_signer

NB, EXP, AT = "2026-01-01T00:00:00Z", "2099-12-31T00:00:00Z", "2026-06-01T00:00:00Z"


def _key(name: str) -> Signer:
    return Signer(Ed25519PrivateKey.from_private_bytes(hashlib.sha256(f"probity-grant-body/{name}".encode()).digest()))


ROOT, AGENT, OPS = _key("root"), _key("agent"), _key("ops")
TOOLS: dict[str, Any] = {"refund": {"approval": "none", "when": ["args.amount_cents < 3000 || args.currency == 'USD'"],
                                    "args": {"amount_cents": {"type": "range", "min": 1, "max": 4000},
                                             "currency": {"type": "one_of", "values": ["USD", "EUR"]}}}}
QUORUM = {"approvers": {"ops": raw_public(OPS)}, "policyId": "pay", "proposerBound": True, "threshold": 1}


def base() -> dict[str, Any]:
    """A well-formed root grant body with a context, a budget and a condition."""
    return issue_grant(ROOT, grant_id="g-root", holder_key=raw_public(AGENT), cnf=cnf_for_signer(AGENT),
                       tools=copy.deepcopy(TOOLS), not_before=NB, expires_at=EXP, max_depth=1,
                       context={"workflowId": {"type": "pattern", "pattern": "refunds-*"}},
                       budget={"uses": 5, "spend": {"arg": "amount_cents", "max": 10000}})["body"]


def _with(**members: Any) -> dict[str, Any]:
    body = base()
    for name, value in members.items():
        if value is _DROP:
            del body[name]
        else:
            body[name] = value
    return body


_DROP = object()


def _arg(constraint: Any) -> dict[str, Any]:
    body = base()
    body["tools"]["refund"]["args"]["amount_cents"] = constraint
    return body


def _tool(**members: Any) -> dict[str, Any]:
    body = base()
    spec = body["tools"]["refund"]
    for name, value in members.items():
        if value is _DROP:
            del spec[name]
        else:
            spec[name] = value
    return body


def _when(expr: Any) -> dict[str, Any]:
    return _tool(when=[expr])


def _budget(budget: Any) -> dict[str, Any]:
    return _with(budget=budget)


ARG = "grant_arg_constraint_invalid:refund.amount_cents:"
WHEN = "grant_when_invalid:refund.0:"
QUORUM_BAD = "grant_quorum_invalid:refund:"
SPEC = {"args": {}, "approval": "none"}


def bodies() -> list[dict[str, Any]]:
    loose_key = base()["issuerKey"][:-2] + "B="  # the unused low bits of the last digit set: decodes, not canonical
    cases: list[tuple[str, str, dict[str, Any], str | None]] = [
        ("GB01", "a well-formed body", base(), None),
        ("GB02", "no tools member", _with(tools=_DROP), "grant_tools_empty"),
        ("GB03", "an empty tools object", _with(tools={}), "grant_tools_empty"),
        ("GB04", "a tool entry that is not an object", _with(tools={"refund": ["args"]}), "grant_tool_shape:refund"),
        ("GB05", "a tool entry with no args object", _tool(args=_DROP), "grant_tool_shape:refund"),
        ("GB06", "an approval level outside none and required", _tool(approval="maybe"),
         "grant_approval_level:refund"),
        ("GB07", "a null approval level, which a reader that defaults null to none would admit", _tool(approval=None),
         "grant_approval_level:refund"),
        ("GB08", "an argument constraint of unknown type", _arg({"type": "money"}), ARG + "constraint_unknown"),
        ("GB09", "a constraint type written as a one-element list, which JavaScript's in operator reads as its text",
         _arg({"type": ["range"], "min": 1}), ARG + "constraint_unknown"),
        ("GB10", "a constraint type that names an inherited JavaScript property", _arg({"type": "toString"}),
         ARG + "constraint_unknown"),
        ("GB11", "an exact constraint with no value", _arg({"type": "exact"}), ARG + "constraint_member_missing:exact.value"),
        ("GB12", "a range with neither bound", _arg({"type": "range"}), ARG + "constraint_range_unbounded"),
        ("GB13", "a range whose min is text", _arg({"type": "range", "min": "1"}),
         ARG + "constraint_member_invalid:range.min"),
        ("GB14", "a one_of whose values is text, which Python would search as a substring",
         _arg({"type": "one_of", "values": "USD"}), ARG + "constraint_member_invalid:one_of.values"),
        ("GB15", "a regex that does not compile", _arg({"type": "regex", "regex": "("}), ARG + "constraint_regex_invalid"),
        ("GB16", "a cidr network with host bits set", _arg({"type": "cidr", "network": "10.0.0.1/8"}),
         ARG + "constraint_cidr_invalid"),
        ("GB17", "a cidr network written as a number, which Python's ip_network reads as an address",
         _arg({"type": "cidr", "network": 5}), ARG + "constraint_member_invalid:cidr.network"),
        ("GB18", "a cel constraint that does not parse", _arg({"type": "cel", "expr": "value =="}),
         ARG + "cel_syntax_invalid"),
        ("GB19", "a defect inside an all constraint", _arg({"type": "all", "of": [{"type": "range", "min": 1}, {"type": "range"}]}),
         ARG + "constraint_range_unbounded"),
        ("GB20", "an all constraint over an empty list", _arg({"type": "all", "of": []}),
         ARG + "constraint_member_invalid:all.of"),
        ("GB21", "a url_pattern whose hosts list holds a number",
         _arg({"type": "url_pattern", "schemes": ["https"], "hosts": [443]}),
         ARG + "constraint_member_invalid:url_pattern.hosts"),
        ("GB22", "conditions that are not a list", _tool(when="args.amount_cents < 3000"), "grant_when_shape:refund"),
        ("GB23", "a condition that does not parse", _when("args.amount_cents <"), WHEN + "cel_syntax_invalid"),
        ("GB24", "a condition of only whitespace", _when(" \t\n"), WHEN + "cel_expression_empty"),
        ("GB25", "a has() over a variable, not a field: cel-cpp's parser refuses it", _when("has(args)"),
         WHEN + "cel_syntax_invalid"),
        ("GB26", "an integer literal beyond the signed 64-bit range", _when("args.amount_cents < 9223372036854775808"),
         WHEN + "cel_syntax_invalid"),
        ("GB27", "an unknown string escape", _when("args.currency == '\\z'"), WHEN + "cel_syntax_invalid"),
        ("GB28", "a one-digit octal escape", _when("args.currency == '\\0'"), WHEN + "cel_syntax_invalid"),
        ("GB29", "a \\u escape inside a bytes literal", _when("b'\\u00e9' == b''"), WHEN + "cel_syntax_invalid"),
        ("GB30", "a condition that ends in a comment with no newline: it parses", _when("args.amount_cents < 3000 // cap"),
         None),
        ("GB31", "a condition that parses but does not type-check: a verifier judges syntax only, and it never holds",
         _when("1 + 'a' == 2"), None),
        ("GB32", "a raw string keeps its backslash: it parses", _when("args.currency == r'\\z'"), None),
        ("GB62", "a condition holding a lone surrogate, which has no UTF-8 form", _when("args.currency == '\ud800'"),
         WHEN + "cel_syntax_invalid"),
        ("GB33", "a quorum that is not an object", _tool(approval="required", quorum=["ops"]),
         QUORUM_BAD + "quorum_policy_shape"),
        ("GB34", "a quorum threshold above its approver count", _tool(approval="required", quorum={**QUORUM, "threshold": 2}),
         QUORUM_BAD + "quorum_threshold_out_of_range"),
        ("GB35", "a quorum role written as a list", _tool(approval="required",
                                                         quorum={**QUORUM, "roles": {"finance": ["ops"]}}),
         QUORUM_BAD + "quorum_role_invalid:finance"),
        ("GB36", "a quorum approver whose key is a number", _tool(approval="required",
                                                                quorum={**QUORUM, "approvers": {"ops": 7}}),
         QUORUM_BAD + "quorum_approver_key_shape"),
        ("GB37", "a quorum that does not bind the proposer",
         _tool(approval="required", quorum={k: v for k, v in QUORUM.items() if k != "proposerBound"}),
         "grant_quorum_must_bind_proposer:refund"),
        ("GB38", "a quorum on a tool that requires no approval", _tool(quorum=QUORUM),
         "grant_quorum_without_required_approval:refund"),
        ("GB39", "two malformed tools written z before a: the first in code point order is named",
         _with(tools={"zeta": ["x"], "alpha": ["x"]}), "grant_tool_shape:alpha"),
        ("GB40", "two malformed tools, U+FFFF and U+1F600: code point order, not UTF-16 order, names U+FFFF first",
         _with(tools={"\U0001F600": ["x"], "￿": ["x"]}), "grant_tool_shape:￿"),
        ("GB41", "two malformed arguments written z before a",
         _tool(args={"zeta": {"type": "range"}, "alpha": {"type": "money"}}),
         "grant_arg_constraint_invalid:refund.alpha:constraint_unknown"),
        ("GB42", "no maxDepth", _with(maxDepth=_DROP), "grant_max_depth"),
        ("GB43", "a negative maxDepth", _with(maxDepth=-1), "grant_max_depth"),
        ("GB44", "a maxDepth written as a float", _with(maxDepth=1.0), "grant_max_depth"),
        ("GB45", "a maxDepth that is a boolean", _with(maxDepth=True), "grant_max_depth"),
        ("GB46", "no context member", _with(context=_DROP), "grant_context_shape"),
        ("GB47", "a context that is a list", _with(context=[]), "grant_context_shape"),
        ("GB48", "a malformed context constraint", _with(context={"workflowId": {"type": "glob"}}),
         "grant_context_constraint_invalid:workflowId:constraint_unknown"),
        ("GB49", "an empty budget", _budget({}), "grant_budget_shape"),
        ("GB50", "a budget with a member outside uses and spend", _budget({"uses": 2, "calls": 1}), "grant_budget_shape"),
        ("GB51", "a negative use count", _budget({"uses": -1}), "grant_budget_uses"),
        ("GB52", "a use count written as a float", _budget({"uses": 2.0}), "grant_budget_uses"),
        ("GB53", "a spend with no max", _budget({"spend": {"arg": "amount_cents"}}), "grant_budget_spend"),
        ("GB54", "a null spend, which narrowing and spend counting would read as an object", _budget({"spend": None}),
         "grant_budget_spend"),
        ("GB55", "a spend max that is a boolean", _budget({"spend": {"arg": "amount_cents", "max": True}}),
         "grant_budget_spend"),
        ("GB56", "a null budget is no budget", _budget(None), None),
        ("GB57", "no issuerKey", _with(issuerKey=_DROP), "grant_issuer_key_invalid"),
        ("GB58", "an issuerKey in non-canonical base64", _with(issuerKey=loose_key), "grant_issuer_key_invalid"),
        ("GB59", "an issuerKey of 31 bytes", _with(issuerKey=_b64(bytes(31))), "grant_issuer_key_invalid"),
        ("GB60", "a malformed budget and a sponsor with no review date: the budget is judged first",
         _with(budget={}, sponsor={"issuer": "https://idp.example.com", "subject": "ops"}), "grant_budget_shape"),
        ("GB61", "a malformed tool and a malformed budget: the tools are judged first",
         _with(tools={"refund": []}, budget={}), "grant_tool_shape:refund"),
    ]
    return [{"id": vid, "description": d, "body": body, "expected": expected} for vid, d, body, expected in cases]


def calls() -> list[dict[str, Any]]:
    signed = issue_grant(ROOT, grant_id="g-call", holder_key=raw_public(AGENT), cnf=cnf_for_signer(AGENT),
                         tools={"refund": {"args": {"zeta": {"type": "exact", "value": 1},
                                                    "alpha": {"type": "exact", "value": 1}}}},
                         not_before=NB, expires_at=EXP,
                         context={"zone": {"type": "exact", "value": "z"}, "area": {"type": "exact", "value": "a"}})
    chain, roots = [signed], [ROOT.key_id]
    good_ctx = {"zone": "z", "area": "a"}
    cases = [
        ("GC01", "a call every member admits", "refund", {"zeta": 1, "alpha": 1}, good_ctx, ("allow", "ok")),
        ("GC02", "a tool named constructor, which every JavaScript object inherits", "constructor", {}, good_ctx,
         ("deny", "tool_not_granted")),
        ("GC03", "a tool named __proto__", "__proto__", {}, good_ctx, ("deny", "tool_not_granted")),
        ("GC04", "two arguments outside their constraints, written z before a: a is named",
         "refund", {"zeta": 2, "alpha": 2}, good_ctx, ("deny", "constraint_violation:alpha")),
        ("GC05", "two context keys outside their constraints: area is named", "refund", {"zeta": 1, "alpha": 1},
         {"zone": "x", "area": "x"}, ("deny", "context_violation:area")),
    ]
    from .grants import verify_grant_allow

    out = []
    for vid, description, tool, args, ctx, (decision, reason) in cases:
        got = verify_grant_allow(chain, tool, args, AT, set(roots), ctx=ctx)
        assert (got["decision"], got["reason"]) == (decision, reason), (vid, got)
        out.append({"id": vid, "description": description, "chain": chain, "roots": roots, "tool": tool, "args": args,
                    "ctx": ctx, "at": AT, "expected": {"decision": decision, "reason": reason}})
    return out
