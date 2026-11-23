"""The grant body grammar both verifiers share: every vector in grant_bodies.json and grant_calls.json."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from probity_records import issue_grant
from probity_records.celexpr import syntax_problem
from probity_records.grant_body_vectors import AGENT, ROOT, TOOLS, base, bodies, calls
from probity_records.grants import body_problem, raw_public, validate_body, verify_grant_allow
from probity_records.possession import cnf_for_signer

SHARED = Path(__file__).resolve().parents[1] / "vectors" / "shared"
BODIES = json.loads((SHARED / "grant_bodies.json").read_text(encoding="utf-8"))
CALLS = json.loads((SHARED / "grant_calls.json").read_text(encoding="utf-8"))


def test_the_vector_files_are_what_the_module_generates() -> None:
    assert json.loads(json.dumps(bodies())) == BODIES
    assert json.loads(json.dumps(calls())) == CALLS


@pytest.mark.parametrize("v", BODIES, ids=lambda v: v["id"])
def test_validate_body_names_the_vector_code(v: dict) -> None:
    assert body_problem(v["body"]) == v["expected"]
    if v["expected"] is None:
        validate_body(v["body"])
    else:
        with pytest.raises(ValueError) as exc:
            validate_body(v["body"])
        assert str(exc.value) == v["expected"]


@pytest.mark.parametrize("v", CALLS, ids=lambda v: v["id"])
def test_a_call_is_judged_as_the_vector_says(v: dict) -> None:
    got = verify_grant_allow(v["chain"], v["tool"], v["args"], v["at"], set(v["roots"]), ctx=v["ctx"])
    assert {"decision": got["decision"], "reason": got["reason"]} == v["expected"]


def test_every_axis_has_a_refusing_vector() -> None:
    heads = {v["expected"].split(":")[0] for v in BODIES if v["expected"]}
    assert heads >= {"grant_tools_empty", "grant_tool_shape", "grant_approval_level", "grant_arg_constraint_invalid",
                     "grant_when_shape", "grant_when_invalid", "grant_quorum_invalid", "grant_quorum_must_bind_proposer",
                     "grant_quorum_without_required_approval", "grant_max_depth", "grant_context_shape",
                     "grant_context_constraint_invalid", "grant_budget_shape", "grant_budget_uses", "grant_budget_spend",
                     "grant_issuer_key_invalid"}


def test_an_issuer_still_refuses_a_condition_that_does_not_type_check() -> None:
    tools = {"refund": {**TOOLS["refund"], "when": ["1 + 'a' == 2"]}}
    with pytest.raises(ValueError, match="^grant_when_invalid:refund.0:cel_type_check_failed$"):
        issue_grant(ROOT, grant_id="g", holder_key=raw_public(AGENT), cnf=cnf_for_signer(AGENT), tools=tools,
                    not_before=base()["notBefore"], expires_at=base()["expiresAt"])


@pytest.mark.parametrize(("expr", "code"), [
    ("value > 1", None), ("", "cel_expression_empty"), (7, "cel_expression_empty"), ("value ==", "cel_syntax_invalid"),
    ("has(value)", "cel_syntax_invalid"), ("value == '\\z'", "cel_syntax_invalid"), ("value > 1 // c", None),
])
def test_syntax_problem(expr: object, code: str | None) -> None:
    assert syntax_problem(expr) == code
