"""Third independent review of the approver-list change (PR 477 at 92e60a37): the attacks, kept as permanent tests.

The journal half builds journals whose approver lists hold shapes the writer's differential did not generate (numbers
written as floats, objects whose members come in another order, a role named ``__proto__``, subjects outside ASCII)
and pins the Python report in ``node/probity-records-verify/test/fixtures/many-approvers-r7.json``; the TypeScript
half (``node/probity-records-verify/test/many-approvers-r7.test.ts``) must return it field for field. The erasure half
holds ``lint_schema`` and ``seal`` to the CHANGELOG's own sentences.

Regenerate the fixture after an intended change: ``uv run python tests/test_many_approvers_verify_r7.py``.
"""

from __future__ import annotations

import contextlib
import copy
import dataclasses
import json
import sys
import tempfile
import types
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from probity_records import journal as journal_module
from probity_records import verify_journal
from probity_records.erasure import (
    PAYLOAD,
    EnvelopeError,
    Rule,
    Schema,
    lint_schema,
    member_subject,
    seal,
)
from probity_records.erasure_vectors import KEYS, SCHEMA, _bytes, record
from probity_records.identity_vectors import base, second_approver

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import gen_shared_vectors as g

FULL = base()["principals"]
FIXTURE = (Path(__file__).resolve().parents[3] / "node" / "probity-records-verify" / "test" / "fixtures"
           / "many-approvers-r7.json")
CALL = {"name": "act.1", "sha256": "f" * 64}
LEAF = b"\x07" * 16


# ---- journal shapes ------------------------------------------------------------------------------------------------
def _member(who: str, **over: Any) -> dict[str, Any]:
    member = copy.deepcopy(FULL["approver"] if who == "ops" else second_approver()[0])
    member["subject"] = g.WHO.get(who, who)
    member.update(over)
    return member


def _block(approver: Any, **extra: Any) -> dict[str, Any]:
    block = {k: copy.deepcopy(v) for k, v in FULL.items() if k != "approver"}
    block["approver"] = copy.deepcopy(approver)
    block.update(copy.deepcopy(extra))
    return block


def _allow(block: dict[str, Any]) -> dict[str, Any]:
    bindings = [g.binding(g.OPS, g.WHO["ops"]), g.binding(g.LEAD, g.WHO["lead"])]
    return g.identity_call("authorize", block, decision="allow", reason="bound", threshold=2,
                           approval_policy="refunds2of2", approval_bindings=bindings)


@contextlib.contextmanager
def _written_as_given() -> Iterator[None]:
    """The journal writes each statement with its object members in the order given, not sorted: a writer the
    readers must not depend on (both read bytes, and JSON object member order carries no meaning)."""
    real = journal_module.json

    def dumps(obj: Any, **kw: Any) -> str:
        if isinstance(obj, dict) and "predicate" in obj:
            kw.pop("sort_keys", None)
        return real.dumps(obj, **kw)

    journal_module.json = types.SimpleNamespace(dumps=dumps, loads=real.loads)  # type: ignore[assignment]
    try:
        yield
    finally:
        journal_module.json = real


def journals() -> dict[str, tuple[list[dict[str, Any]], bool]]:
    """Each journal (an allow of two approvers and an intent on its permit) and whether it is written unsorted."""
    ops, lead = g.WHO["ops"], g.WHO["lead"]
    first, second = sorted((ops, lead))  # the subject that sorts first, and the other one
    pick = {ops: "ops", lead: "lead"}
    out: dict[str, tuple[list[dict[str, Any]], bool]] = {}

    def pair(name: str, allow_members: list[Any], intent_members: list[Any], *, unsorted: bool = False,
             allow_extra: dict | None = None, intent_extra: dict | None = None) -> None:
        out[name] = ([_allow(_block(allow_members, **(allow_extra or {}))),
                      g.identity_call("intent", _block(intent_members, **(intent_extra or {})))], unsorted)

    # N1, N2: an issuer written 1.0 in the allow and 1 in the intent. Python reads them equal and so do Python's
    # sort keys only when the float member does not change the order.
    pair("N1 issuer 1.0 on the member that sorts second",
         [_member(pick[first], issuer=1), _member(pick[second], issuer=1.0)],
         [_member(pick[first], issuer=1), _member(pick[second], issuer=1)])
    pair("N2 issuer 1.0 on the member that sorts first",
         [_member(pick[first], issuer=1.0), _member(pick[second], issuer=1)],
         [_member(pick[first], issuer=1), _member(pick[second], issuer=1)])
    pair("N3 issuer 1e16 against 10000000000000000",
         [_member(pick[first], issuer=1e16), _member(pick[second], issuer=10**16)],
         [_member(pick[first], issuer=10**16), _member(pick[second], issuer=10**16)])
    pair("N4 issuer true against 1",
         [_member(pick[first], issuer=True), _member(pick[second], issuer=1)],
         [_member(pick[first], issuer=1), _member(pick[second], issuer=1)])
    # K1, K2: an issuer object whose members come in another order in the intent (written unsorted).
    pair("K1 issuer object members reordered",
         [_member(pick[first], issuer={"a": 1, "b": 2}), _member(pick[second], issuer={"a": 5})],
         [_member(pick[first], issuer={"b": 2, "a": 1}), _member(pick[second], issuer={"a": 5})], unsorted=True)
    pair("K2 issuer object members reordered, sorted write (control)",
         [_member(pick[first], issuer={"a": 1, "b": 2}), _member(pick[second], issuer={"a": 5})],
         [_member(pick[first], issuer={"b": 2, "a": 1}), _member(pick[second], issuer={"a": 5})])
    # P1 to P3: a role named __proto__.
    two = [_member("ops"), _member("lead")]
    pair("P1 a __proto__ role that changes between allow and intent", two, two,
         allow_extra={"__proto__": _member("ops")}, intent_extra={"__proto__": _member("lead")})
    pair("P2 a __proto__ role only in the intent", two, two, intent_extra={"__proto__": _member("ops")})
    pair("P3 a __proto__ role, the same in both", two, two,
         allow_extra={"__proto__": _member("ops")}, intent_extra={"__proto__": _member("ops")})
    pair("P4 a __proto__ role written as a list", two, two,
         allow_extra={"__proto__": [_member("ops"), _member("lead")]},
         intent_extra={"__proto__": [_member("lead"), _member("ops")]})
    # U1, U2: subjects outside ASCII, whose order differs between escaped and raw JSON text (controls).
    pair("U1 subjects outside ASCII, the other order",
         [_member("ops", subject="é"), _member("lead", subject="z")],
         [_member("lead", subject="z"), _member("ops", subject="é")])
    pair("U2 subjects outside ASCII, one changed",
         [_member("ops", subject="é"), _member("lead", subject="z")],
         [_member("lead", subject="z"), _member("ops", subject="ê")])
    # M1: a member that is a nested list beside a principal.
    pair("M1 a member that is a list beside a principal",
         [_member("ops"), [g.WHO["lead"]]], [[g.WHO["lead"]], _member("ops")])
    return out


def build() -> list[dict[str, Any]]:
    trust, doc = g.approvers_trust()
    auditors = {"strict": (trust, doc),
                "basic": (dataclasses.replace(trust, identity_profile="basic"), dict(doc, identityProfile="basic"))}
    rows = []
    for name, (records, unsorted) in journals().items():
        with tempfile.TemporaryDirectory() as tmp:
            with _written_as_given() if unsorted else contextlib.nullcontext():
                j = g.identity_case(Path(tmp), records)
            checkpoint = j.checkpoint()
            lines = [line for line in j.path.read_text().splitlines() if line.strip()]
            for auditor, (t, d) in auditors.items():
                full = verify_journal(tmp, [g.GATE.public_pem()], checkpoint, trust=t)
                rows.append({"id": f"{name} [{auditor}]", "journal": lines, "checkpoint": checkpoint, "trust": d,
                             "keys": [g.GATE.public_pem().decode()],
                             "expected": {k: full[k] for k in ("verdict", "records", "verified", "failures",
                                                               "checkpoint")}})
    return rows


def test_the_node_fixture_is_this_readers_report() -> None:
    assert json.loads(FIXTURE.read_text()) == build()


def test_the_unsorted_write_reaches_the_journal() -> None:
    """K1 must really carry the reordered object in its bytes, or it tests nothing."""
    rows = {r["id"]: r for r in json.loads(FIXTURE.read_text())}
    import base64
    payload = base64.b64decode(json.loads(rows["K1 issuer object members reordered [strict]"]["journal"][1])["payload"])
    assert b'{"b":2,"a":1}' in payload


# ---- erasure -------------------------------------------------------------------------------------------------------
PAIR = [{"issuer": "https://idp.example", "subject": "carol"}, {"issuer": "https://idp.example", "subject": "dave"}]
MEMBERS = {"user": KEYS["user"], member_subject(0): _bytes("r7/m0", 32), member_subject(1): _bytes("r7/m1", 32)}


def _listed() -> dict[str, Any]:
    r = record(approver=None)
    r["principals"]["approver"] = copy.deepcopy(PAIR)
    return r


def _replace(schema: Schema, path: str, rule: Rule | None, *extra: Rule) -> Schema:
    rules = tuple(rule if r.path == path else r for r in schema.rules if rule is not None or r.path != path)
    return Schema(schema.name, rules + extra, schema.structural, schema.fixed)


def _several_under_one_key(sealed: Any) -> list[str]:
    """Paths that carry the whole approver list under one subject."""
    return [p for p, role in sealed.erasure["roles"].items()
            if p in ("principals", "principals.approver") and not role.startswith("approver.")]


def test_lint_requires_the_flag_on_principals_approver_whatever_its_subject() -> None:
    """CHANGELOG: "lint_schema requires it on principals.approver". A rule there for the user subject without the flag
    passes lint, and seal puts both approvers under the user's key."""
    schema = _replace(SCHEMA, "principals.approver", Rule("principals.approver", PAYLOAD, "user", personal=True))
    problems = lint_schema(schema)
    if not problems:
        sealed = seal(schema, _listed(), MEMBERS, CALL, "user", leaf=LEAF)
        pytest.fail(f"lint passes, and seal put the list under one key: {_several_under_one_key(sealed)}")


def test_a_rule_on_the_whole_principals_object_never_seals_a_list_of_approvers_under_one_key() -> None:
    """A schema that seals ``principals`` whole carries the approver list under one subject key."""
    schema = _replace(SCHEMA, "principals.user", None)
    schema = _replace(schema, "principals.approver", None, Rule("principals", PAYLOAD, "user", personal=True))
    try:
        sealed = seal(schema, _listed(), MEMBERS, CALL, "user", leaf=LEAF)
    except EnvelopeError:
        return
    pytest.fail(f"sealed several approvers under one key: {_several_under_one_key(sealed)}")


def test_member_keys_held_as_bytearray_are_compared_not_crashed_on() -> None:
    """seal reads a key as bytes-like everywhere else (a record with no list seals with bytearray keys); the
    one-key-per-member check must refuse or accept, never raise TypeError."""
    keys = {k: bytearray(v) for k, v in MEMBERS.items()}
    seal(SCHEMA, record(approver=None), {"user": bytearray(KEYS["user"]), "approver": bytearray(KEYS["approver"])},
         CALL, "user", leaf=LEAF)  # a record with no list: seals
    try:
        seal(SCHEMA, _listed(), keys, CALL, "user", leaf=LEAF)
    except EnvelopeError:
        pass
    shared = dict(MEMBERS)
    shared[member_subject(1)] = bytearray(MEMBERS[member_subject(0)])
    with pytest.raises(EnvelopeError, match="field_names_several_subjects"):
        seal(SCHEMA, _listed(), shared, CALL, "user", leaf=LEAF)


def test_one_key_under_two_members_in_any_bytes_like_spelling_is_refused() -> None:
    """R2 held: the same 32 bytes as bytes and as a memoryview under two members are one key."""
    shared = dict(MEMBERS)
    shared[member_subject(1)] = memoryview(MEMBERS[member_subject(0)])
    with pytest.raises(EnvelopeError, match="field_names_several_subjects"):
        seal(SCHEMA, _listed(), shared, CALL, "user", leaf=LEAF)
    shared = dict(MEMBERS)
    shared[member_subject(0)], shared[member_subject(1)] = MEMBERS[member_subject(1)], MEMBERS[member_subject(1)]
    with pytest.raises(EnvelopeError, match="field_names_several_subjects"):
        seal(SCHEMA, _listed(), shared, CALL, "user", leaf=LEAF)


# ---- the TypeScript count of OpenID Connect approvers and revoked keys ------------------------------------------------
COUNT_FIXTURE = FIXTURE.with_name("many-approvers-r7-count.json")


def _raw_token(claims_text: str) -> str:
    """An ID token whose claims segment is ``claims_text`` exactly, signed by the pinned provider key."""
    import test_oidc_approval as o
    from probity_records.identity import b64url

    head = b64url(json.dumps({"alg": "EdDSA", "kid": "idp-1", "typ": "JWT"}, separators=(",", ":")).encode())
    body = b64url(claims_text.encode())
    return f"{head}.{body}.{b64url(o.IDP.sign(f'{head}.{body}'.encode()))}"


def _oidc_with(claims_text: str, principal_claims: dict[str, Any]) -> dict[str, Any]:
    import test_oidc_approval as o
    from probity_records import build_approval_binding
    from probity_records.identity_vectors import _principal
    from probity_records.oidc_approval import embed_oidc_approval

    token = _raw_token(claims_text)
    principal = _principal(token, o.JWK, o.JWKS, "id-token", {**principal_claims, "client_id": o.CLIENT})
    principal["authMethod"] = "client_secret_basic"
    approval = o.body()
    record, payload = build_approval_binding(approval, o.USE, o.PAYLOAD, [], {"dave": approval["keyId"]}, o.DECIDED,
                                             o.RELEASE, issued=["req-1"], enforcement="enforce")
    return embed_oidc_approval(record, payload, token, principal, o.JWKS)


def count_cases() -> dict[str, dict[str, Any]]:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import test_oidc_approval as o
    from probity_records.oidc_approval import approval_nonce

    claims = {"aud": o.CLIENT, "auth_time": o.EPOCH + 60, "azp": o.CLIENT, "exp": o.EPOCH + 300,
              "iat": o.EPOCH + 61, "iss": o.ISSUER, "nonce": approval_nonce(o.body()), "sub": o.SUB}
    text = json.dumps(claims, separators=(",", ":"), sort_keys=True)
    return {
        "C0 the sign-in as written (control)": {"bindings": [_oidc_with(text, claims)]},
        "C1 nbf written as a float": {"bindings": [_oidc_with(text[:-1] + f',"nbf":{o.EPOCH}.0}}', claims)]},
        "C2 a claim whose value is NaN": {"bindings": [_oidc_with(text[:-1] + ',"x":NaN}', claims)]},
        "C3 iat null": {"bindings": [_oidc_with(text.replace(f'"iat":{o.EPOCH + 61}', '"iat":null'), claims)]},
    }


def count_result(case: dict[str, Any]) -> Any:
    import test_oidc_approval as o
    from probity_records.quorum import count_bindings

    policy = {"policyId": "acme-wires", "threshold": 1, "approvers": {"dave": o.POLICY["approvers"]["dave"]}}
    try:
        counted, problems = count_bindings(policy, case["bindings"], o.DECIDED, oidc_pins=o.PINS)
    except Exception as exc:  # noqa: BLE001 - a verifier that raises on a signed input is the finding
        return {"raises": type(exc).__name__}
    return [sorted(counted), problems]


def build_count() -> dict[str, Any]:
    import test_oidc_approval as o

    policy = {"policyId": "acme-wires", "threshold": 1, "approvers": {"dave": o.POLICY["approvers"]["dave"]}}
    return {"policy": policy, "at": o.DECIDED, "pins": o.PINS,
            "cases": [{"id": k, **v, "expected": count_result(v)} for k, v in count_cases().items()]}


def test_the_count_fixture_is_this_readers_count() -> None:
    assert json.loads(COUNT_FIXTURE.read_text()) == build_count()


def test_a_pinned_providers_signed_token_never_raises() -> None:
    """A malformed claim in a token the pinned provider signed is refused with a code, never an exception."""
    raised = {c["id"]: c["expected"] for c in build_count()["cases"] if isinstance(c["expected"], dict)}
    assert raised == {}


# ---- revocations the TypeScript TrustDoc carries but its journal reader ignores ------------------------------------
def revoked_signer_rows() -> list[dict[str, Any]]:
    from probity_records import RevocationState, sign_revocations

    root = g.key("ma-verify-r7/revocation-root")
    trust, doc = g.approvers_trust()
    with tempfile.TemporaryDirectory() as tmp:
        records = [_allow(_block([_member("ops"), _member("lead")]))]
        j = g.identity_case(Path(tmp), records)
        checkpoint = j.checkpoint()
        lines = [line for line in j.path.read_text().splitlines() if line.strip()]
        rows = []
        for name, kind, ident in (("gate signer key", "key", g.GATE.key_id),
                                  ("agent", "agent", str(FULL["agent"]["clientId"]))):
            entry = {"kind": kind, "id": ident, "revokedAt": "2020-01-01T00:00:00Z", "reason": "left"}
            lists = [sign_revocations(root, list_id="rl", seq=1, issued_at="2020-01-02T00:00:00Z", entries=[entry])]
            t = dataclasses.replace(trust, revocations=RevocationState.from_lists(lists, [root.key_id]))
            full = verify_journal(tmp, [g.GATE.public_pem()], checkpoint, trust=t)
            rows.append({"id": f"R{len(rows) + 1} {name} revoked before the record", "journal": lines,
                         "checkpoint": checkpoint, "keys": [g.GATE.public_pem().decode()],
                         "trust": {**doc, "revocations": {"rootKeyIds": [root.key_id], "lists": lists}},
                         "expected": {k: full[k] for k in ("verdict", "records", "verified", "failures",
                                                           "checkpoint")}})
    return rows


REVOKED_FIXTURE = FIXTURE.with_name("many-approvers-r7-revoked.json")


def test_the_revoked_fixture_is_this_readers_report() -> None:
    rows = revoked_signer_rows()
    assert json.loads(REVOKED_FIXTURE.read_text()) == rows
    assert all(r["expected"]["verdict"] == "FAIL" for r in rows)


if __name__ == "__main__":
    FIXTURE.write_text(json.dumps(build(), sort_keys=True, separators=(",", ":")) + "\n")
    COUNT_FIXTURE.write_text(json.dumps(build_count(), sort_keys=True, separators=(",", ":")) + "\n")
    REVOKED_FIXTURE.write_text(json.dumps(revoked_signer_rows(), sort_keys=True, separators=(",", ":")) + "\n")
