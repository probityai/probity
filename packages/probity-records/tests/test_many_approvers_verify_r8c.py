"""Fourth independent review of the approver-list change (PR 477 at 30aa697b): the attacks, kept as permanent tests.

Every earlier differential wrote its journals with Python's own ``json.dumps``, so a value could only reach the
readers in the spelling Python prints. This file writes chosen raw spellings into the signed statement bytes (``1e2``,
``1E2``, ``-0``, ``-0.0``, a 30-digit integer, ``\\u`` escapes, a member written twice) and reads every journal with
both readers: the Python report is pinned in ``node/probity-records-verify/test/fixtures/many-approvers-r8c.json`` and
the TypeScript half (``node/probity-records-verify/test/many-approvers-r8c.test.ts``) must return it field for field.

Three groups:

- J: an allow of two approvers and an intent on its permit, with the parties spelled differently in the two records.
- D: an approver list that names one person twice through a spelling (an escaped subject, three members).
- C: the M of N count when the approval body names its approver with a value that is not a JSON string (``1.0``,
  ``true``, ``null``), the policy pinning the name each reader would print for it.

Regenerate the fixture after an intended change: ``uv run python tests/test_many_approvers_verify_r8c.py``.
"""

from __future__ import annotations

import base64
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

from probity_records import journal as journal_module
from probity_records import verify_journal
from probity_records.authority import Trust
from probity_records.identity_vectors import base, second_approver

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import gen_shared_vectors as g

FULL = base()["principals"]
FIXTURE = (Path(__file__).resolve().parents[3] / "node" / "probity-records-verify" / "test" / "fixtures"
           / "many-approvers-r8c.json")


def _raw(n: int) -> str:
    """A placeholder string the writer below replaces, quotes included, with raw JSON text."""
    return f"@@raw{n}@@"


@contextlib.contextmanager
def _raw_spellings(spellings: dict[str, str]) -> Iterator[None]:
    """The journal writes each statement with every placeholder replaced by its raw JSON text."""
    real = journal_module.json

    def dumps(obj: Any, **kw: Any) -> str:
        text = real.dumps(obj, **kw)
        if isinstance(obj, dict) and "predicate" in obj:
            for placeholder, raw in spellings.items():
                text = text.replace(json.dumps(placeholder), raw)
        return text

    journal_module.json = types.SimpleNamespace(dumps=dumps, loads=real.loads)  # type: ignore[assignment]
    try:
        yield
    finally:
        journal_module.json = real


def _member(who: str, **over: Any) -> dict[str, Any]:
    member = copy.deepcopy(FULL["approver"] if who == "ops" else second_approver()[0])
    member["subject"] = g.WHO.get(who, who)
    member.update(over)
    return member


def _block(approver: Any, **extra: Any) -> dict[str, Any]:
    block = {k: copy.deepcopy(v) for k, v in FULL.items() if k != "approver"}
    if approver is not None:
        block["approver"] = copy.deepcopy(approver)
    block.update(copy.deepcopy(extra))
    return block


def _allow2(block: dict[str, Any]) -> dict[str, Any]:
    bindings = [g.binding(g.OPS, g.WHO["ops"]), g.binding(g.LEAD, g.WHO["lead"])]
    return g.identity_call("authorize", block, decision="allow", reason="bound", threshold=2,
                           approval_policy="refunds2of2", approval_bindings=bindings)


def _escaped(text: str) -> str:
    """``text`` as a JSON string with every character written as a \\u escape."""
    return '"' + "".join(f"\\u{ord(c):04x}" for c in text) + '"'


Case = tuple[list[dict[str, Any]], dict[str, str], dict[str, Any]]


def journals() -> dict[str, Case]:
    """Each journal's records, its raw spellings, and the extra quorum policies its auditor pins."""
    out: dict[str, Case] = {}
    iss = FULL["approver"]["issuer"]

    def pair(name: str, allow_ops: dict[str, Any], intent_ops: dict[str, Any], spellings: dict[str, str]) -> None:
        out[name] = ([_allow2(_block([_member("ops", **allow_ops), _member("lead")])),
                      g.identity_call("intent", _block([_member("lead"), _member("ops", **intent_ops)]))],
                     spellings, {})

    # J: one party, two spellings. Both readers must read the intent as the allow's parties.
    for n, (name, a, b) in enumerate([("1e2 against 100", "1e2", "100"), ("1E2 against 100.0", "1E2", "100.0"),
                                      ("-0 against 0", "-0", "0"), ("-0.0 against 0", "-0.0", "0"),
                                      ("1e+2 against 1.00e2", "1e+2", "1.00e2")]):
        pair(f"J{n + 1} issuer {name}", {"issuer": _raw(2 * n)}, {"issuer": _raw(2 * n + 1)},
             {_raw(2 * n): a, _raw(2 * n + 1): b})
    # J6: two integers past 2**53 that one double holds (both readers read every number as a double).
    pair("J6 issuer two 30-digit integers one double holds", {"issuer": _raw(20)}, {"issuer": _raw(21)},
         {_raw(20): "123456789012345678901234567890", _raw(21): "123456789012345678901234567891"})
    # J7: the subject written with escapes in the intent, the issuer with escapes in the allow: the same strings.
    pair("J7 subject and issuer written as escapes", {"issuer": _raw(30)}, {"subject": _raw(31)},
         {_raw(30): _escaped(iss), _raw(31): _escaped(g.WHO["ops"])})
    # J8: one subject in two Unicode normal forms: two strings to both readers (no reader normalises).
    out["J8 the user subject NFC in the allow, NFD in the intent"] = (
        [_allow2(_block([_member("ops"), _member("lead")], user={**FULL["user"], "subject": "josé"})),
         g.identity_call("intent", _block([_member("ops"), _member("lead")], user={**FULL["user"], "subject": "josé"}))],
        {}, {})
    # D: one person twice in the list, through a spelling.
    out["D1 ops twice, the second subject written as escapes"] = (
        [_allow2(_block([_member("ops"), _member("ops", subject=_raw(40))]))], {_raw(40): _escaped(g.WHO["ops"])}, {})
    out["D2 three members, ops twice"] = (
        [_allow2(_block([_member("ops"), _member("lead"), _member("ops")]))], {}, {})
    out["D3 a member that writes subject twice (escaped key)"] = (
        [_allow2(_block([_member("ops", subject=_raw(41)), _member("lead")]))],
        {_raw(41): json.dumps(g.WHO["ops"]) + ',"subj\\u0065ct":' + json.dumps(g.WHO["lead"])}, {})
    # C: the approval names its approver with a value that is not a JSON string. The policy pins the printed name.
    # The approver signs the body with that value (its signature covers the RFC 8785 bytes, so it verifies).
    for n, (name, value, pinned) in enumerate([("1.0, pinned as 1", 1.0, "1"), ("1.0, pinned as 1.0", 1.0, "1.0"),
                                               ("true, pinned as true", True, "true"),
                                               ("true, pinned as True", True, "True"),
                                               ("1e16, pinned as 10000000000000000", 1e16, "10000000000000000"),
                                               ("1e16, pinned as 1e+16", 1e16, "1e+16"),
                                               ("1, pinned as 1 (control)", 1, "1"),
                                               ("\"1\", pinned as 1 (control)", "1", "1")]):
        policy = g.approval_policy(f"p{n}", {pinned: g.OPS.public_pem()}, 1)
        out[f"C{n + 1} approver {name}"] = (
            [g.identity_call("authorize", _block(None), decision="allow", reason="bound", threshold=1,
                             approval_policy=f"p{n}",
                             approval_bindings=[g.binding(g.OPS, pinned, approval={"approver": value})])],
            {}, {f"p{n}": policy})
    return out


def build() -> list[dict[str, Any]]:
    trust, doc = g.approvers_trust()
    rows = []
    for name, (records, spellings, policies) in journals().items():
        t0 = dataclasses.replace(trust, quorum_policies={**trust.quorum_policies, **policies})
        d0 = dict(doc, quorumPolicies={**doc["quorumPolicies"], **policies})
        auditors: dict[str, tuple[Trust, dict[str, Any]]] = {
            "strict": (t0, d0),
            "basic": (dataclasses.replace(t0, identity_profile="basic"), dict(d0, identityProfile="basic"))}
        with tempfile.TemporaryDirectory() as tmp:
            with _raw_spellings(spellings):
                j = g.identity_case(Path(tmp), records)
            checkpoint = j.checkpoint()
            lines = [line for line in j.path.read_text().splitlines() if line.strip()]
            for auditor, (t, d) in auditors.items():
                try:
                    full = verify_journal(tmp, [g.GATE.public_pem()], checkpoint, trust=t)
                    expected: dict[str, Any] = {k: full[k] for k in ("verdict", "records", "verified", "failures",
                                                                      "checkpoint")}
                except Exception as e:  # recorded so the TypeScript half can be compared; a test below forbids it
                    expected = {"raises": f"{type(e).__name__}: {e}"}
                rows.append({"id": f"{name} [{auditor}]", "journal": lines, "checkpoint": checkpoint, "trust": d,
                             "keys": [g.GATE.public_pem().decode()], "expected": expected})
    return rows


def _payloads(row: dict[str, Any]) -> list[bytes]:
    return [base64.b64decode(json.loads(line)["payload"]) for line in row["journal"]]


def test_the_node_fixture_is_this_readers_report() -> None:
    assert json.loads(FIXTURE.read_text()) == build()


def test_the_raw_spellings_reach_the_signed_bytes() -> None:
    """Each placeholder was replaced, so each journal carries the spelling it names."""
    rows = {r["id"]: r for r in json.loads(FIXTURE.read_text())}
    assert b'"issuer":1e2' in _payloads(rows["J1 issuer 1e2 against 100 [strict]"])[0]
    assert b'"issuer":-0,' in _payloads(rows["J3 issuer -0 against 0 [strict]"])[0]
    assert b"subj\\u0065ct" in _payloads(rows["D3 a member that writes subject twice (escaped key) [strict]"])[0]
    assert all(b"@@raw" not in p for r in rows.values() for p in _payloads(r))


def test_one_party_in_two_spellings_is_one_party() -> None:
    rows = json.loads(FIXTURE.read_text())
    for r in rows:
        if r["id"].startswith(("J1", "J2", "J3", "J4", "J5", "J6", "J7")):
            assert not any("principals_differ_from_permit" in f for f in r["expected"]["failures"]), r["id"]


def test_one_person_twice_is_refused() -> None:
    rows = json.loads(FIXTURE.read_text())
    for r in rows:
        if r["id"].startswith(("D1", "D2")):
            assert any("principal_approver_duplicate" in f for f in r["expected"]["failures"]), r["id"]


def test_no_journal_raises() -> None:
    assert [r["id"] for r in json.loads(FIXTURE.read_text()) if "raises" in r["expected"]] == []


if __name__ == "__main__":
    FIXTURE.write_text(json.dumps(build(), sort_keys=True, separators=(",", ":")) + "\n")
