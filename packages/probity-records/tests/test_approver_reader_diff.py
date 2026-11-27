"""The two readers agree on every approver shape: one verdict and one report, field for field.

Each journal is an allow alone, or an allow followed by an intent on the same permit. The approver value of each
record is drawn from one generated set of shapes (one principal, a list of two in either order, a refreshed
credential, two strings that spell a principal in either order, one string, a list of one, null, absent): every
shape stands alone as an allow, and every allow shape is paired with every intent shape. Each journal is read by
the strict and by the basic auditor.

The Python half is this file: the committed fixture must equal this reader's report on every journal. The
TypeScript half is ``node/probity-records-verify/test/approver-shapes.test.ts``, which reads the same fixture and
must return each report field for field. Together they hold the two readers to one report, so a party spelled one
way in one reader and another way in the other fails one side or the other.

Regenerate after an intended change: ``uv run python packages/probity-records/tests/test_approver_reader_diff.py``.
"""

from __future__ import annotations

import copy
import dataclasses
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from probity_records import verify_journal
from probity_records.identity_vectors import base, second_approver

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import gen_shared_vectors as g

FIXTURE = (Path(__file__).resolve().parents[3] / "node" / "probity-records-verify" / "test" / "fixtures"
           / "approver-shapes.json")
FULL = base()["principals"]
ABSENT = object()


def _member(who: str, *, refreshed: bool = False) -> dict[str, Any]:
    member = copy.deepcopy(FULL["approver"] if who == "ops" else second_approver()[0])
    member["subject"] = g.WHO[who]
    if refreshed:
        member["tokenDigest"] = "ab" * 32
    return member


def shapes() -> dict[str, Any]:
    """Every approver value the readers must agree on."""
    iss = FULL["approver"]["issuer"]
    return {
        "ops": _member("ops"),
        "ops-refreshed": _member("ops", refreshed=True),
        "ops,lead": [_member("ops"), _member("lead")],
        "lead,ops": [_member("lead"), _member("ops")],
        "lead,ops-refreshed": [_member("lead", refreshed=True), _member("ops")],
        "strings:iss,sub": [iss, g.WHO["ops"]],
        "strings:sub,iss": [g.WHO["ops"], iss],
        "string": g.WHO["ops"],
        "list-of-one": [_member("ops")],
        "null": None,
        "absent": ABSENT,
    }


def _block(approver: Any) -> dict[str, Any]:
    block = {k: copy.deepcopy(v) for k, v in FULL.items() if k != "approver"}
    if approver is not ABSENT:
        block["approver"] = copy.deepcopy(approver)
    return block


def _allow(approver: Any) -> dict[str, Any]:
    if isinstance(approver, list) and len(approver) == 2 and all(isinstance(m, dict) for m in approver):
        bindings = [g.binding(g.OPS, g.WHO["ops"]), g.binding(g.LEAD, g.WHO["lead"])]
        return g.identity_call("authorize", _block(approver), decision="allow", reason="bound", threshold=2,
                               approval_policy="refunds2of2", approval_bindings=bindings)
    return g.identity_call("authorize", _block(approver), decision="allow", reason="bound", threshold=1,
                           approval_policy="refunds1of2", approval_bindings=[g.binding(g.OPS, g.WHO["ops"])])


ALLOW_SHAPES = ("ops", "ops,lead", "lead,ops", "strings:iss,sub")


def journals() -> dict[str, list[dict[str, Any]]]:
    s = shapes()
    alone = {f"allow={a}": [_allow(s[a])] for a in s}
    paired = {f"allow={a} intent={i}": [_allow(s[a]), g.identity_call("intent", _block(s[i]))]
              for a in ALLOW_SHAPES for i in s}
    return alone | paired


def build() -> dict[str, Any]:
    trust, doc = g.approvers_trust()
    auditors = {"strict": (trust, doc),
                "basic": (dataclasses.replace(trust, identity_profile="basic"), dict(doc, identityProfile="basic"))}
    rows = []
    for name, records in journals().items():
        with tempfile.TemporaryDirectory() as tmp:
            j = g.identity_case(Path(tmp), records)
            checkpoint = j.checkpoint()
            lines = [line for line in j.path.read_text().splitlines() if line.strip()]
            expected = {}
            for auditor, (t, _) in auditors.items():
                full = verify_journal(tmp, [g.GATE.public_pem()], checkpoint, trust=t)
                expected[auditor] = {k: full[k] for k in ("verdict", "records", "verified", "failures", "checkpoint")}
        rows.append({"id": name, "journal": lines, "checkpoint": checkpoint, "expected": expected})
    return {"keys": [g.GATE.public_pem().decode()], "trust": {k: d for k, (_, d) in auditors.items()},
            "cases": rows}


def test_the_fixture_is_this_readers_report_on_every_shape() -> None:
    assert json.loads(FIXTURE.read_text()) == build()


def test_the_shapes_reach_both_party_outcomes() -> None:
    """A generator that only produced agreeing parties, or only differing ones, or only one verdict, would prove
    nothing about them."""
    found = [r for c in json.loads(FIXTURE.read_text())["cases"] for r in c["expected"].values()]
    differ = [r for r in found if any("principals_differ_from_permit" in x for x in r["failures"])]
    assert differ and len(differ) < len(found)
    assert {r["verdict"] for r in found} == {"PASS", "FAIL"}


if __name__ == "__main__":
    FIXTURE.write_text(json.dumps(build(), sort_keys=True, separators=(",", ":")) + "\n")
