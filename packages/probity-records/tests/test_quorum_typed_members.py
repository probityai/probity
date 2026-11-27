"""A vote, a delegation and quorum evidence are received JSON: every member is read by its type before it is used.

``String(["carol"])`` is ``"carol"`` and ``str(["carol"])`` is ``"['carol']"``; every JavaScript object has a member
named ``constructor``; ``"finance-and-more".includes("finance")`` is true and so is ``"finance" in "finance-and-more"``;
``[]`` is true in JavaScript and false in Python. A reader that turns such a member into text, looks it up among
inherited members, or tests it for truth counts a vote the other reader ignores. Rows QV6 to QV20 of
``vectors/shared/quorum.json`` (``scripts/gen_shared_vectors.py`` signs each value exactly as written) hold both
readers to one answer: this file pins the answer of each row and runs the Python reader on it, and
``node/probity-records-verify/test/shared.test.ts`` holds the TypeScript reader to the same report.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from probity_records import Trust, verify_journal

ROWS = {v["id"]: v for v in json.loads((Path(__file__).resolve().parents[1] / "vectors" / "shared" / "quorum.json").read_text())}

#: Row -> the one failure the record carries, or None where the quorum holds.
EXPECTED: dict[str, str | None] = {
    "QV6": "quorum_vote_invalid:vote_from_unknown_approver",  # approver is a list
    "QV7": "quorum_vote_invalid:vote_from_unknown_approver",  # approver named constructor
    "QV8": "quorum_vote_invalid:deputy_for_unknown_approver",  # onBehalfOf is a list
    "QV9": "quorum_policy_not_pinned",  # policy id is a list
    "QV10": "quorum_policy_not_pinned",  # policy id named constructor
    "QV11": "quorum_pending",  # a proposer named constructor is no approver
    "QV12": "quorum_vote_invalid:vote_role_not_held",  # role is a list
    "QV13": None,  # a deputy named constructor is no approver
    "QV14": "quorum_vote_invalid:vote_signature_unverified",  # deputy key is a number
    "QV15": "quorum_vote_invalid:deputy_role_not_delegated",  # role is a list the delegation lists
    "QV16": "quorum_vote_invalid:deputy_role_not_delegated",  # delegated roles are one text
    "QV17": "quorum_vote_invalid:vote_shape",  # no decision
    "QV18": "quorum_vote_invalid:vote_shape",  # decision is a list
    "QV19": "quorum_proposer_unbound",  # proposer is an empty list
    "QV20": None,  # the control: every member a string
}


def test_every_typed_row_has_a_pinned_answer() -> None:
    typed = {i for i in ROWS if int(i[2:]) >= 6}
    assert typed == set(EXPECTED), sorted(typed ^ set(EXPECTED))


def _read(row: dict[str, Any], tmp_path: Path) -> list[str]:
    trust = Trust(grant_root_key_ids=frozenset(row["trust"]["grantRootKeyIds"]),
                  quorum_policies=row["trust"]["quorumPolicies"])  # fmt: skip
    (tmp_path / "journal.jsonl").write_text("\n".join(row["journal"]) + "\n")
    failures = verify_journal(tmp_path, [k.encode() for k in row["keys"]], row["checkpoint"], trust=trust)["failures"]
    assert isinstance(failures, list)
    return failures


@pytest.mark.parametrize("row", sorted(EXPECTED, key=lambda i: int(i[2:])))
def test_a_quorum_member_of_another_type_gets_one_answer(row: str, tmp_path: Path) -> None:
    want = [] if EXPECTED[row] is None else [f"line_1:{EXPECTED[row]}"]
    assert ROWS[row]["expected"]["failures"] == want, "the shared vector carries another answer than this table"
    assert _read(ROWS[row], tmp_path) == want
