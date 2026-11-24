"""probity-key-delegation/v2: explicit scope members, a half-open window, held to the shared vectors and the spec."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from probity_records import Journal, Signer, sign_permit, verify_journal, verify_permit
from probity_records.clock import FixedClock, from_datetime
from probity_records.delegation_vectors import CASES, check, vectors
from probity_records.signing import (
    DELEGATION_CODES,
    DelegationScope,
    SigningError,
    delegate,
    verify_delegation,
)

PACKAGE = Path(__file__).resolve().parents[1]
SHARED = PACKAGE / "vectors" / "shared" / "delegation.json"
SPEC = PACKAGE / "docs" / "key-delegation.md"
START = datetime(2026, 11, 23, 12, 0, tzinfo=UTC)
RECORD = DelegationScope("record", "ours", "tenant-a", 600)


def test_every_vector_judges_as_expected_and_the_shared_file_is_current() -> None:
    rows = vectors()
    assert json.loads(SHARED.read_text()) == json.loads(json.dumps(rows))
    assert check(json.loads(SHARED.read_text())) == []
    assert {code for *_, code in CASES} - {None} == set(DELEGATION_CODES)


def test_the_spec_lists_exactly_the_codes_the_reader_raises_in_its_order() -> None:
    listed = re.findall(r"^\| \d+ \| `(delegation_[a-z_]+)` \|", SPEC.read_text(), re.MULTILINE)
    assert tuple(listed) == DELEGATION_CODES


def test_a_round_trip_returns_the_scope_the_root_certified() -> None:
    root = Signer.generate()
    key = delegate(root, DelegationScope("authority", "customer", "acme", 3600), now=START)
    body = key.certificate["body"]
    assert body["format"] == "probity-key-delegation/v2"
    assert {k: body[k] for k in ("custody", "hierarchy", "tenant", "windowS")} == {
        "custody": "customer", "hierarchy": "authority", "tenant": "acme", "windowS": 3600}
    d = verify_delegation(key.certificate, [root.public])
    assert d.scope == DelegationScope("authority", "customer", "acme", 3600)
    assert d.scope.members() == {"custody": "customer", "hierarchy": "authority", "tenant": "acme", "windowS": 3600}
    assert d.session_key_id == key.key_id and d.root_key_id == root.key_id


def test_the_window_is_half_open() -> None:
    root = Signer.generate()
    d = verify_delegation(delegate(root, RECORD, now=START).certificate, [root.public])
    assert d.covers("2026-11-23T12:00:00.000000Z")
    assert d.covers("2026-11-23T12:09:59.999999Z")
    assert not d.covers("2026-11-23T12:10:00.000000Z")
    assert not d.covers("2026-11-23T11:59:59.999999Z")
    assert not d.covers("not a time")


def test_the_root_never_certifies_a_window_longer_than_declared_or_an_empty_one() -> None:
    root = Signer.generate()
    with pytest.raises(SigningError):
        delegate(root, RECORD, now=START, lifetime=timedelta(seconds=601))
    with pytest.raises(SigningError):
        delegate(root, RECORD, now=START, lifetime=timedelta(0))
    shorter = delegate(root, RECORD, now=START, lifetime=timedelta(seconds=60))
    assert shorter.certificate["body"]["notAfter"] == "2026-11-23T12:01:00.000000Z"


@pytest.mark.parametrize(("scope", "code"), [
    (("record", "customer", "acme", 600), "delegation_record_root_customer_custody"),
    (("witness", "ours", "acme", 600), "delegation_hierarchy_invalid"),
    (("record", "tenant", "acme", 600), "delegation_custody_invalid"),
    (("record", "ours", "", 600), "delegation_tenant_invalid"),
    (("record", "ours", "acme", 0), "delegation_window_invalid"),
    (("record", "ours", "acme", True), "delegation_window_invalid"),
])
def test_a_scope_no_root_may_certify_cannot_be_built(scope: tuple, code: str) -> None:
    with pytest.raises(ValueError, match=f"^{code}$"):
        DelegationScope(*scope)


def test_a_record_signed_at_the_notafter_instant_is_outside_the_window(tmp_path: Path) -> None:
    root = Signer.generate()
    key = delegate(root, RECORD, now=START)
    clock = FixedClock(from_datetime(START + timedelta(seconds=600)))
    journal = Journal(tmp_path, key, clock=clock)
    journal.append("https://example.test/t", "s", "0" * 64, {"phase": "note"})
    out = verify_journal(tmp_path, [root.public_pem()], journal.checkpoint())
    assert any("session_key_used_outside_its_certified_window" in f for f in out["failures"])
    inside = tmp_path / "inside"
    early = Journal(inside, key, clock=FixedClock(from_datetime(START + timedelta(seconds=599))))
    early.append("https://example.test/t", "s", "0" * 64, {"phase": "note"})
    assert verify_journal(inside, [root.public_pem()], early.checkpoint())["verdict"] == "PASS"


def test_a_permit_issued_at_notafter_is_refused() -> None:
    root = Signer.generate()
    key = delegate(root, DelegationScope("authority", "ours", "tenant-a", 600), now=START)
    assert verify_permit(sign_permit(key, {"issuedAt": "2026-11-23T12:09:59.999999Z", "permitId": "p"}),
                         root.public_pem()) is not None
    assert verify_permit(sign_permit(key, {"issuedAt": "2026-11-23T12:10:00.000000Z", "permitId": "p"}),
                         root.public_pem()) is None


def test_a_v1_certificate_in_a_journal_is_a_failure_named_by_its_format(tmp_path: Path) -> None:
    rows = {r["id"]: r for r in vectors()}
    (tmp_path / "keys.jsonl").write_text(json.dumps(rows["DG04"]["certificate"]) + "\n")
    root = Signer.generate()
    journal = Journal(tmp_path / "j", root, clock=FixedClock(from_datetime(START)))
    journal.append("https://example.test/t", "s", "0" * 64, {"phase": "note"})
    (tmp_path / "j" / "keys.jsonl").write_text((tmp_path / "keys.jsonl").read_text())
    out = verify_journal(tmp_path / "j", [root.public_pem()], journal.checkpoint())
    assert any(f.startswith("keys_line_1:session_key_delegation_invalid:delegation_format_retired")
               for f in out["failures"])
