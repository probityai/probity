"""Break-it suite for the records layer: each test is an attack on our own grants, constraints,
canonical bytes and export seals, and asserts the attack is refused.

Every attack here was run against the code first; the ones that worked are fixed in this package and
these tests are their regression guards.
"""

from __future__ import annotations

import json

import pytest

from probity_records import (Signer, canonical, issue_grant, raw_public, seal_export, verify_chain,
                             verify_export_seal)
from probity_records.constraints import check

T0 = "2026-01-01T00:00:00Z"
T1 = "2027-01-01T00:00:00Z"


# ---- widened grant -------------------------------------------------------------------------------
def _root_and_holder() -> tuple[Signer, Signer, dict]:
    root, holder = Signer.generate(), Signer.generate()
    parent = issue_grant(root, grant_id="g1", holder_key=raw_public(holder), not_before=T0, expires_at=T1, max_depth=1,
                         tools={"transfer": {"args": {"to": {"type": "exact", "value": "acct-1"},
                                                      "amount": {"type": "range", "max": 100}}}})
    return root, holder, parent


def test_child_grant_that_drops_a_parent_constraint_is_refused() -> None:
    """A child naming fewer arguments than its parent admits calls the parent refuses (the dropped
    argument then falls to the tool's own default, unbounded)."""
    root, holder, parent = _root_and_holder()
    widened = {"transfer": {"args": {"to": {"type": "exact", "value": "acct-1"}}}}
    with pytest.raises(ValueError, match="child_drops_argument"):
        issue_grant(holder, grant_id="g2", holder_key=raw_public(Signer.generate()), not_before=T0,
                    expires_at=T1, tools=widened, parent=parent)
    # A forged chain that skips issue_grant's own check is refused by every verifier.
    from probity_records.core import _b64, canonical as jcs
    from probity_records.grants import GRANT_DOMAIN, grant_digest

    body = {"context": {}, "expiresAt": T1, "grantId": "g2", "holderKey": raw_public(Signer.generate()),
            "issuerKey": raw_public(holder), "maxDepth": 0, "notBefore": T0, "parent": grant_digest(parent["body"]),
            "tools": widened}
    child = {"body": body, "sig": _b64(holder.sign(GRANT_DOMAIN + jcs(body)))}
    leaf, reason = verify_chain([parent, child], {root.key_id}, "2026-06-01T00:00:00Z")
    assert leaf is None and reason.startswith("child_drops_argument")


@pytest.mark.parametrize("url", [
    "https://api.example.com/api/%2e%2e/admin",
    "https://api.example.com/api/%2E%2E/admin",
    "https://api.example.com/api/..%2fadmin",
    "https://api.example.com/api%2f..%2fadmin",
    "https://api.example.com/api/%252e%252e/admin",
    "https://api.example.com/api\\..\\admin",
])
def test_url_pattern_path_escape_through_encoding_is_refused(url: str) -> None:
    c = {"type": "url_pattern", "schemes": ["https"], "hosts": ["api.example.com"], "pathPrefix": "/api"}
    assert check(c, "https://api.example.com/api/orders/1")
    assert not check(c, url)


@pytest.mark.parametrize("url", [
    "http://2130706433/", "http://127.1/", "http://0x7f.0.0.1/", "http://0177.0.0.1/", "http://0x7f000001/",
    "http://017700000001/", "http://10.1/", "http://[::ffff:127.0.0.1]/", "http://0/",
])
def test_url_safe_private_address_in_alternate_notation_is_refused(url: str) -> None:
    c = {"type": "url_safe", "schemes": ["http", "https"]}
    assert check(c, "http://example.com/")
    assert not check(c, url)


# ---- approval for other bytes: the canonical form must be one-to-one ------------------------------
@pytest.mark.parametrize("n", [2**53, 2**53 + 1, -(2**53), -(2**53) - 1, 10**17 + 1, 2**63 - 1])
def test_integers_that_jcs_cannot_print_exactly_are_refused(n: int) -> None:
    """JCS writes every number as an IEEE double, so two integers past 2**53 print the same bytes and
    an approval signed over one amount would hold for another. Such integers are refused outright."""
    with pytest.raises(ValueError):
        canonical([n])
    assert canonical([2**53 - 1]) == b"[9007199254740991]"
    assert canonical([-(2**53 - 1)]) == b"[-9007199254740991]"


# ---- export edited after sealing -----------------------------------------------------------------
EXPORT = json.dumps({"records": [{"id": "a1", "type": "approval", "stage": "approved", "createdBy": "u1",
                                  "lastModifiedBy": "u1", "createdDate": T0, "lastUpdatedDate": T0}]}).encode()


@pytest.mark.parametrize("edit", [
    lambda d: d.replace(b'"approved"', b'"rejected"'),
    lambda d: d.replace(b'"u1"', b'"u2"', 1),
    lambda d: d + b"\n",
    lambda d: d.replace(b'"records": [', b'"records": [{"id": "a0"}, '),
    lambda d: d.replace(b'{"records"', b'{"items": [], "records"'),
])
def test_export_edited_after_sealing_fails(edit) -> None:
    signer = Signer.generate()
    seal = seal_export(signer, EXPORT, source="vendor", kind="entities", captured_at=T0, sealed_at=T0)
    assert verify_export_seal(seal, EXPORT, [signer.public_pem()])["verdict"] == "PASS"
    edited = edit(EXPORT)
    assert edited != EXPORT
    assert verify_export_seal(seal, edited, [signer.public_pem()])["verdict"] == "FAIL"


def test_export_seal_from_an_unpinned_key_fails() -> None:
    attacker = Signer.generate()
    seal = seal_export(attacker, EXPORT, source="vendor", kind="entities", captured_at=T0, sealed_at=T0)
    assert verify_export_seal(seal, EXPORT, [Signer.generate().public_pem()])["verdict"] == "FAIL"
