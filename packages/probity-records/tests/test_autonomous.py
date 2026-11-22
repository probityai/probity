"""Standing grants and the autonomous principals block: an agent that acts with no person in its session.

Every refusal below is something an attacker or a stale configuration could present; each fails closed with its own
code, and the accepted case verifies offline from the record plus what the auditor pins."""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from probity_records import (
    TOOL_CALL_RECORD,
    Journal,
    RevocationState,
    Signer,
    Trust,
    args_sha256,
    issue_grant,
    permit_id,
    raw_public,
    sign_revocations,
    tool_call_predicate,
    verify_journal,
)
from probity_records.grants import (
    chain_digests,
    chain_problem,
    grant_digest,
    is_standing,
    verify_chain,
)
from probity_records.identity import (
    b64url,
    check_principals,
    jwk_thumbprint,
    jwks_digest,
    sponsor_id,
)
from probity_records.possession import cnf_for_signer

ISSUER = "https://idp.example.com/realms/agents"
SPONSOR = {"issuer": ISSUER, "subject": "owner@example.com"}
TOOLS = {"refund": {"args": {"cents": {"type": "range", "min": 1, "max": 5000}}}}


def iso(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


NOW = datetime.now(UTC).replace(microsecond=0)


def standing(root: Signer, holder: Signer, *, sponsor: dict | None = None, review: timedelta = timedelta(days=30),
             expires: timedelta = timedelta(days=90), **kw) -> dict:
    return issue_grant(root, grant_id="nightly", holder_key=raw_public(holder), cnf=cnf_for_signer(holder),
                       tools=TOOLS, not_before=iso(NOW - timedelta(hours=1)), expires_at=iso(NOW + expires),
                       sponsor=sponsor or SPONSOR, review_by=iso(NOW + review), **kw)


# --- the standing grant ---------------------------------------------------------------------------------------


def test_a_standing_grant_names_its_sponsor_and_review_date_together() -> None:
    root, holder = Signer.generate(), Signer.generate()
    grant = standing(root, holder)
    assert is_standing(grant["body"]) and chain_problem([grant], {root.key_id}) is None
    common = {"grant_id": "g", "holder_key": raw_public(holder), "cnf": cnf_for_signer(holder), "tools": TOOLS,
              "not_before": iso(NOW), "expires_at": iso(NOW + timedelta(days=1))}
    with pytest.raises(ValueError, match="grant_standing_incomplete"):
        issue_grant(root, **common, sponsor=SPONSOR)
    with pytest.raises(ValueError, match="grant_standing_incomplete"):
        issue_grant(root, **common, review_by=iso(NOW + timedelta(hours=1)))
    for bad in ({"issuer": ISSUER}, {"issuer": "http://idp", "subject": "x"}, {"issuer": ISSUER + "#f", "subject": "x"},
                {"issuer": ISSUER, "subject": ""}, {"issuer": ISSUER, "subject": "a b"}, {**SPONSOR, "extra": "1"}):
        with pytest.raises(ValueError, match="grant_sponsor_invalid"):
            issue_grant(root, **common, sponsor=bad, review_by=iso(NOW + timedelta(hours=1)))
    for review in (iso(NOW), iso(NOW + timedelta(days=2)), "2026-01-01T00:00:00", "soon"):
        with pytest.raises(ValueError, match="grant_review_invalid"):
            issue_grant(root, **common, sponsor=SPONSOR, review_by=review)


def test_past_its_review_date_a_standing_grant_admits_nothing_down_the_chain() -> None:
    root, holder, child_holder = Signer.generate(), Signer.generate(), Signer.generate()
    grant = standing(root, holder, review=timedelta(hours=1), max_depth=1)
    child = issue_grant(holder, grant_id="c", holder_key=raw_public(child_holder), cnf=cnf_for_signer(child_holder),
                        tools=TOOLS, not_before=iso(NOW - timedelta(minutes=30)), expires_at=iso(NOW + timedelta(days=1)),
                        parent=grant, sponsor=SPONSOR, review_by=iso(NOW + timedelta(minutes=30)))
    assert verify_chain([grant, child], {root.key_id}, iso(NOW))[1] == "ok"
    assert verify_chain([grant, child], {root.key_id}, iso(NOW + timedelta(minutes=30)))[1] == "grant_review_overdue:1"
    assert verify_chain([grant], {root.key_id}, iso(NOW + timedelta(hours=1)))[1] == "grant_review_overdue:0"


def test_a_child_keeps_the_sponsor_and_reviews_no_later() -> None:
    root, holder, child_holder = Signer.generate(), Signer.generate(), Signer.generate()
    grant = standing(root, holder, max_depth=1)
    common = {"grant_id": "c", "holder_key": raw_public(child_holder), "cnf": cnf_for_signer(child_holder),
              "tools": TOOLS, "not_before": iso(NOW), "expires_at": iso(NOW + timedelta(days=60)), "parent": grant}
    with pytest.raises(ValueError, match="child_changes_sponsor"):
        issue_grant(holder, **common)
    with pytest.raises(ValueError, match="child_changes_sponsor"):
        issue_grant(holder, **common, sponsor={**SPONSOR, "subject": "mallory@example.com"},
                    review_by=iso(NOW + timedelta(days=1)))
    with pytest.raises(ValueError, match="child_review_later_than_parent"):
        issue_grant(holder, **common, sponsor=SPONSOR, review_by=iso(NOW + timedelta(days=31)))
    # a forged child that swaps the sponsor is refused by every verifier, not only at issue
    forged = issue_grant(holder, **common, sponsor=SPONSOR, review_by=iso(NOW + timedelta(days=1)))
    forged["body"]["sponsor"] = {**SPONSOR, "subject": "mallory@example.com"}
    assert chain_problem([grant, forged], {root.key_id}) == "grant_signature_unverified:1"


def test_chain_digests_returns_nothing_for_a_chain_that_does_not_verify() -> None:
    root, holder = Signer.generate(), Signer.generate()
    grant = standing(root, holder)
    assert chain_digests([grant], {root.key_id}) == {grant_digest(grant["body"]): grant["body"]}
    assert chain_digests([grant], {Signer.generate().key_id}) == {}  # an unpinned root
    tampered = json.loads(json.dumps(grant))
    tampered["body"]["reviewBy"] = iso(NOW + timedelta(days=89))
    assert chain_digests([tampered], {root.key_id}) == {}


def test_sponsor_id_is_unambiguous() -> None:
    assert sponsor_id(ISSUER, "owner@example.com") == f"{ISSUER}#owner@example.com"
    for issuer, subject in ((ISSUER + "#x", "y"), ("http://idp", "y"), (ISSUER, ""), (ISSUER, "a b")):
        with pytest.raises(ValueError):
            sponsor_id(issuer, subject)


# --- the autonomous block in a journal ------------------------------------------------------------------------


class Idp:
    def __init__(self) -> None:
        self.private = Ed25519PrivateKey.generate()
        raw = self.private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.jwk = {"crv": "Ed25519", "kid": "k1", "kty": "OKP", "x": b64url(raw)}
        self.jwks = {"keys": [self.jwk]}

    def principal(self, sub: str, client: str, *, iat: int, exp: int, cnf: dict | None = None) -> dict:
        claims = {"iss": ISSUER, "sub": sub, "client_id": client, "aud": "https://api.example.com", "iat": iat,
                  "exp": exp}
        head = b64url(json.dumps({"alg": "EdDSA", "kid": "k1", "typ": "JWT"}).encode())
        body = b64url(json.dumps(claims).encode())
        token = f"{head}.{body}.{b64url(self.private.sign(f'{head}.{body}'.encode()))}"
        import hashlib

        p = {"issuer": ISSUER, "subject": sub, "clientId": client, "audience": ["https://api.example.com"],
             "authMethod": "private_key_jwt", "source": "jwt-access-token",
             "tokenDigest": hashlib.sha256(token.encode()).hexdigest(),
             "issuedAt": datetime.fromtimestamp(iat, UTC).isoformat().replace("+00:00", "Z"),
             "expiresAt": datetime.fromtimestamp(exp, UTC).isoformat().replace("+00:00", "Z"), "kid": "k1",
             "key": dict(self.jwk), "keyThumbprint": jwk_thumbprint(self.jwk), "jwksDigest": jwks_digest(self.jwks)}
        if cnf is not None:
            p["cnf"] = dict(cnf)
        return p


def autonomous(tmp_path, *, revoke_sponsor: bool = False, pin_grant: bool = True, profile: str = "strict",
               root_pinned: bool = True) -> list[str]:  # fmt: skip
    idp, gate, root, holder = Idp(), Signer.generate(), Signer.generate(), Signer.generate()
    grant = standing(root, holder)
    now = int(time.time())
    block = {"agent": idp.principal("agent-nightly", "agent-nightly", iat=now - 60, exp=now + 3600,
                                    cnf=cnf_for_signer(holder)),
             "sponsor": idp.principal("owner@example.com", "console", iat=now - 7200, exp=now + 3600),
             "session": {"id": "run-1", "startedAt": iso(NOW - timedelta(minutes=5))},
             "standingGrant": grant_digest(grant["body"])}  # fmt: skip
    args = {"cents": 40}
    j = Journal(tmp_path, gate)
    j.append(TOOL_CALL_RECORD, "tool-call:c1", args_sha256(args), tool_call_predicate(
        phase="intent", run_id="r", tool_call_id="c1", tool="refund", args_sha256_hex=args_sha256(args),
        permit_id=permit_id("p", "c1", args_sha256(args)), principals=block))
    revocations = None
    if revoke_sponsor:
        signed = sign_revocations(root, list_id="acme", seq=1, issued_at=iso(NOW - timedelta(minutes=1)), entries=[
            {"kind": "sponsor", "id": sponsor_id(ISSUER, "owner@example.com"),
             "revokedAt": iso(NOW - timedelta(minutes=1)), "reason": "departed"}])  # fmt: skip
        revocations = RevocationState.from_lists([signed], [root.key_id])
    trust = Trust(identity_issuers={ISSUER: frozenset({jwk_thumbprint(idp.jwk)})}, identity_profile=profile,
                  grant_root_key_ids=frozenset({root.key_id} if root_pinned else set()),
                  agent_sponsors={"agent-nightly": frozenset({(ISSUER, "owner@example.com")})},
                  standing_grants=((grant,),) if pin_grant else (), revocations=revocations)  # fmt: skip
    failures = verify_journal(tmp_path, [gate.public_pem()], j.checkpoint(), trust=trust)["failures"]
    # a lone intent line also fails the permit and effect checks; only the identity verdict is under test here
    other = {f for f in failures if f == "line_1:intent_without_permit" or "open_intent_no_effect" in f}
    assert set(failures) - other == {f for f in failures if "principal" in f}
    return [f for f in failures if "principal" in f]


def test_an_autonomous_record_verifies_offline_under_a_strict_auditor(tmp_path) -> None:
    assert autonomous(tmp_path) == []


def test_a_departed_sponsor_in_the_revocation_list_refuses_the_record(tmp_path) -> None:
    assert "line_1:principals_sponsor_revoked" in autonomous(tmp_path, revoke_sponsor=True)


def test_a_standing_grant_the_auditor_cannot_resolve_or_whose_root_is_not_pinned(tmp_path) -> None:
    assert "line_1:principals_standing_grant_unknown" in autonomous(tmp_path / "a", pin_grant=False)
    assert "line_1:principals_standing_grant_unknown" in autonomous(tmp_path / "b", root_pinned=False)


def test_autonomous_grade_and_sponsor_check_time() -> None:
    idp, root, holder = Idp(), Signer.generate(), Signer.generate()
    grant = standing(root, holder)
    now = int(time.time())
    block = {"agent": idp.principal("a", "a", iat=now - 60, exp=now + 60, cnf=cnf_for_signer(holder)),
             "sponsor": idp.principal("owner@example.com", "console", iat=now - 7200, exp=now - 3000),
             "session": {"id": "s", "startedAt": iso(NOW)}, "standingGrant": grant_digest(grant["body"])}
    pins = {ISSUER: frozenset({jwk_thumbprint(idp.jwk)})}
    kw = {"sponsors": {"a": {(ISSUER, "owner@example.com")}}, "standing_grants": {block["standingGrant"]: grant["body"]}}
    # the sponsor's credential expired before the record, but was live when the grant was issued: accepted
    assert check_principals(block, iso(NOW), pins, None, **kw) == ([], "autonomous")
    swapped = {**block, "standingGrant": "0" * 64}
    assert check_principals(swapped, iso(NOW), pins, None, **kw) == (["principals_standing_grant_unknown"], None)
    malformed = {**block, "standingGrant": "Z" * 64}
    assert check_principals(malformed, iso(NOW), pins, None, **kw) == (["principals_standing_grant_malformed"], None)
    assert check_principals({**block, "extra": 1}, iso(NOW), pins, None, **kw) == (["principals_malformed"], None)
