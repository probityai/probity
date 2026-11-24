"""The one signed revocation list: eight subject kinds, a hash chain, cumulative entries, root rotation.

Every reader of revocations (records audit, the TypeScript twin, the Go reader and any other) applies this format
and must agree with these refusals.
"""

from __future__ import annotations

import base64
import importlib.util
import json
from pathlib import Path

import pytest
from probity_records import (
    REFUSAL_CODES,
    REVOCATION_KINDS,
    Journal,
    RevocationError,
    RevocationState,
    Signer,
    Trust,
    check_subject_id,
    grant_digest,
    issue_grant,
    list_digest,
    raw_public,
    sign_approval,
    sign_revocations,
    verify_approval_live,
    verify_grant_allow,
    verify_journal,
)
from probity_records.clock import SystemClock
from probity_records.core import canonical, sha256_hex
from probity_records.identity import jwk_thumbprint
from probity_records.possession import cnf_for_signer
from test_records import _approval, _trust, _write_run

SYSTEM_CLOCK = SystemClock()  # these cases judge windows against the host's time

PAST = "2000-01-01T00:00:00Z"
ROOT = Path(__file__).resolve().parents[1]
H = "ab" * 32
#: The RFC 7638 thumbprint of the RFC 8037 appendix A Ed25519 key, as RFC 8037 A.3 states it.
RFC8037_JWK = {"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
THUMBPRINT = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"


def _list(root: Signer, seq: int, entries: list, previous=None, *, issued_at: str = PAST, list_id: str = "rl") -> dict:
    return sign_revocations(root, list_id=list_id, seq=seq, issued_at=issued_at, entries=entries, previous=previous)


def _entry(kind: str, ident: str, at: str = PAST, **extra) -> dict:
    return {"kind": kind, "id": ident, "revokedAt": at, **extra}


def _resign(root: Signer, body: dict) -> dict:
    """Sign an arbitrary body, bypassing the issuer's own shape check, to put a malformed list in front of a reader."""
    from probity_records.revocation import REVOCATION_DOMAIN

    try:
        message = REVOCATION_DOMAIN + canonical(body)
    except ValueError:  # a body with no canonical form: the reader must refuse its shape before any signature
        return {"body": body, "sig": base64.b64encode(bytes(64)).decode()}
    return {"body": body, "sig": base64.b64encode(root.sign(message)).decode()}


def _code(exc: pytest.ExceptionInfo[RevocationError]) -> str:
    return str(exc.value).split(":", 1)[0]


# -- the chain ---------------------------------------------------------------------------------------------------


def test_seq_rises_by_one_and_previous_is_the_digest_of_the_last_body() -> None:
    root = Signer.generate()
    first = _list(root, 1, [])
    second = _list(root, 2, [_entry("agent", "agent:a")], previous=first)
    assert second["body"]["previous"] == list_digest(first["body"])
    assert list_digest(first["body"]) == "sha256:" + sha256_hex(canonical(first["body"]))
    state = RevocationState.from_lists([second, first], {root.key_id})
    assert (state.seq, state.head, state.list_id) == (2, list_digest(second["body"]), "rl")
    assert state.revoked("agent", "agent:a") and not state.revoked("agent", "agent:b")


@pytest.mark.parametrize(("case", "code"), [
    ("replay", "revocation_list_rollback"), ("rollback", "revocation_list_rollback"),
    ("future", "revocation_list_gap"), ("fork", "revocation_list_previous_mismatch"),
    ("chain", "revocation_list_other_chain"), ("time", "revocation_list_time_reversed"),
])
def test_out_of_order_lists_are_refused_and_leave_the_state_unchanged(case: str, code: str) -> None:
    root = Signer.generate()
    one = _list(root, 1, [], issued_at="2026-06-01T00:00:00Z")
    two = _list(root, 2, [_entry("stream", "s1")], previous=one, issued_at="2026-06-02T00:00:00Z")
    state = RevocationState(roots=frozenset({root.key_id})).apply(one).apply(two)
    bad = {
        "replay": two,
        "rollback": one,
        "future": _list(root, 4, [_entry("stream", "s1")], previous=two, issued_at="2026-06-03T00:00:00Z"),
        "fork": _list(root, 3, [_entry("stream", "s1")], previous=one, issued_at="2026-06-03T00:00:00Z"),
        "chain": _list(root, 3, [_entry("stream", "s1")], previous=two, issued_at="2026-06-03T00:00:00Z", list_id="x"),
        "time": _list(root, 3, [_entry("stream", "s1")], previous=two, issued_at="2026-06-01T12:00:00Z"),
    }[case]
    with pytest.raises(RevocationError) as exc:
        state.apply(bad)
    assert _code(exc) == code
    assert state.seq == 2 and state.revoked("stream", "s1")


def test_a_fresh_verifier_starts_at_seq_one() -> None:
    root = Signer.generate()
    one = _list(root, 1, [])
    with pytest.raises(RevocationError) as exc:
        RevocationState(roots=frozenset({root.key_id})).apply(_list(root, 2, [], previous=one))
    assert _code(exc) == "revocation_list_gap"


@pytest.mark.parametrize("edit", ["drop", "retime", "reason", "add-successor"])
def test_a_list_never_shrinks_and_never_edits_an_entry(edit: str) -> None:
    root, other = Signer.generate(), Signer.generate()
    kept = _entry("key", other.key_id, reason="lost")
    first = _list(root, 1, [kept, _entry("sponsor", "sponsor:acme")])
    changed = {
        "drop": [_entry("sponsor", "sponsor:acme")],
        "retime": [{**kept, "revokedAt": "1999-01-01T00:00:00Z"}, _entry("sponsor", "sponsor:acme")],
        "reason": [{**kept, "reason": "found"}, _entry("sponsor", "sponsor:acme")],
        "add-successor": [{**kept, "successor": raw_public(root)}, _entry("sponsor", "sponsor:acme")],
    }[edit]
    with pytest.raises(RevocationError) as exc:
        RevocationState.from_lists([first, _list(root, 2, changed, previous=first)], {root.key_id})
    assert _code(exc) == "revocation_list_drops_entry"


# -- who may sign -------------------------------------------------------------------------------------------------


def test_a_list_from_a_key_that_is_not_a_pinned_root_is_refused() -> None:
    root, other = Signer.generate(), Signer.generate()
    with pytest.raises(RevocationError) as exc:
        RevocationState.from_lists([_list(other, 1, [])], {root.key_id})
    assert _code(exc) == "revocation_list_signer_not_a_root"


@pytest.mark.parametrize("tamper", ["entries", "sig-bytes", "sig-short", "issuer-swap"])
def test_a_forged_list_is_refused(tamper: str) -> None:
    root, other = Signer.generate(), Signer.generate()
    good = _list(root, 1, [_entry("agent", "agent:a")])
    sig = base64.b64decode(good["sig"])
    forged = {
        "entries": {**good, "body": {**good["body"], "entries": []}},
        "sig-bytes": {**good, "sig": base64.b64encode(bytes([sig[0] ^ 1]) + sig[1:]).decode()},
        "sig-short": {**good, "sig": base64.b64encode(sig[:63]).decode()},
        # the presented key is a pinned root, but the signature is another key's
        "issuer-swap": {"body": {**good["body"], "issuerKey": raw_public(root)},
                        "sig": _resign(other, {**good["body"], "issuerKey": raw_public(root)})["sig"]},
    }[tamper]
    with pytest.raises(RevocationError) as exc:
        RevocationState.from_lists([forged], {root.key_id})
    assert _code(exc) == "revocation_list_signature_unverified"


def test_root_rotation_hands_over_to_the_successor() -> None:
    old, new = Signer.generate(), Signer.generate()
    first = _list(old, 1, [_entry("key", old.key_id, reason="rotation", successor=raw_public(new))])
    second = _list(new, 2, first["body"]["entries"], previous=first)
    state = RevocationState.from_lists([first, second], {old.key_id})
    assert state.roots == frozenset({new.key_id}) and state.seq == 2
    with pytest.raises(RevocationError) as exc:
        RevocationState.from_lists([first, _list(old, 2, first["body"]["entries"], previous=first)], {old.key_id})
    assert _code(exc) == "revocation_list_signer_not_a_root"


def test_a_revoked_successor_is_never_a_root_in_either_id_order() -> None:
    other = Signer.generate()
    seen = set()
    for _ in range(64):
        old, new = Signer.generate(), Signer.generate()
        entries = [_entry("key", old.key_id, reason="rotation", successor=raw_public(new)),
                   _entry("key", new.key_id, reason="compromised")]
        state = RevocationState.from_lists([_list(old, 1, entries)], {old.key_id, other.key_id})
        assert state.roots == frozenset({other.key_id})
        seen.add(old.key_id < new.key_id)
    assert seen == {True, False}


# -- shape --------------------------------------------------------------------------------------------------------


def _body(root: Signer, entries: list) -> dict:
    return dict(_list(root, 1, [])["body"], entries=entries)


@pytest.mark.parametrize("mutate", [
    lambda b: {**b, "extra": 1},
    lambda b: {k: v for k, v in b.items() if k != "listId"},
    lambda b: {**b, "type": "https://example.org/other-list"},
    lambda b: {**b, "seq": 0},
    lambda b: {**b, "seq": True},
    lambda b: {**b, "seq": 2**53},
    lambda b: {**b, "previous": "sha256:" + "00" * 32},
    lambda b: {**b, "issuedAt": "2026-06-01T00:00:00+00:00"},
    lambda b: {**b, "issuedAt": "2026-02-30T00:00:00Z"},
    lambda b: {**b, "issuerKey": base64.b64encode(b"\x01" * 31).decode()},
    lambda b: {**b, "listId": "has space"},
    lambda b: {**b, "entries": [_entry("tenant", "t")]},
    lambda b: {**b, "entries": [_entry("agent", "a"), _entry("agent", "a")]},
    lambda b: {**b, "entries": [_entry("stream", "s"), _entry("agent", "a")]},
    lambda b: {**b, "entries": [_entry("agent", "")]},
    lambda b: {**b, "entries": [_entry("agent", "a" * 513)]},
    lambda b: {**b, "entries": [_entry("agent", "agenté")]},
    lambda b: {**b, "entries": [_entry("grant", "AB" * 32)]},
    lambda b: {**b, "entries": [_entry("key", "ab" * 31)]},
    lambda b: {**b, "entries": [_entry("agent", "a", successor="x")]},
    lambda b: {**b, "entries": [{**_entry("agent", "a"), "note": "x"}]},
    lambda b: {**b, "entries": [_entry("agent", "a", reason=7)]},
    lambda b: {**b, "entries": [{"kind": "agent", "id": "a"}]},
])
def test_malformed_lists_are_refused_even_when_signed(mutate) -> None:
    root = Signer.generate()
    with pytest.raises(RevocationError) as exc:
        RevocationState.from_lists([_resign(root, mutate(_list(root, 1, [])["body"]))], {root.key_id})
    assert _code(exc) == "revocation_list_shape"


@pytest.mark.parametrize("signed", [None, [], {"body": {}}, {"body": {}, "sig": "", "x": 1}, {"sig": ""}])
def test_a_list_that_is_not_an_object_of_body_and_sig_is_refused(signed) -> None:
    with pytest.raises(RevocationError) as exc:
        RevocationState(roots=frozenset({"00" * 32})).apply(signed)
    assert _code(exc) == "revocation_list_shape"


def test_the_issuer_refuses_to_sign_a_malformed_list() -> None:
    root = Signer.generate()
    with pytest.raises(RevocationError) as exc:
        _list(root, 1, [_entry("tenant", "t")])
    assert _code(exc) == "revocation_list_shape"


def test_an_entry_revoked_after_the_list_was_issued_is_refused() -> None:
    root = Signer.generate()
    body = _body(root, [_entry("agent", "a", at="2026-07-01T00:00:00Z")])
    with pytest.raises(RevocationError) as exc:
        RevocationState.from_lists([_resign(root, body)], {root.key_id})
    assert _code(exc) == "revocation_entry_from_future"


def _some_id(kind: str) -> str:
    return {"grant": H, "key": H, "permit": H, "idp-key": THUMBPRINT}.get(kind, f"{kind}:x")


def test_the_issuer_sorts_entries_and_every_kind_is_listed() -> None:
    root = Signer.generate()
    entries = [_entry(k, _some_id(k)) for k in reversed(REVOCATION_KINDS)]
    state = RevocationState.from_lists([_list(root, 1, entries)], {root.key_id})
    assert [e["kind"] for e in _list(root, 1, entries)["body"]["entries"]] == sorted(REVOCATION_KINDS)
    assert all(state.revoked(k, _some_id(k)) for k in REVOCATION_KINDS)
    assert state.revokes([("sponsor", "sponsor:x"), ("agent", "agent:none")])
    assert not state.revokes([("agent", "sponsor:x")])
    assert set(REFUSAL_CODES) >= {"revocation_list_shape", "revocation_list_rollback", "revocation_list_gap"}


def test_an_unknown_kind_in_a_query_is_a_programming_error() -> None:
    with pytest.raises(ValueError, match="unknown_revocation_kind"):
        RevocationState().revoked("tenant", "t")


# -- the records audit reads the same list ------------------------------------------------------------------------


def test_revoked_approver_approval_is_refused() -> None:
    root, approver = Signer.generate(), Signer.generate()
    signed = sign_approval(approver, _approval(approver, "00" * 32))
    pems = {"human:ops": approver.public_pem()}
    clean = RevocationState.from_lists([], {root.key_id})
    assert verify_approval_live(signed, pems, clean, "2026-06-01T00:00:00Z") == signed["body"]
    state = RevocationState.from_lists(
        [_list(root, 1, [_entry("key", approver.key_id, "2026-05-01T00:00:00Z", reason="laptop lost")],
               issued_at="2026-05-02T00:00:00Z")], {root.key_id})
    assert verify_approval_live(signed, pems, state, "2026-06-01T00:00:00Z") is None
    assert verify_approval_live(signed, pems, state, "2026-04-01T00:00:00Z") == signed["body"]


def test_records_signed_after_revocation_fail_offline(tmp_path) -> None:
    root, gate, approver = Signer.generate(), Signer.generate(), Signer.generate()
    journal = Journal(tmp_path, gate, clock=SYSTEM_CLOCK)
    _write_run(journal, approver, "committed", "confirmed")
    lists = [_list(root, 1, [_entry("key", gate.key_id, reason="compromised")])]
    trust = Trust(revocations=RevocationState.from_lists(lists, {root.key_id}))
    report = verify_journal(tmp_path, [gate.public_pem()], journal.checkpoint(), trust=trust)
    assert report["verdict"] == "FAIL"
    assert sum("signer_key_revoked" in f for f in report["failures"]) == 3
    approver_out = Trust(revocations=RevocationState.from_lists(
        [_list(root, 1, [_entry("key", approver.key_id, reason="left")])], {root.key_id}),
        quorum_policies=_trust(("human:ops", approver)).quorum_policies)
    failures = verify_journal(tmp_path, [gate.public_pem()], journal.checkpoint(), trust=approver_out)["failures"]
    assert any("approver_key_revoked" in f for f in failures), failures
    pid = journal.statements()[0]["predicate"]["permitId"]
    permit_out = Trust(revocations=RevocationState.from_lists(
        [_list(root, 1, [_entry("permit", pid, reason="cancelled")])], {root.key_id}))
    failures = verify_journal(tmp_path, [gate.public_pem()], journal.checkpoint(), trust=permit_out)["failures"]
    assert sum("permit_revoked" in f for f in failures) == 3
    clean = Trust(revocations=RevocationState.from_lists([], {root.key_id}),
                  quorum_policies=_trust(("human:ops", approver)).quorum_policies)
    assert verify_journal(tmp_path, [gate.public_pem()], journal.checkpoint(), trust=clean)["verdict"] == "PASS"


def test_revoking_a_parent_grant_revokes_its_descendants() -> None:
    root, agent, sub, rev = (Signer.generate() for _ in range(4))
    tools = {"t": {"args": {"n": {"type": "range", "max": 10}}}}
    parent = issue_grant(root, grant_id="p", holder_key=raw_public(agent), cnf=cnf_for_signer(agent), tools=tools, max_depth=1,
                         not_before="2026-01-01T00:00:00Z", expires_at="2099-01-01T00:00:00Z")
    child = issue_grant(agent, grant_id="c", holder_key=raw_public(sub), cnf=cnf_for_signer(sub), tools=tools, parent=parent,
                        not_before="2026-01-01T00:00:00Z", expires_at="2099-01-01T00:00:00Z")
    state = RevocationState.from_lists([_list(rev, 1, [_entry("grant", grant_digest(parent["body"]))])],
                                       {rev.key_id})
    verdict = verify_grant_allow([parent, child], "t", {"n": 1}, "2026-06-01T00:00:00Z", {root.key_id},
                                 set(state.revoked_grants()), state.key_revoked)
    assert verdict["reason"] == "grant_revoked:0"
    key_state = RevocationState.from_lists([_list(rev, 1, [_entry("key", agent.key_id)])], {rev.key_id})
    verdict = verify_grant_allow([parent, child], "t", {"n": 1}, "2026-06-01T00:00:00Z", {root.key_id},
                                 set(), key_state.key_revoked)
    assert verdict["reason"] == "grant_issuer_key_revoked:1"


def test_state_carries_the_newest_lists_signed_issue_time() -> None:
    root = Signer.generate()
    first = _list(root, 1, [], issued_at="2026-06-01T00:00:00Z", list_id="L")
    second = _list(root, 2, [], previous=first, issued_at="2026-06-02T00:00:00Z", list_id="L")
    assert RevocationState.from_lists([first, second], {root.key_id}).issued_at == "2026-06-02T00:00:00Z"


# -- the shared vectors every other reader runs -------------------------------------------------------------------


def _generator():
    spec = importlib.util.spec_from_file_location("gen_shared_vectors", ROOT / "scripts" / "gen_shared_vectors.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_shared_revocation_vectors_are_this_packages_output() -> None:
    rows = _generator().revocation_rows()
    assert rows == json.loads((ROOT / "vectors" / "shared" / "revocation.json").read_text())
    codes = {row["expected"]["refused"] for row in rows if "refused" in row["expected"]}
    assert codes == set(REFUSAL_CODES), set(REFUSAL_CODES) - codes


def test_every_shared_vector_holds_under_this_reader() -> None:
    for row in json.loads((ROOT / "vectors" / "shared" / "revocation.json").read_text()):
        state = RevocationState(roots=frozenset(row["roots"]))
        expected = row["expected"]
        for index, signed in enumerate(row["lists"]):
            try:
                state = state.apply(signed)
            except RevocationError as exc:
                assert expected.get("refused") == str(exc).split(":", 1)[0], row["id"]
                assert expected.get("index") == index, row["id"]
                break
        else:
            assert expected.get("state") == state.summary(), row["id"]


@pytest.mark.parametrize(("kind", "ident"), [
    ("grant", "a" * 64), ("key", "0" * 64), ("permit", "f" * 64),
    ("agent", "agent://tenant/a"), ("stream", "s"), ("sponsor", "issuer#subject"), ("build", "x" * 512),
])
def test_check_subject_id_admits_every_id_a_list_can_name(kind: str, ident: str) -> None:
    check_subject_id(kind, ident)


@pytest.mark.parametrize(("kind", "ident", "why"), [
    ("grant", "A" * 64, "entry_id_form:grant"), ("key", "a" * 63, "entry_id_form:key"),
    ("agent", "", "entry_id_form:agent"), ("agent", "caf\u00e9", "entry_id_form:agent"),
    ("stream", "x" * 513, "entry_id_form:stream"), ("sponsor", 7, "entry_id_form:sponsor"),
    ("user", "u", "entry_kind_unknown"),
])
def test_check_subject_id_refuses_what_no_list_can_name(kind: str, ident: object, why: str) -> None:
    with pytest.raises(RevocationError, match=f"^revocation_list_shape:{why}$"):
        check_subject_id(kind, ident)


# -- identity provider signing keys (kind "idp-key", named by RFC 7638 thumbprint) ---------------------------------


def _loosen(char: str) -> str:
    """The same base64url digit with its lowest bit set: unused in a thumbprint's last digit, so a second spelling."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    return alphabet[alphabet.index(char) | 1]


#: Each id an idp-key entry must refuse, with what is wrong with it.
BAD_THUMBPRINTS = {
    "42 characters": THUMBPRINT[:-1],
    "44 characters": THUMBPRINT + "A",
    "padded": THUMBPRINT + "=",
    "padding inside 43 characters": THUMBPRINT[:-1] + "=",
    "a 64-hex key id": "ab" * 32,
    "the standard base64 alphabet": THUMBPRINT.replace("_", "/"),
    "nonzero unused bits in the last digit": THUMBPRINT[:-1] + _loosen(THUMBPRINT[-1]),
    "empty": "",
}


def test_the_thumbprint_constant_is_rfc8037s() -> None:
    assert jwk_thumbprint(RFC8037_JWK) == THUMBPRINT


def test_an_idp_key_entry_is_read_by_its_thumbprint() -> None:
    root = Signer.generate()
    state = RevocationState.from_lists(
        [_list(root, 1, [_entry("idp-key", THUMBPRINT, "2026-05-01T00:00:00Z", reason="signing key leaked")],
               issued_at="2026-05-02T00:00:00Z")], {root.key_id})
    assert state.revoked("idp-key", THUMBPRINT) and state.revoked_ids("idp-key") == frozenset({THUMBPRINT})
    assert not state.revoked("key", THUMBPRINT)
    assert state.summary()["revoked"]["idp-key"] == [THUMBPRINT]
    check_subject_id("idp-key", THUMBPRINT)


def test_idp_key_revoked_holds_at_and_after_revoked_at_only() -> None:
    root = Signer.generate()
    state = RevocationState.from_lists(
        [_list(root, 1, [_entry("idp-key", THUMBPRINT, "2026-05-01T00:00:00Z")], issued_at="2026-05-02T00:00:00Z")],
        {root.key_id})
    assert not state.idp_key_revoked(THUMBPRINT, "2026-04-30T23:59:59Z")
    assert state.idp_key_revoked(THUMBPRINT, "2026-05-01T00:00:00Z")
    assert state.idp_key_revoked(THUMBPRINT, "2026-05-01T01:00:00+01:00")
    assert state.idp_key_revoked(THUMBPRINT, "2026-06-01T00:00:00Z")
    assert not state.idp_key_revoked(THUMBPRINT[:-1] + "A", "2026-06-01T00:00:00Z")
    assert not state.key_revoked(THUMBPRINT, "2026-06-01T00:00:00Z")


@pytest.mark.parametrize("ident", list(BAD_THUMBPRINTS.values()), ids=list(BAD_THUMBPRINTS))
def test_an_idp_key_id_that_is_not_one_thumbprint_spelling_is_refused(ident: str) -> None:
    with pytest.raises(RevocationError, match="^revocation_list_shape:entry_id_form:idp-key$"):
        check_subject_id("idp-key", ident)
    root = Signer.generate()
    with pytest.raises(RevocationError, match="^revocation_list_shape:entry_id_form:idp-key$"):
        RevocationState.from_lists([_resign(root, _body(root, [_entry("idp-key", ident)]))], {root.key_id})


def test_a_thumbprint_never_names_a_key_entry() -> None:
    with pytest.raises(RevocationError, match="^revocation_list_shape:entry_id_form:key$"):
        check_subject_id("key", THUMBPRINT)


def test_an_idp_key_entry_carries_no_successor() -> None:
    root = Signer.generate()
    body = _body(root, [_entry("idp-key", THUMBPRINT, successor=raw_public(Signer.generate()))])
    with pytest.raises(RevocationError, match="^revocation_list_shape:successor_on_non_key_entry$"):
        RevocationState.from_lists([_resign(root, body)], {root.key_id})


def test_the_shared_vectors_hold_idp_key_lists() -> None:
    rows = {row["id"]: row for row in json.loads((ROOT / "vectors" / "shared" / "revocation.json").read_text())}
    accepted = [r for r in rows.values() if r["expected"].get("state", {}).get("revoked", {}).get("idp-key")]
    refused = [r for r in rows.values() if "refused" in r["expected"]
               and any(e.get("kind") == "idp-key" for signed in r["lists"] for e in signed["body"].get("entries", []))]
    assert accepted and len(refused) >= 5
