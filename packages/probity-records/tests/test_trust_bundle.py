"""Trust bundle version 2: signing anchors with a status, a window, the predicate types they sign, the signed
revocation list for keys, and a signing time the signer cannot choose (a witnessed tree head)."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from probity_records import Signer, sign_revocations
from probity_records import witness as w
from probity_records.core import _b64, sign_envelope, statement
from probity_records.identity import jwk_thumbprint
from probity_records.revocation import RevocationState
from probity_records.trust_bundle import (
    AnchorRefused,
    WitnessedTime,
    inclusion_proof,
    verify_anchored,
    verify_inclusion,
)
from probity_records.verified_identities import TrustBundle, VerifiedIdentitiesRefused
from probity_records.verified_identities_vectors import bundle as v_bundle

KERNEL = "https://probityai.github.io/agent-evidence-vectors/predicate/v2/kernel-substrate"
LAUNCH = "https://probityai.github.io/agent-evidence-vectors/predicate/v2/launch-chain"
ORIGIN = "authority.example/evidence"
WITNESS = "customer.example/witness-0"
NOT_BEFORE, NOT_AFTER = "2026-06-10T00:00:00Z", "2026-09-01T00:00:00Z"
#: cosignature times in seconds: 2026-08-17T20:53:20Z, 2026-09-21T14:13:20Z, 2026-02-02T02:40:00Z
T_INSIDE, T_AFTER, T_BEFORE = 1_787_000_000, 1_790_000_000, 1_770_000_000


def _jwk(signer: Signer) -> dict[str, Any]:
    raw = signer.public.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {"crv": "Ed25519", "kty": "OKP", "x": _b64(raw).rstrip("=").replace("+", "-").replace("/", "_")}


def _anchor(signer: Signer, **over: Any) -> dict[str, Any]:
    jwk = _jwk(signer)
    anchor = {"jwk": jwk, "thumbprint": jwk_thumbprint(jwk), "role": "kernel-substrate-signer", "status": "active",
              "notBefore": NOT_BEFORE, "notAfter": None, "predicateTypes": [KERNEL]}
    anchor.update(over)
    return anchor


def _bundle(*anchors: dict[str, Any], issuers: bool = True) -> dict[str, Any]:
    doc = v_bundle()
    doc["anchors"] = list(anchors)
    if not issuers:
        doc["issuers"] = {}
    return doc


def _envelope(signer: Signer, predicate_type: str = KERNEL, build: str = "1") -> dict[str, Any]:
    """Ed25519 is deterministic: the same key over the same body gives the same bytes, so another statement needs
    another ``build``."""
    body = statement("kernel", "ab" * 32, predicate_type, {"build": build})
    return sign_envelope(signer, json.dumps(body, sort_keys=True, separators=(",", ":")).encode())


def _leaf(envelope: dict[str, Any]) -> bytes:
    return json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()


def _witnessed(envelope: dict[str, Any], at: int, *, others: int = 3, index: int = 1,
               quorum: str = "w0") -> WitnessedTime:
    """``envelope`` as leaf ``index`` of a log whose checkpoint one witness cosigned at ``at`` (seconds)."""
    log = Signer.generate()
    witness = Ed25519PrivateKey.generate()
    leaves = [f"other-{n}".encode() for n in range(others)]
    leaves.insert(index, _leaf(envelope))
    hashes = [w.leaf_hash(x) for x in leaves]
    cp = w.Checkpoint(ORIGIN, len(leaves), w.root(hashes))
    note = w.parse_note(w.sign_checkpoint(cp, log))
    cosigned = w.Note(note.text, (*note.sigs, w.cosign(note.text, WITNESS, witness, at))).encode()
    wit_vkey = w.vkey(WITNESS, w.SIG_COSIGNATURE_V1, witness.public_key()).encode()
    policy = w.parse_policy(f"log {w.log_vkey(ORIGIN, log)}\nwitness w0 {wit_vkey}\nquorum {quorum}\n")
    return WitnessedTime(note=cosigned, policy=policy, index=index, proof=tuple(inclusion_proof(index, hashes)))


# --- the format ---------------------------------------------------------------------------------------------------


def test_a_version_one_bundle_is_refused() -> None:
    doc = v_bundle()
    doc["version"] = 1
    with pytest.raises(VerifiedIdentitiesRefused) as caught:
        TrustBundle.parse(doc)
    assert caught.value.code == "trust_bundle_malformed"


def test_a_version_two_bundle_without_anchors_member_is_refused() -> None:
    doc = v_bundle()
    del doc["anchors"]
    with pytest.raises(VerifiedIdentitiesRefused):
        TrustBundle.parse(doc)


def test_an_anchor_only_bundle_parses_and_states_both_key_names() -> None:
    signer = Signer.generate()
    parsed = TrustBundle.parse(_bundle(_anchor(signer), issuers=False))
    (anchor,) = parsed.anchors
    assert anchor.key_id == signer.key_id  # sha256(raw key): the name records and revocation lists use
    assert anchor.thumbprint == jwk_thumbprint(_jwk(signer))


def test_a_bundle_with_neither_issuers_nor_anchors_is_refused() -> None:
    doc = _bundle(issuers=False)
    with pytest.raises(VerifiedIdentitiesRefused):
        TrustBundle.parse(doc)


@pytest.mark.parametrize("mutate", [
    lambda a: a.update(thumbprint="A" * 43),
    lambda a: a["jwk"].update(d="secret"),
    lambda a: a.update(status="expired"),
    lambda a: a.update(status="retired", notAfter=None),
    lambda a: a.update(notAfter="2026-06-01T00:00:00Z"),
    lambda a: a.update(notBefore="2026-06-10T00:00:00"),
    lambda a: a.update(predicateTypes=[]),
    lambda a: a.update(predicateTypes=[KERNEL, KERNEL]),
    lambda a: a.update(predicateTypes=["not a uri"]),
    lambda a: a.update(role=""),
    lambda a: a.update(extra=1),
    lambda a: a.pop("role"),
    lambda a: a["jwk"].update(kty="RSA"),
])
def test_a_malformed_anchor_is_refused(mutate: Any) -> None:
    anchor = _anchor(Signer.generate())
    mutate(anchor)
    with pytest.raises(VerifiedIdentitiesRefused) as caught:
        TrustBundle.parse(_bundle(anchor))
    assert caught.value.code == "trust_bundle_malformed"


def test_an_anchor_listed_twice_is_refused() -> None:
    signer = Signer.generate()
    with pytest.raises(VerifiedIdentitiesRefused):
        TrustBundle.parse(_bundle(_anchor(signer), _anchor(signer, role="other")))


# --- verifying a statement under an anchor ------------------------------------------------------------------------


def _refused(code: str, *args: Any, **kwargs: Any) -> None:
    with pytest.raises(AnchorRefused) as caught:
        verify_anchored(*args, **kwargs)
    assert caught.value.code == code, caught.value


def test_an_active_unbounded_anchor_verifies_its_predicate_without_a_time() -> None:
    signer = Signer.generate()
    bundle = TrustBundle.parse(_bundle(_anchor(signer)))
    verdict = verify_anchored(_envelope(signer), bundle)
    assert verdict.anchor.key_id == signer.key_id
    assert verdict.statement["predicateType"] == KERNEL
    assert verdict.signed_no_later_than is None


def test_a_key_the_bundle_does_not_list_is_refused() -> None:
    bundle = TrustBundle.parse(_bundle(_anchor(Signer.generate())))
    _refused("anchor_unknown", _envelope(Signer.generate()), bundle)


def test_a_predicate_type_the_anchor_may_not_sign_is_refused() -> None:
    signer = Signer.generate()
    bundle = TrustBundle.parse(_bundle(_anchor(signer)))
    _refused("anchor_predicate_not_authorized", _envelope(signer, LAUNCH), bundle)


def test_a_revoked_anchor_verifies_nothing_even_inside_its_window() -> None:
    signer = Signer.generate()
    bundle = TrustBundle.parse(_bundle(_anchor(signer, status="revoked", notAfter=NOT_AFTER)))
    env = _envelope(signer)
    _refused("key_revoked", env, bundle, witnessed=_witnessed(env, T_INSIDE))


def test_a_retired_anchor_refuses_a_signature_made_after_its_window() -> None:
    signer = Signer.generate()
    bundle = TrustBundle.parse(_bundle(_anchor(signer, status="retired", notAfter=NOT_AFTER)))
    env = _envelope(signer)
    _refused("anchor_signed_outside_window", env, bundle, witnessed=_witnessed(env, T_AFTER))


def test_a_retired_anchor_with_no_trusted_signing_time_is_refused() -> None:
    signer = Signer.generate()
    bundle = TrustBundle.parse(_bundle(_anchor(signer, status="retired", notAfter=NOT_AFTER)))
    _refused("anchor_signing_time_unbound", _envelope(signer), bundle)


def test_an_active_anchor_whose_window_closed_needs_a_witnessed_time_too() -> None:
    signer = Signer.generate()
    bundle = TrustBundle.parse(_bundle(_anchor(signer, notAfter=NOT_AFTER)))
    _refused("anchor_signing_time_unbound", _envelope(signer), bundle)


def test_a_retired_anchor_verifies_a_signature_witnessed_inside_its_window() -> None:
    signer = Signer.generate()
    bundle = TrustBundle.parse(_bundle(_anchor(signer, status="retired", notAfter=NOT_AFTER)))
    env = _envelope(signer)
    verdict = verify_anchored(env, bundle, witnessed=_witnessed(env, T_INSIDE))
    assert verdict.signed_no_later_than == "2026-08-17T20:53:20Z"


def test_a_witnessed_time_before_the_window_is_refused() -> None:
    signer = Signer.generate()
    bundle = TrustBundle.parse(_bundle(_anchor(signer, status="retired", notAfter=NOT_AFTER)))
    env = _envelope(signer)
    _refused("anchor_signed_outside_window", env, bundle, witnessed=_witnessed(env, T_BEFORE))


def test_a_witnessed_head_that_does_not_include_the_statement_is_refused() -> None:
    signer = Signer.generate()
    bundle = TrustBundle.parse(_bundle(_anchor(signer, status="retired", notAfter=NOT_AFTER)))
    env = _envelope(signer)
    other_env = _envelope(signer, build="2")  # the same key, another statement
    assert other_env != env
    other = _witnessed(other_env, T_INSIDE)
    _refused("anchor_signing_time_unbound", env, bundle, witnessed=other)


def test_an_inclusion_proof_for_another_index_gives_no_time() -> None:
    signer = Signer.generate()
    bundle = TrustBundle.parse(_bundle(_anchor(signer, status="retired", notAfter=NOT_AFTER)))
    env = _envelope(signer)
    held = _witnessed(env, T_INSIDE, index=1)
    for index in (0, 2, 3, 4, -1):
        moved = WitnessedTime(note=held.note, policy=held.policy, index=index, proof=held.proof)
        _refused("anchor_signing_time_unbound", env, bundle, witnessed=moved)
    assert verify_anchored(env, bundle, witnessed=held).signed_no_later_than


def test_a_truncated_or_padded_inclusion_proof_gives_no_time() -> None:
    signer = Signer.generate()
    bundle = TrustBundle.parse(_bundle(_anchor(signer, status="retired", notAfter=NOT_AFTER)))
    env = _envelope(signer)
    held = _witnessed(env, T_INSIDE, others=6, index=3)
    for proof in (held.proof[:-1], (*held.proof, held.proof[-1]), ()):
        bent = WitnessedTime(note=held.note, policy=held.policy, index=held.index, proof=proof)
        _refused("anchor_signing_time_unbound", env, bundle, witnessed=bent)


def test_a_witness_quorum_of_none_gives_no_time() -> None:
    signer = Signer.generate()
    bundle = TrustBundle.parse(_bundle(_anchor(signer, status="retired", notAfter=NOT_AFTER)))
    env = _envelope(signer)
    _refused("anchor_signing_time_unbound", env, bundle, witnessed=_witnessed(env, T_INSIDE, quorum="none"))


def _revocations(root: Signer, key_id: str, revoked_at: str) -> RevocationState:
    entry = {"kind": "key", "id": key_id, "revokedAt": revoked_at}
    signed = sign_revocations(root, list_id="anchors", seq=1, issued_at=revoked_at, entries=[entry])
    return RevocationState.from_lists([signed], [root.key_id])


def test_a_key_revoked_on_the_signed_list_refuses_statements_witnessed_after_it() -> None:
    signer, root = Signer.generate(), Signer.generate()
    bundle = TrustBundle.parse(_bundle(_anchor(signer)))
    env = _envelope(signer)
    state = _revocations(root, signer.key_id, "2026-08-01T00:00:00Z")
    _refused("key_revoked", env, bundle, revocations=state, witnessed=_witnessed(env, T_INSIDE))
    _refused("anchor_signing_time_unbound", env, bundle, revocations=state)


def test_a_key_revoked_on_the_signed_list_keeps_statements_witnessed_before_it() -> None:
    signer, root = Signer.generate(), Signer.generate()
    bundle = TrustBundle.parse(_bundle(_anchor(signer)))
    env = _envelope(signer)
    state = _revocations(root, signer.key_id, "2026-08-30T00:00:00Z")
    assert verify_anchored(env, bundle, revocations=state, witnessed=_witnessed(env, T_INSIDE)).anchor


# --- RFC 9162 inclusion -------------------------------------------------------------------------------------------


def test_inclusion_proofs_hold_for_every_leaf_and_fail_when_bent() -> None:
    for size in range(1, 18):
        hashes = [w.leaf_hash(f"line-{i}".encode()) for i in range(size)]
        head = w.root(hashes)
        for index in range(size):
            proof = inclusion_proof(index, hashes)
            assert verify_inclusion(index, size, hashes[index], proof, head)
            assert not verify_inclusion(index, size, w.leaf_hash(b"x"), proof, head)
            if proof:
                assert not verify_inclusion(index, size, hashes[index], [bytes(32), *proof[1:]], head)
            if size > 1:
                assert not verify_inclusion((index + 1) % size, size, hashes[index], proof, head)


def test_a_bundle_document_is_not_mutated_by_parsing() -> None:
    doc = _bundle(_anchor(Signer.generate()))
    before = copy.deepcopy(doc)
    TrustBundle.parse(doc)
    assert doc == before
