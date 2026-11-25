"""The renewal records and the offline chain and fork check: only certificates, requests and a pinned root.

Every refusal carries its own registered code, and every registered code of the check is reached by a case below."""

from __future__ import annotations

import base64
import copy
import json
from importlib import resources
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from probity_records import renewal
from probity_records.core import Signer, sha256_hex
from probity_records.refusal_codes import is_registered

T0 = 1_800_000_000_000
BUILD = "sha256:" + "b" * 64
LEASE = {"epoch": 1, "leaseId": "l1", "notAfter": T0 + 60_000, "notBefore": T0, "source": "s"}


class World:
    def __init__(self) -> None:
        self.root = Signer.generate()
        self.key = Ed25519PrivateKey.generate()
        self.signed_cert = self.certificate(self.key)
        self.cert = renewal.open_certificate(self.signed_cert, [self.root.public])

    def certificate(self, key: Ed25519PrivateKey, **kw: Any) -> dict[str, Any]:
        args: dict[str, Any] = {"instance": "i1", "agent": "a", "session": "s", "build": BUILD, "model": "undeclared",
                                "not_before": T0, "not_after": T0 + 900_000, "counter": 0, "scope": "default", **kw}
        return renewal.certificate(self.root, key=renewal.raw_public(key.public_key()), **args)

    def request(self, counter: int, previous: str, at: int, **kw: Any) -> dict[str, Any]:
        args: dict[str, Any] = {"instance": "i1", "counter": counter, "previous": previous, "issued_at": at,
                                "signing_key_id": self.cert.key_id, "successor": None, "audience": self.root.key_id,
                                **kw}
        return renewal.request(_Signer(self.key), **args)

    def line(self, n: int) -> list[dict[str, Any]]:
        out, previous = [], self.cert.digest
        for counter in range(1, n + 1):
            req = self.request(counter, previous, T0 + counter * 30_000)
            out.append(req)
            previous = renewal.body_digest(req["body"])
        return out

    def verify(self, requests: list[dict[str, Any]]) -> renewal.Chain:
        return renewal.verify_chain([self.signed_cert], requests, [self.root.public])


class _Signer:
    def __init__(self, key: Ed25519PrivateKey) -> None:
        self.key = key
        self.key_id = sha256_hex(renewal.raw_public(key.public_key()))

    def sign(self, data: bytes) -> bytes:
        return self.key.sign(data)


def code_of(call: Any, *args: Any) -> str:
    with pytest.raises(renewal.RenewalError) as raised:
        call(*args)
    assert is_registered(raised.value.code)
    return str(raised.value.code)


def test_a_clean_chain_reports_its_length() -> None:
    world = World()
    chain = world.verify(world.line(5))
    assert (chain.length, chain.fork, chain.instance) == (5, None, "i1")


def test_order_and_duplicates_do_not_matter() -> None:
    world = World()
    line = world.line(4)
    assert world.verify([line[2], line[0], line[3], line[1], line[1], line[0]]).length == 4


def test_an_empty_chain_is_length_zero() -> None:
    assert World().verify([]).length == 0


def test_two_requests_on_one_previous_are_a_fork_with_both_digests() -> None:
    world = World()
    line = world.line(3)
    clone = world.request(2, renewal.body_digest(line[0]["body"]), T0 + 61_000)
    chain = world.verify([*line, clone])
    assert chain.fork is not None
    assert chain.fork.counter == 2 and chain.fork.previous == renewal.body_digest(line[0]["body"])
    assert {chain.fork.first, chain.fork.second} == {renewal.body_digest(line[1]["body"]),
                                                     renewal.body_digest(clone["body"])}


def test_a_fork_at_the_first_renewal_is_found() -> None:
    world = World()
    one, two = world.request(1, world.cert.digest, T0 + 1000), world.request(1, world.cert.digest, T0 + 2000)
    assert world.verify([one, two]).fork is not None


def test_fork_proven_needs_one_previous_and_two_different_requests() -> None:
    world = World()
    a, b = world.request(1, world.cert.digest, T0 + 1000), world.request(1, world.cert.digest, T0 + 2000)
    c = world.request(2, renewal.body_digest(a["body"]), T0 + 3000)
    certs, roots = [world.signed_cert], [world.root.public]
    assert renewal.fork_proven(a, b, certs, roots) is not None
    assert renewal.fork_proven(a, a, certs, roots) is None
    assert renewal.fork_proven(a, c, certs, roots) is None


def test_fork_proven_refuses_a_request_no_certified_key_signed() -> None:
    world = World()
    a = world.request(1, world.cert.digest, T0 + 1000)
    stranger = Ed25519PrivateKey.generate()
    b = renewal.request(_Signer(stranger), instance="i1", counter=1, previous=world.cert.digest,
                        signing_key_id=world.cert.key_id, successor=None, issued_at=T0 + 2000,
                        audience=world.root.key_id)
    assert code_of(renewal.fork_proven, a, b, [world.signed_cert], [world.root.public]) == "renewal_signature_unverified"


def test_a_request_outside_every_key_window_is_refused() -> None:
    world = World()
    late = world.request(1, world.cert.digest, T0 + 900_000)
    early = world.request(1, world.cert.digest, T0 - 1)
    assert code_of(world.verify, [late]) == "renewal_signature_unverified"
    assert code_of(world.verify, [early]) == "renewal_signature_unverified"


def test_a_request_for_another_instance_is_refused() -> None:
    world = World()
    other = world.request(1, world.cert.digest, T0 + 1, instance="i2")
    assert code_of(world.verify, [other]) == "renewal_instance_mismatch"


def test_a_counter_that_skips_and_a_request_that_continues_nothing_are_refused() -> None:
    world = World()
    assert code_of(world.verify, [world.request(3, world.cert.digest, T0 + 1000)]) == "renewal_counter_gap"
    assert code_of(world.verify, [world.request(1, "sha256:" + "ab" * 32, T0 + 1000)]) == "renewal_request_orphaned"


def test_a_certificate_from_an_unpinned_root_is_refused() -> None:
    world = World()
    assert code_of(renewal.open_certificate, world.signed_cert,
                   [Signer.generate().public]) == "renewal_signature_unverified"


def test_two_issuing_certificates_and_none_are_refused() -> None:
    world = World()
    roots = [world.root.public]
    assert code_of(renewal.verify_chain, [world.signed_cert, world.signed_cert], [], roots) == (
        "renewal_certificates_invalid")
    rotated = world.certificate(Ed25519PrivateKey.generate(), counter=1)
    assert code_of(renewal.verify_chain, [rotated], [], roots) == "renewal_certificates_invalid"


def test_certificates_of_one_instance_state_one_identity() -> None:
    world = World()
    rotated = world.certificate(Ed25519PrivateKey.generate(), counter=1, agent="another")
    assert code_of(renewal.verify_chain, [world.signed_cert, rotated], [],
                   [world.root.public]) == "renewal_identity_changed"
    same = world.certificate(Ed25519PrivateKey.generate(), counter=1)
    assert renewal.verify_chain([world.signed_cert, same], [], [world.root.public]).length == 0


def test_certificate_window_is_half_open() -> None:
    cert = World().cert
    assert cert.covers(cert.not_before) and cert.covers(cert.not_after - 1) and not cert.covers(cert.not_after)
    assert not cert.covers(cert.not_before - 1)


def _padded(sig: str) -> str:
    """The same 64 signature bytes in base64 whose last character carries a non-zero trailing bit."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    changed = sig[:-3] + alphabet[alphabet.index(sig[-3]) | 1] + sig[-2:]
    assert changed != sig and base64.b64decode(changed, validate=True) == base64.b64decode(sig)
    return changed


def _tampered(signed: dict[str, Any], **changes: Any) -> dict[str, Any]:
    body = {**copy.deepcopy(signed["body"]), **changes}
    return {"body": body, "sig": signed["sig"]}


def test_every_malformed_record_is_refused_with_its_own_code() -> None:
    world = World()
    req = world.request(1, world.cert.digest, T0 + 1000)
    keys = [world.key.public_key()]
    grant = renewal.grant(world.root, instance="i1", counter=1, request_digest=world.cert.digest, lease=LEASE,
                          certificate_signed=None, issued_at=T0)
    roots = [world.root.public]
    cases: list[tuple[str, Any, Any]] = [
        ("renewal_record_malformed", renewal.open_request, ({"body": req["body"]}, keys)),
        ("renewal_record_malformed", renewal.open_request, ({"body": 5, "sig": req["sig"]}, keys)),
        ("renewal_record_malformed", renewal.open_request, ("text", keys)),
        ("renewal_base64_invalid", renewal.open_request, ({"body": req["body"], "sig": 7}, keys)),
        ("renewal_base64_invalid", renewal.open_request, ({"body": req["body"], "sig": "not base64!"}, keys)),
        ("renewal_base64_invalid", renewal.open_request,
         ({"body": req["body"], "sig": base64.b64encode(base64.b64decode(req["sig"])).decode().rstrip("=")}, keys)),
        ("renewal_base64_invalid", renewal.open_request, ({"body": req["body"], "sig": _padded(req["sig"])}, keys)),
        ("renewal_request_members_invalid", renewal.open_request,
         ({"body": {**req["body"], "extra": 1}, "sig": req["sig"]}, keys)),
        ("renewal_request_type_invalid", renewal.open_request, (_tampered(req, type="instance-renewal/v2"), keys)),
        ("renewal_counter_invalid", renewal.open_request, (_tampered(req, counter=0), keys)),
        ("renewal_integer_invalid", renewal.open_request, (_tampered(req, counter=True), keys)),
        ("renewal_integer_invalid", renewal.open_request, (_tampered(req, counter=1.0), keys)),
        ("renewal_integer_invalid", renewal.open_request, (_tampered(req, issuedAt=-1), keys)),
        ("renewal_integer_invalid", renewal.open_request, (_tampered(req, issuedAt=2**53), keys)),
        ("renewal_digest_invalid", renewal.open_request, (_tampered(req, previous="sha256:AB"), keys)),
        ("renewal_digest_invalid", renewal.open_request, (_tampered(req, attestation="sha256:00"), keys)),
        ("renewal_text_invalid", renewal.open_request, (_tampered(req, audience=""), keys)),
        ("renewal_text_invalid", renewal.open_request, (_tampered(req, instance="i" * 513), keys)),
        ("renewal_text_invalid", renewal.open_request, (_tampered(req, keyId="café"), keys)),
        ("renewal_successor_invalid", renewal.open_request,
         (_tampered(req, successor=base64.b64encode(b"short").decode()), keys)),
        ("renewal_signature_unverified", renewal.open_request, (_tampered(req, audience="elsewhere"), keys)),
        ("renewal_signature_unverified", renewal.open_request, (req, [Ed25519PrivateKey.generate().public_key()])),
        ("renewal_signature_unverified", renewal.open_signed, (req, renewal.GRANT_DOMAIN, keys[0])),
        ("renewal_certificate_members_invalid", renewal.check_certificate_body,
         ({**world.signed_cert["body"], "extra": 1},)),
        ("renewal_certificate_type_invalid", renewal.check_certificate_body,
         (_tampered(world.signed_cert, type="x")["body"],)),
        ("renewal_text_invalid", renewal.check_certificate_body, (_tampered(world.signed_cert, agent="")["body"],)),
        ("renewal_digest_invalid", renewal.check_certificate_body,
         (_tampered(world.signed_cert, build="sha256:1")["body"],)),
        ("renewal_model_invalid", renewal.check_certificate_body, (_tampered(world.signed_cert, model="gpt")["body"],)),
        ("renewal_model_invalid", renewal.check_model, ({"id": "m", "weights": "x"},)),
        ("renewal_model_invalid", renewal.check_model, ({"digest": BUILD},)),
        ("renewal_key_invalid", renewal.check_certificate_body, (_tampered(world.signed_cert, keyId="0" * 64)["body"],)),
        ("renewal_key_invalid", renewal.check_certificate_body,
         (_tampered(world.signed_cert, key=base64.b64encode(b"x" * 31).decode())["body"],)),
        ("renewal_certificate_window_invalid", renewal.check_certificate_body,
         (_tampered(world.signed_cert, notAfter=T0)["body"],)),
        ("renewal_grant_members_invalid", renewal.check_grant_body, ({**grant["body"], "extra": 1},)),
        ("renewal_grant_type_invalid", renewal.check_grant_body, (_tampered(grant, type="x")["body"],)),
        ("renewal_lease_members_invalid", renewal.check_grant_body, (_tampered(grant, lease=5)["body"],)),
        ("renewal_lease_members_invalid", renewal.check_grant_body,
         (_tampered(grant, lease={**LEASE, "extra": 1})["body"],)),
        ("renewal_lease_window_invalid", renewal.check_grant_body,
         (_tampered(grant, lease={**LEASE, "notAfter": T0})["body"],)),
        ("renewal_signature_unverified", renewal.open_grant, (grant, [Signer.generate().public])),
        ("renewal_signature_unverified", renewal.open_grant, (_tampered(grant, counter=9), roots)),
    ]
    assert [code_of(call, *args) for _, call, args in cases] == [code for code, _, _ in cases]


def test_a_certificate_or_grant_whose_authority_names_another_key_is_refused() -> None:
    world = World()
    other = Signer.generate()
    cert = world.certificate(world.key)
    body = {**cert["body"], "authority": other.key_id}
    forged = renewal.sign(world.root, renewal.CERTIFICATE_DOMAIN, body)
    assert code_of(renewal.open_certificate, forged, [world.root.public]) == "renewal_authority_mismatch"
    grant = renewal.grant(world.root, instance="i1", counter=1, request_digest=BUILD, lease=LEASE,
                          certificate_signed=None, issued_at=T0)
    wrong = renewal.sign(world.root, renewal.GRANT_DOMAIN, {**grant["body"], "authority": other.key_id})
    assert code_of(renewal.open_grant, wrong, [world.root.public]) == "renewal_authority_mismatch"


def test_a_request_whose_key_id_names_another_key_is_refused() -> None:
    world = World()
    req = world.request(1, world.cert.digest, T0 + 1000, signing_key_id=world.root.key_id)
    assert code_of(renewal.open_request, req, [world.key.public_key()]) == "renewal_key_id_mismatch"


def test_the_key_id_is_a_claim_checked_against_the_verifying_key_never_a_selector() -> None:
    world = World()
    req = world.request(1, world.cert.digest, T0 + 1000)
    stranger = Ed25519PrivateKey.generate().public_key()
    shaped, used = renewal.open_request(req, [stranger, world.key.public_key()])
    assert used.public_bytes_raw() == world.key.public_key().public_bytes_raw() and shaped.counter == 1


def test_domains_do_not_cross() -> None:
    assert len({renewal.REQUEST_DOMAIN, renewal.CERTIFICATE_DOMAIN, renewal.GRANT_DOMAIN}) == 3


def test_grant_round_trip() -> None:
    world = World()
    grant = renewal.grant(world.root, instance="i1", counter=1, request_digest=world.cert.digest, lease=LEASE,
                          certificate_signed=None, issued_at=T0)
    assert renewal.open_grant(grant, [world.root.public])["lease"] == LEASE


def test_every_registered_renewal_code_is_reached_by_a_case_above() -> None:
    """The registry's lifecycle.renewal codes and the cases of this file are the same set."""
    registry = json.loads(resources.files("probity_records").joinpath("refusal_codes.json").read_text("utf-8"))
    held = {entry["code"] for entry in registry["codes"] if entry["check"] == "lifecycle.renewal"}
    source = resources.files("probity_records").joinpath("renewal.py").read_text("utf-8")
    here = open(__file__, encoding="utf-8").read()
    assert held
    assert {code for code in held if f'"{code}"' not in here} == set()
    assert {code for code in held if f'"{code}"' not in source} == set()
