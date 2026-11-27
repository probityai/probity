"""Attacks on the record formats: bundles, renewals, registry documents and stamp windows.

Each test builds hostile bytes a stranger can hand the offline verifiers and states the behaviour the module
documents. A bundle needs no witness to reach the record and leaf parsers: a checkpoint signed by a log key the
bundle itself names is graded S, so every parser below is reachable by anyone.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from probity_records import registry, renewal, stamp
from probity_records import witness as w
from probity_records.bundle import (
    BUNDLE_FORMAT,
    EVALUATOR_PREDICATE,
    LEAF_FORMAT,
    PAYLOAD_TYPE,
    STATEMENT_TYPE,
    BundleRefused,
    PublicWitness,
    SourceKey,
    ThirdPartyTrust,
    canonical,
    leaf_entry,
    read_evaluator,
    verify_bundle,
)
from probity_records.core import Signer, pae

ORIGIN = "example.com/decision-log"
NOW = 1_800_000_000
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def _envelope(key: Ed25519PrivateKey, payload: bytes) -> bytes:
    sig = key.sign(pae(PAYLOAD_TYPE, payload))
    return json.dumps({"payloadType": PAYLOAD_TYPE, "payload": _b64(payload),
                       "signatures": [{"keyid": "", "sig": _b64(sig)}]}).encode()


def _statement(sequence: int = 0) -> bytes:
    runtime = {"scope": {"tenant_id": "tenant-a"}, "sequence": sequence, "previous": None}
    return json.dumps({"_type": STATEMENT_TYPE, "subject": [], "predicateType": EVALUATOR_PREDICATE,
                       "predicate": {"runtime": runtime}}, sort_keys=True).encode()


class SelfMade:
    """A bundle whose log key the bundle itself names and no witness cosigned: what anyone can build."""

    def __init__(self) -> None:
        self.source_key = Ed25519PrivateKey.generate()
        self.source = SourceKey("evaluator-1", "evaluator", self.source_key.public_key().public_bytes_raw())
        self.log = Signer.generate()
        self.witness = Ed25519PrivateKey.generate()

    def bundle(self, leaf: bytes, record: bytes) -> dict[str, Any]:
        cp = w.Checkpoint(ORIGIN, 1, w.leaf_hash(leaf))
        return {"format": BUNDLE_FORMAT, "checkpoint": w.sign_checkpoint(cp, self.log),
                "log": {"vkey": w.log_vkey(ORIGIN, self.log), "pqVkey": None},
                "leaf": {"index": 0, "bytes": _b64(leaf), "inclusion": []},
                "record": {"bytes": _b64(record), "source": {"id": self.source.source_id, "kind": "evaluator",
                                                             "publicKey": self.source.public_raw.hex()}},
                "map": None}

    def trust(self) -> ThirdPartyTrust:
        vkey = w.vkey("witness-a.example", w.SIG_COSIGNATURE_V1, self.witness.public_key()).encode()
        return ThirdPartyTrust((PublicWitness(vkey, "operator-a", "production"),), quorum=1)

    def good(self) -> tuple[bytes, bytes]:
        record = _envelope(self.source_key, _statement())
        return canonical(leaf_entry(self.source, read_evaluator(record, self.source), 1_799_999_000_000)), record


def test_a_self_made_bundle_reaches_the_parsers_and_grades_s() -> None:
    world = SelfMade()
    leaf, record = world.good()
    assert verify_bundle(world.bundle(leaf, record), world.trust(), NOW).grade == "S"


def _refused(world: SelfMade, leaf: bytes, record: bytes) -> BundleRefused:
    with pytest.raises(BundleRefused) as caught:
        verify_bundle(world.bundle(leaf, record), world.trust(), NOW)
    return caught.value


def test_a_leaf_with_a_lone_surrogate_is_refused_not_raised() -> None:
    world = SelfMade()
    leaf = ('{"format":"' + LEAF_FORMAT + '","tenant":"\\ud800"}').encode()
    _, record = world.good()
    assert _refused(world, leaf, record).code == "bundle_leaf_malformed"


def test_a_deeply_nested_leaf_is_refused_not_raised() -> None:
    world = SelfMade()
    leaf = ('{"format":"' + LEAF_FORMAT + '","x":' + "[" * 100_000 + "]" * 100_000 + "}").encode()
    _, record = world.good()
    assert _refused(world, leaf, record).code == "bundle_leaf_malformed"


def test_a_deeply_nested_record_is_refused_not_raised() -> None:
    world = SelfMade()
    leaf, _ = world.good()
    record = b"[" * 100_000 + b"]" * 100_000
    assert _refused(world, leaf, record).code == "bundle_record_invalid"


@pytest.mark.parametrize("spelling", [True, 1.0])
def test_a_leaf_that_spells_the_sequence_otherwise_is_not_the_leaf_the_log_writes(spelling: Any) -> None:
    """The log writes ``"sequence":1``; ``true`` and ``1.0`` compare equal in Python but are other leaf bytes."""
    world = SelfMade()
    record = _envelope(world.source_key, _statement(sequence=1))
    entry = leaf_entry(world.source, read_evaluator(record, world.source), 1_799_999_000_000)
    leaf = canonical({**entry, "sequence": spelling})
    assert leaf != canonical(entry)
    assert _refused(world, leaf, record).code == "bundle_record_mismatch"


def test_a_log_key_not_named_after_the_origin_is_refused() -> None:
    world = SelfMade()
    leaf, record = world.good()
    bundle = world.bundle(leaf, record)
    bundle["log"]["vkey"] = w.log_vkey("other.example/log", world.log)
    with pytest.raises(BundleRefused, match="^bundle_log_key_invalid"):
        verify_bundle(bundle, world.trust(), NOW)


def test_a_cosignature_dated_ahead_of_the_clock_completes_no_quorum() -> None:
    world = SelfMade()
    leaf, record = world.good()
    bundle = world.bundle(leaf, record)
    note = w.parse_note(bundle["checkpoint"])
    late = w.cosign(note.text, "witness-a.example", world.witness, NOW + 3600)
    bundle["checkpoint"] = w.Note(note.text, (*note.sigs, late)).encode()
    assert verify_bundle(bundle, world.trust(), NOW).grade == "S"


# --- registry ----------------------------------------------------------------------------------------------------

ISSUER = "https://validator.example"
CLOCK = int(datetime(2026, 11, 21, 12, 0, tzinfo=UTC).timestamp())
AGENT = "agt_" + "a" * 26


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _segment(value: Any) -> str:
    return _b64url(json.dumps(value, separators=(",", ":"), sort_keys=True).encode())


def _validation_claims() -> dict[str, Any]:
    return {"iss": ISSUER, "iat": CLOCK, "exp": CLOCK + 600, "domain": "acme.example", "tenant": "acme",
            "sub": AGENT, "method": "dns-01", "jti": "j1"}


def test_an_es256_validation_has_one_spelling() -> None:
    """``unb64url`` reads one spelling of each segment because single-use checks key on the token's text; an ECDSA
    signature (r, s) and (r, n - s) both verify, so the other spelling must be refused for the digest to be single."""
    key = ec.generate_private_key(ec.SECP256R1())
    numbers = key.public_key().public_numbers()
    jwk = {"kty": "EC", "crv": "P-256", "x": _b64url(numbers.x.to_bytes(32, "big")),
           "y": _b64url(numbers.y.to_bytes(32, "big")), "kid": "k1"}
    pins = {ISSUER: registry.PinnedKeys.of(ISSUER, {"keys": [jwk]})}
    head, body = _segment({"alg": "ES256", "kid": "k1", "typ": registry.VALIDATION_TYP}), _segment(_validation_claims())
    r, s = decode_dss_signature(key.sign(f"{head}.{body}".encode(), ec.ECDSA(hashes.SHA256())))
    tokens = [f"{head}.{body}.{_b64url(r.to_bytes(32, 'big') + v.to_bytes(32, 'big'))}" for v in (s, P256_ORDER - s)]
    accepted = []
    for token in tokens:
        try:
            accepted.append(registry.check_validation(token, pins, domain="acme.example", tenant="acme",
                                                      subject=AGENT, now=CLOCK).digest)
        except registry.RegistryError:
            continue
    assert len(accepted) == 1, f"{len(accepted)} spellings of one validation verify, with digests {accepted}"


def test_an_eddsa_validation_has_one_spelling() -> None:
    key = Ed25519PrivateKey.generate()
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": _b64url(key.public_key().public_bytes_raw()), "kid": "k1"}
    pins = {ISSUER: registry.PinnedKeys.of(ISSUER, {"keys": [jwk]})}
    head, body = _segment({"alg": "EdDSA", "kid": "k1", "typ": registry.VALIDATION_TYP}), _segment(_validation_claims())
    sig = key.sign(f"{head}.{body}".encode())
    order = 2**252 + 27742317777372353535851937790883648493
    s = int.from_bytes(sig[32:], "little") + order
    other = f"{head}.{body}.{_b64url(sig[:32] + s.to_bytes(32, 'little'))}"
    with pytest.raises(registry.RegistryError, match="^jws_signature_unverified"):
        registry.check_validation(other, pins, domain="acme.example", tenant="acme", subject=AGENT, now=CLOCK)


def test_a_key_binding_jwt_that_demands_an_extension_is_refused() -> None:
    """The issuer JWT refuses ``crit`` (RFC 7515 section 4.1.11); the key binding JWT must too."""
    issuer, holder = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    salt = _b64url(b"s" * 16)
    disclosure = _b64url(json.dumps([salt, "name", "refunds"], separators=(",", ":")).encode())
    payload = {"iss": ISSUER, "sub": AGENT, "tenant": "acme", "epoch": 3, "iat": CLOCK, "exp": CLOCK + 3600,
               "cnf": {"jwk": {"kty": "OKP", "crv": "Ed25519",
                               "x": _b64url(holder.public_key().public_bytes_raw())}},
               "_sd_alg": "sha-256", "_sd": [_b64url(hashlib.sha256(disclosure.encode()).digest())]}
    head, body = _segment({"alg": "EdDSA", "kid": "k1", "typ": registry.PASSPORT_TYP}), _segment(payload)
    jwt = f"{head}.{body}.{_b64url(issuer.sign(f'{head}.{body}'.encode()))}"
    prefix = f"{jwt}~{disclosure}~"
    kb_claims = {"aud": "rp", "nonce": "n1", "iat": CLOCK,
                 "sd_hash": _b64url(hashlib.sha256(prefix.encode()).digest())}
    kb_head, kb_body = _segment({"alg": "EdDSA", "typ": registry.KB_TYP, "crit": ["x-must-understand"]}), \
        _segment(kb_claims)
    text = prefix + f"{kb_head}.{kb_body}.{_b64url(holder.sign(f'{kb_head}.{kb_body}'.encode()))}"
    jwks = {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": _b64url(issuer.public_key().public_bytes_raw()),
                      "kid": "k1"}]}
    with pytest.raises(registry.RegistryError):
        registry.verify_presentation(text, {ISSUER: registry.PinnedKeys.of(ISSUER, jwks)}, audience="rp",
                                     now=CLOCK)


def test_a_naming_leaf_with_a_lone_surrogate_is_refused_not_raised() -> None:
    log = Ed25519PrivateKey.generate()
    origin = "names.example/log"
    leaf = ('{"admittedAtMs":1,"canonicalId":"' + AGENT + '","domain":"acme.example","format":"'
            + registry.LEAF_FORMAT + '","keys":[],"name":"pay.acme.example","tenant":"\\ud800","validation":'
            '{"digest":"' + "0" * 64 + '","expiresAt":2,"issuedAt":1,"issuer":"i","method":"dns-01"}}').encode()

    class Key:
        public = log.public_key()

        def sign(self, data: bytes) -> bytes:
            return log.sign(data)

    note = w.sign_checkpoint(w.Checkpoint(origin, 1, w.leaf_hash(leaf)), Key())
    vkey = w.vkey(origin, w.SIG_ED25519, log.public_key())
    with pytest.raises(registry.RegistryError, match="^naming_leaf_malformed"):
        registry.verify_entry(registry.Inclusion(leaf, 0, (), note), vkey)


# --- stamp window -------------------------------------------------------------------------------------------------


def test_a_deeply_nested_window_field_is_refused_not_raised() -> None:
    value = base64.b64encode(b"[" * 100_000 + b"]" * 100_000).decode()
    with pytest.raises(stamp.StampRefused, match="^stamp_window_malformed"):
        stamp.window_certificate([(stamp.WINDOW_FIELD, value)])


# --- renewal ------------------------------------------------------------------------------------------------------


class Authority:
    def __init__(self) -> None:
        self.private = Ed25519PrivateKey.generate()
        self.public = self.private.public_key()
        self.key_id = hashlib.sha256(self.public.public_bytes_raw()).hexdigest()

    def sign(self, data: bytes) -> bytes:
        return self.private.sign(data)


class Instance:
    def __init__(self) -> None:
        self.private = Ed25519PrivateKey.generate()
        self.raw = self.private.public_key().public_bytes_raw()
        self.key_id = hashlib.sha256(self.raw).hexdigest()

    def sign(self, data: bytes) -> bytes:
        return self.private.sign(data)


def _certificate(authority: Authority, key: Instance, *, counter: int = 0, instance: str = "i-1",
                 window: tuple[int, int] = (0, 1000)) -> dict[str, Any]:
    return renewal.certificate(authority, instance=instance, agent="a", session="s", build="sha256:" + "0" * 64,
                               model=renewal.UNDECLARED, key=key.raw, not_before=window[0], not_after=window[1],
                               counter=counter, scope="sc")


def _request(key: Instance, previous: str, *, counter: int = 1, issued_at: int = 10) -> dict[str, Any]:
    return renewal.request(key, instance="i-1", counter=counter, previous=previous, signing_key_id=key.key_id,
                           successor=None, issued_at=issued_at, audience="aud")


def test_a_request_dated_outside_its_key_window_is_not_counted() -> None:
    authority, key = Authority(), Instance()
    cert = _certificate(authority, key, window=(0, 100))
    start = renewal.body_digest(cert["body"])
    with pytest.raises(renewal.RenewalError, match="^renewal_signature_unverified"):
        renewal.verify_chain([cert], [_request(key, start, issued_at=100)], [authority.public])


def test_a_fork_is_found_and_an_identical_replay_is_one_request() -> None:
    authority, key = Authority(), Instance()
    cert = _certificate(authority, key)
    start = renewal.body_digest(cert["body"])
    first = _request(key, start)
    assert renewal.verify_chain([cert], [first, first], [authority.public]).fork is None
    chain = renewal.verify_chain([cert], [first, _request(key, start, issued_at=11)], [authority.public])
    assert chain.fork is not None and chain.fork.previous == start


def test_a_float_or_boolean_counter_is_refused() -> None:
    authority, key = Authority(), Instance()
    cert = _certificate(authority, key)
    start = renewal.body_digest(cert["body"])
    for spelling in (1.0, True):
        body = {**_request(key, start)["body"], "counter": spelling}
        signed = renewal.sign(key, renewal.REQUEST_DOMAIN, body)
        with pytest.raises(renewal.RenewalError, match="^renewal_integer_invalid"):
            renewal.verify_chain([cert], [signed], [authority.public])


def test_a_certificate_from_another_root_or_instance_is_refused() -> None:
    authority, rogue, key = Authority(), Authority(), Instance()
    with pytest.raises(renewal.RenewalError, match="^renewal_signature_unverified"):
        renewal.verify_chain([_certificate(rogue, key)], [], [authority.public])
    with pytest.raises(renewal.RenewalError, match="^renewal_certificates_invalid"):
        renewal.verify_chain([_certificate(authority, key), _certificate(authority, Instance(), counter=1,
                                                                         instance="i-2")], [], [authority.public])
