"""Second-round attacks on the strict reader, the leaf byte compare, low-S and crit (verify of the r6c repair).

Each test hands a verifier bytes a stranger can send and states the documented behaviour: a registered refusal,
never an exception, and one spelling per signed statement. The first-round attacks stay unchanged in
``test_record_format_attacks.py``.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from probity_records import registry, renewal, stamp
from probity_records import witness as w
from probity_records.bundle import PAYLOAD_TYPE, BundleRefused, canonical, leaf_entry, read_evaluator, verify_bundle
from probity_records.core import JsonRefused, admitted_loads, pae
from probity_records.identity import verify_token
from probity_records.identity_vectors import base
from test_record_format_attacks import (
    AGENT,
    CLOCK,
    ISSUER,
    NOW,
    Authority,
    Instance,
    SelfMade,
    _b64,
    _b64url,
    _certificate,
    _request,
    _segment,
    _statement,
    _validation_claims,
)

# --- the strict reader itself -------------------------------------------------------------------------------------


def test_a_python_string_carrying_a_raw_lone_surrogate_is_refused() -> None:
    with pytest.raises(JsonRefused):
        admitted_loads('{"a":"\ud800"}')


# --- verify_token: a received token is refused, never raised -----------------------------------------------------


def _principal_for(v: dict[str, Any], token: str) -> dict[str, Any]:
    return {**v["principals"]["user"],
            "tokenDigest": hashlib.sha256(token.encode("utf-8", "surrogatepass")).hexdigest()}


@pytest.mark.parametrize("suffix", ["é", "\ud800", " "])
def test_a_token_that_is_not_ascii_is_a_refusal_not_a_raise(suffix: str) -> None:
    """An escrowed token is received text; ``token.encode("ascii")`` must not be the verifier's answer to it."""
    v = base()
    token = v["tokens"]["user"] + suffix
    assert isinstance(verify_token(_principal_for(v, token), token, v["jwks"]), str)


def test_a_header_that_spells_crit_with_an_escape_is_still_refused() -> None:
    v = base()
    _, body, sig = v["tokens"]["user"].split(".")
    head = _b64url(b'{"alg":"EdDSA","\\u0063rit":["x"]}')
    token = f"{head}.{body}.{sig}"
    assert verify_token(_principal_for(v, token), token, v["jwks"]) == "token_critical_unsupported"


# --- the record bundle --------------------------------------------------------------------------------------------


def _refused(world: SelfMade, leaf: bytes, record: bytes) -> str:
    with pytest.raises(BundleRefused) as caught:
        verify_bundle(world.bundle(leaf, record), world.trust(), NOW)
    return caught.value.code


@pytest.mark.parametrize("edit", [
    "escaped-member-name", "bom", "trailing-newline", "big-int-member", "big-admitted", "nan", "overflow",
    "repeated-member", "invalid-utf8", "overlong-utf8", "raw-surrogate-bytes", "float-admitted",
])
def test_a_leaf_in_any_other_spelling_is_refused_not_raised(edit: str) -> None:
    world = SelfMade()
    good, record = world.good()
    text = good.decode()
    leaf = {
        "escaped-member-name": text.replace('"tenant"', '"\\u0074enant"').encode(),
        "bom": b"\xef\xbb\xbf" + good,
        "trailing-newline": good + b"\n",
        "big-int-member": (text[:-1] + ',"zz":123456789012345678901234567890}').encode(),
        "big-admitted": text.replace('"admittedAtMs":1799999000000', '"admittedAtMs":9007199254740993').encode(),
        "nan": text.replace('"admittedAtMs":1799999000000', '"admittedAtMs":NaN').encode(),
        "overflow": text.replace('"admittedAtMs":1799999000000', '"admittedAtMs":1e400').encode(),
        "repeated-member": (text[:-1] + ',"tenant":"tenant-b"}').encode(),
        "invalid-utf8": text.replace('"tenant-a"', '"tenant-\xff"').encode("latin-1"),
        "overlong-utf8": good.replace(b'"tenant-a"', b'"tenant-\xc0\xaf"'),
        "raw-surrogate-bytes": good.replace(b'"tenant-a"', b'"tenant-\xed\xa0\x80"'),
        "float-admitted": text.replace('"admittedAtMs":1799999000000', '"admittedAtMs":1799999000000.0').encode(),
    }[edit]
    assert leaf != good
    assert _refused(world, leaf, record) in {"bundle_leaf_malformed", "bundle_record_mismatch"}


def _envelope_text(key: Ed25519PrivateKey, payload: bytes) -> str:
    sig = key.sign(pae(PAYLOAD_TYPE, payload))
    return ('{"payloadType":"' + PAYLOAD_TYPE + '","payload":"' + _b64(payload) + '","signatures":[{"keyid":"","sig":"'
            + _b64(sig) + '"}]}')


def test_a_record_envelope_with_a_repeated_payload_member_is_refused() -> None:
    """json.loads keeps the last ``payload``; a verifier and a log reading one envelope must see one record."""
    world = SelfMade()
    leaf, _ = world.good()
    other = _statement(sequence=7)
    text = _envelope_text(world.source_key, _statement())
    record = (text[:-1] + ',"payload":"' + _b64(other) + '"}').encode()
    assert _refused(world, leaf, record) == "bundle_record_invalid"


def test_a_signed_statement_with_a_repeated_sequence_is_refused() -> None:
    world = SelfMade()
    payload = _statement(sequence=0)[:-1] + b',"predicate":{"runtime":{"scope":{"tenant_id":"t"},"sequence":9}}}'
    record = _envelope_text(world.source_key, payload).encode()
    with pytest.raises(ValueError):
        read_evaluator(record, world.source)


def test_a_record_with_a_bom_is_refused() -> None:
    world = SelfMade()
    leaf, record = world.good()
    assert _refused(world, leaf, b"\xef\xbb\xbf" + record) == "bundle_record_invalid"


def test_the_good_leaf_still_grades_after_every_edit_is_refused() -> None:
    world = SelfMade()
    leaf, record = world.good()
    assert leaf == canonical(leaf_entry(world.source, read_evaluator(record, world.source), 1_799_999_000_000))
    assert verify_bundle(world.bundle(leaf, record), world.trust(), NOW).grade == "S"


# --- registry: crit by escape, low-S on a validation, the naming leaf ---------------------------------------------


def _ed_sign_raw(head: bytes, claims: dict[str, Any], key: Ed25519PrivateKey) -> str:
    h, b = _b64url(head), _segment(claims)
    return f"{h}.{b}.{_b64url(key.sign(f'{h}.{b}'.encode()))}"


def test_an_issuer_jwt_that_spells_crit_with_an_escape_is_refused() -> None:
    key = Ed25519PrivateKey.generate()
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": _b64url(key.public_key().public_bytes_raw()), "kid": "k1"}
    pins = {ISSUER: registry.PinnedKeys.of(ISSUER, {"keys": [jwk]})}
    head = ('{"alg":"EdDSA","kid":"k1","typ":"' + registry.VALIDATION_TYP + '","\\u0063rit":["x"]}').encode()
    token = _ed_sign_raw(head, _validation_claims(), key)
    with pytest.raises(registry.RegistryError, match="^jws_header_critical"):
        registry.check_validation(token, pins, domain="acme.example", tenant="acme", subject=AGENT, now=CLOCK)


def test_a_key_binding_jwt_that_spells_crit_with_an_escape_is_refused() -> None:
    issuer, holder = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    salt = _b64url(b"s" * 16)
    disclosure = _b64url(json.dumps([salt, "name", "refunds"], separators=(",", ":")).encode())
    payload = {"iss": ISSUER, "sub": AGENT, "tenant": "acme", "epoch": 3, "iat": CLOCK, "exp": CLOCK + 3600,
               "cnf": {"jwk": {"kty": "OKP", "crv": "Ed25519",
                               "x": _b64url(holder.public_key().public_bytes_raw())}},
               "_sd_alg": "sha-256", "_sd": [_b64url(hashlib.sha256(disclosure.encode()).digest())]}
    jwt = _ed_sign_raw(json.dumps({"alg": "EdDSA", "kid": "k1", "typ": registry.PASSPORT_TYP}).encode(), payload, issuer)
    prefix = f"{jwt}~{disclosure}~"
    kb_claims = {"aud": "rp", "nonce": "n1", "iat": CLOCK,
                 "sd_hash": _b64url(hashlib.sha256(prefix.encode()).digest())}
    kb = _ed_sign_raw(('{"alg":"EdDSA","typ":"' + registry.KB_TYP + '","\\u0063rit":["x"]}').encode(), kb_claims, holder)
    jwks = {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": _b64url(issuer.public_key().public_bytes_raw()),
                      "kid": "k1"}]}
    with pytest.raises(registry.RegistryError, match="^passport_kb_critical"):
        registry.verify_presentation(prefix + kb, {ISSUER: registry.PinnedKeys.of(ISSUER, jwks)}, audience="rp",
                                     now=CLOCK)


def test_an_es256_validation_signed_high_s_is_refused_by_its_own_code_and_low_s_is_read() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    numbers = key.public_key().public_numbers()
    jwk = {"kty": "EC", "crv": "P-256", "x": _b64url(numbers.x.to_bytes(32, "big")),
           "y": _b64url(numbers.y.to_bytes(32, "big")), "kid": "k1"}
    pins = {ISSUER: registry.PinnedKeys.of(ISSUER, {"keys": [jwk]})}
    head, body = _segment({"alg": "ES256", "kid": "k1", "typ": registry.VALIDATION_TYP}), _segment(_validation_claims())
    r, s = decode_dss_signature(key.sign(f"{head}.{body}".encode(), ec.ECDSA(hashes.SHA256())))
    low = min(s, registry.P256_ORDER - s)
    spell = {name: f"{head}.{body}.{_b64url(r.to_bytes(32, 'big') + v.to_bytes(32, 'big'))}"
             for name, v in (("low", low), ("high", registry.P256_ORDER - low))}
    got = registry.check_validation(spell["low"], pins, domain="acme.example", tenant="acme", subject=AGENT, now=CLOCK)
    assert got.spend_key == (ISSUER, "j1")
    with pytest.raises(registry.RegistryError, match="^jws_signature_not_low_s"):
        registry.check_validation(spell["high"], pins, domain="acme.example", tenant="acme", subject=AGENT, now=CLOCK)
    # s = 0 and s = n are not signatures at all, and must not slip through as "low".
    for bad in (0, registry.P256_ORDER):
        token = f"{head}.{body}.{_b64url(r.to_bytes(32, 'big') + bad.to_bytes(32, 'big'))}"
        with pytest.raises(registry.RegistryError):
            registry.check_validation(token, pins, domain="acme.example", tenant="acme", subject=AGENT, now=CLOCK)


@pytest.mark.parametrize("edit", ["repeated-member", "invalid-utf8", "deep"])
def test_a_log_signed_naming_leaf_the_reader_refuses_is_naming_leaf_malformed(edit: str) -> None:
    log = Ed25519PrivateKey.generate()
    origin = "names.example/log"
    good = ('{"admittedAtMs":1,"canonicalId":"' + AGENT + '","domain":"acme.example","format":"'
            + registry.LEAF_FORMAT + '","keys":[],"name":"pay.acme.example","tenant":"acme","validation":'
            '{"digest":"' + "0" * 64 + '","expiresAt":2,"issuedAt":1,"issuer":"i","method":"dns-01"}}')
    leaf = {
        "repeated-member": (good[:-1] + ',"tenant":"evil"}').encode(),
        "invalid-utf8": good.replace('"acme"', '"ac\xffme"').encode("latin-1"),
        "deep": (good[:-1] + ',"x":' + "[" * 5000 + "]" * 5000 + "}").encode(),
    }[edit]

    class Key:
        public = log.public_key()

        def sign(self, data: bytes) -> bytes:
            return log.sign(data)

    note = w.sign_checkpoint(w.Checkpoint(origin, 1, w.leaf_hash(leaf)), Key())
    vkey = w.vkey(origin, w.SIG_ED25519, log.public_key())
    with pytest.raises(registry.RegistryError, match="^naming_leaf_malformed"):
        registry.verify_entry(registry.Inclusion(leaf, 0, (), note), vkey)


# --- stamp window and renewal -------------------------------------------------------------------------------------


@pytest.mark.parametrize("raw", [b'{"a":1,"a":1}', b'{"a":"\\ud800"}', b'{"a":"\xff"}', b'{"a":9007199254740993}',
                                 b'{"a":1e400}', b"\xef\xbb\xbf{}", b'{"a":' + b"[" * 200 + b"]" * 200 + b"}"])
def test_a_window_field_the_strict_reader_refuses_is_stamp_window_malformed(raw: bytes) -> None:
    with pytest.raises(stamp.StampRefused, match="^stamp_window_malformed"):
        stamp.window_certificate([(stamp.WINDOW_FIELD, base64.b64encode(raw).decode())])


@pytest.mark.parametrize("member", [{"note": "\ud800"}, {"note": 2**60}, {"note": float("nan")}])
def test_a_request_body_jcs_cannot_print_is_a_renewal_error_not_a_raise(member: dict[str, Any]) -> None:
    authority, key = Authority(), Instance()
    cert = _certificate(authority, key)
    start = renewal.body_digest(cert["body"])
    signed = _request(key, start)
    hostile = {"body": {**signed["body"], **member}, "sig": signed["sig"]}
    with pytest.raises(renewal.RenewalError):
        renewal.verify_chain([cert], [hostile], [authority.public])
