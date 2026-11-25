"""The registry formats a verifier reads offline: pinned-key JWS, domain key documents, naming log entries, passports.

Every document is built here with the test's own keys, so each refusal is reached from the bytes a verifier is handed.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from importlib import resources
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from probity_records import registry, witness
from probity_records.identity import jwk_thumbprint
from probity_records.registry import RegistryError

NOW = datetime(2026, 11, 21, 12, 0, tzinfo=UTC)
CLOCK = int(NOW.timestamp())
AGENT = "agt_" + "a" * 26
OTHER = "agt_" + "b" * 26
ISSUER = "https://validator.example"
ORIGIN = "names.example/log"


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def jwk_of(key: Ed25519PrivateKey) -> dict[str, str]:
    return {"crv": "Ed25519", "kty": "OKP", "x": b64(key.public_key().public_bytes_raw())}


def segment(value: Any) -> str:
    return b64(json.dumps(value, separators=(",", ":"), sort_keys=True).encode())


def sign(header: dict[str, Any], claims: dict[str, Any], key: Ed25519PrivateKey) -> str:
    head, body = segment(header), segment(claims)
    return f"{head}.{body}.{b64(key.sign(f'{head}.{body}'.encode()))}"


def pinned(issuer: str, key: Ed25519PrivateKey, kid: str = "k1") -> dict[str, registry.PinnedKeys]:
    return {issuer: registry.PinnedKeys.of(issuer, {"keys": [{**jwk_of(key), "kid": kid}]})}


def raises(code: str):  # type: ignore[no-untyped-def]
    return pytest.raises(RegistryError, match=f"^{code}(:|$)")


# --- the JWS under pinned keys ---------------------------------------------------------------------------------


def claims_of(**extra: Any) -> dict[str, Any]:
    return {"iss": ISSUER, "iat": CLOCK, "exp": CLOCK + 600, **extra}


def test_a_token_under_a_pinned_key_verifies_and_returns_its_claims() -> None:
    key = Ed25519PrivateKey.generate()
    token = sign({"alg": "EdDSA", "kid": "k1", "typ": "t+jwt"}, claims_of(a=1), key)
    got = registry.verify_jws(token, pinned(ISSUER, key), typ=("t+jwt",))
    assert got.claims["a"] == 1 and got.header["kid"] == "k1"


@pytest.mark.parametrize("text", ["abc=", "a b", "é", "AB", "A"])
def test_only_the_canonical_unpadded_base64url_spelling_is_read(text: str) -> None:
    with raises("jws_malformed"):
        registry.unb64url(text)


def test_a_repeated_member_nan_or_deep_nesting_is_refused() -> None:
    for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b"[" * 5000 + b"]" * 5000, b"\xff"):
        with raises("jws_duplicate_member" if b'"a":1,"a"' in raw else "jws_malformed"):
            registry.strict_json(raw)


@pytest.mark.parametrize("member", ["jku", "jwk", "x5u", "x5c"])
def test_a_header_that_names_its_own_key_is_refused(member: str) -> None:
    key = Ed25519PrivateKey.generate()
    token = sign({"alg": "EdDSA", "kid": "k1", "typ": "t+jwt", member: "x"}, claims_of(), key)
    with raises("jws_header_names_a_key"):
        registry.verify_jws(token, pinned(ISSUER, key), typ=("t+jwt",))


def test_a_header_that_demands_an_extension_is_refused() -> None:
    key = Ed25519PrivateKey.generate()
    token = sign({"alg": "EdDSA", "kid": "k1", "typ": "t+jwt", "crit": ["x"]}, claims_of(), key)
    with raises("jws_header_critical"):
        registry.verify_jws(token, pinned(ISSUER, key), typ=("t+jwt",))


def test_the_type_issuer_kid_pin_and_signature_are_each_held() -> None:
    key, other = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    head = {"alg": "EdDSA", "kid": "k1", "typ": "t+jwt"}
    pins = pinned(ISSUER, key)
    with raises("jws_type_mismatch"):
        registry.verify_jws(sign({**head, "typ": "x"}, claims_of(), key), pins, typ=("t+jwt",))
    with raises("jws_issuer_untrusted"):
        registry.verify_jws(sign(head, claims_of(iss="https://rival.example"), key), pins, typ=("t+jwt",))
    with raises("jws_kid_unknown"):
        registry.verify_jws(sign({**head, "kid": "zz"}, claims_of(), key), pins, typ=("t+jwt",))
    with raises("jws_signature_unverified"):
        registry.verify_jws(sign(head, claims_of(), other), pins, typ=("t+jwt",))
    with raises("jws_signature_unverified"):
        registry.verify_jws(sign({**head, "alg": "none"}, claims_of(), key), pins, typ=("t+jwt",))
    snapshot = {"keys": [{**jwk_of(key), "kid": "k1"}]}
    narrow = {ISSUER: registry.PinnedKeys.of(ISSUER, snapshot, frozenset({jwk_thumbprint(jwk_of(other))}))}
    with raises("jws_key_not_pinned"):
        registry.verify_jws(sign(head, claims_of(), key), narrow, typ=("t+jwt",))
    broken = {ISSUER: registry.PinnedKeys.of(ISSUER, {"keys": [{"kid": "k1", "kty": "OKP"}]})}
    with raises("jws_key_invalid"):
        registry.verify_jws(sign(head, claims_of(), key), broken, typ=("t+jwt",))


@pytest.mark.parametrize("token", ["a.b", "a..c", "a.b.c.d", "é.b.c", "x" * (70 << 10)])
def test_a_compact_jws_has_three_ascii_bounded_segments(token: str) -> None:
    with raises("jws_malformed"):
        registry.split(token)


def test_claims_that_are_not_an_object_or_an_integer_are_refused() -> None:
    key = Ed25519PrivateKey.generate()
    head = {"alg": "EdDSA", "kid": "k1", "typ": "t+jwt"}
    with raises("jws_malformed"):
        registry.verify_jws(sign(head, [1], key), pinned(ISSUER, key), typ=("t+jwt",))  # type: ignore[arg-type]
    with raises("jws_claim_invalid"):
        registry.int_claim({"iat": True}, "iat")
    with raises("jws_claim_invalid"):
        registry.int_claim({}, "iat")


# --- domain-control validation ---------------------------------------------------------------------------------


def validation(key: Ed25519PrivateKey, **over: Any) -> str:
    claims = claims_of(domain="acme.example", tenant="acme", sub=AGENT, method="dns-01", jti="j1", **over)
    return sign({"alg": "EdDSA", "kid": "k1", "typ": registry.VALIDATION_TYP}, claims, key)


def check(token: str, key: Ed25519PrivateKey, **over: Any) -> registry.Validation:
    args: dict[str, Any] = {"domain": "acme.example", "tenant": "acme", "subject": AGENT, "now": CLOCK, **over}
    return registry.check_validation(token, pinned(ISSUER, key), **args)


def test_a_validation_signed_by_a_pinned_validator_for_this_name_is_read() -> None:
    key = Ed25519PrivateKey.generate()
    got = check(validation(key), key)
    assert (got.domain, got.method, got.digest) == (
        "acme.example", "dns-01", hashlib.sha256(validation(key).encode()).hexdigest())


@pytest.mark.parametrize("over", [{"domain": "rival.example"}, {"tenant": "rival"}, {"subject": OTHER}])
def test_a_validation_names_one_domain_tenant_and_id(over: dict[str, str]) -> None:
    key = Ed25519PrivateKey.generate()
    with raises("dcv_validation_mismatch"):
        check(validation(key), key, **over)


def test_a_validation_has_a_method_a_jti_and_a_reuse_window() -> None:
    key = Ed25519PrivateKey.generate()
    with raises("dcv_validation_malformed"):
        check(validation(key, method="carrier-pigeon"), key)
    with raises("dcv_validation_expired"):
        check(validation(key), key, now=CLOCK + 600)
    with raises("dcv_validation_not_yet_valid"):
        check(validation(key, iat=CLOCK + 5000, exp=CLOCK + 5600), key)
    with raises("dcv_validation_lifetime_invalid"):
        check(validation(key, exp=CLOCK + registry.VALIDATION_REUSE_S + 1), key)


@pytest.mark.parametrize("bad", ["localhost", "acme..example", "-acme.example", "acme.example.", "acme.123",
                                 " acme.example", "über.example"])
def test_a_domain_is_one_comparable_name(bad: str) -> None:
    with raises("domain_invalid"):
        registry.domain_name(bad)
    assert registry.domain_name("Acme.Example") == "acme.example"


# --- the key document under the owner's domain ----------------------------------------------------------------


def name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


@dataclass
class Authority:
    cn: str = "Test Root"
    key: Any = field(default_factory=lambda: ec.generate_private_key(ec.SECP256R1()))

    def __post_init__(self) -> None:
        self.cert = (
            x509.CertificateBuilder().subject_name(name(self.cn)).issuer_name(name(self.cn))
            .public_key(self.key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(NOW - timedelta(days=30)).not_valid_after(NOW + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(self.key.public_key()), critical=False)
            .sign(self.key, hashes.SHA256())
        )  # fmt: skip

    def leaf(self, host: str, days: int = 90) -> bytes:
        key = ec.generate_private_key(ec.SECP256R1())
        cert = (
            x509.CertificateBuilder().subject_name(name(host)).issuer_name(self.cert.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(NOW - timedelta(days=1)).not_valid_after(NOW + timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()), critical=False)
            .sign(self.key, hashes.SHA256())
        )  # fmt: skip
        return cert.public_bytes(Encoding.DER)


def document(host: str, keys: list[dict[str, Any]], not_after: str = "2027-01-01T00:00:00Z", **extra: Any) -> bytes:
    body = {"format": registry.KEY_DOCUMENT_FORMAT, "domain": host, "keys": keys, "notAfter": not_after, **extra}
    return json.dumps(body).encode()


def receipt_entry(kid: str = "r1", use: str = "receipt") -> dict[str, Any]:
    return {"kid": kid, "use": use, "jwk": jwk_of(Ed25519PrivateKey.generate())}


HOST = "payments.example"


def test_a_key_document_pinned_with_its_chain_binds_grade_i_independent_of_the_tenant() -> None:
    ca = Authority()
    leaf = ca.leaf(HOST)
    pin = registry.pin_key_document(HOST, document(HOST, [receipt_entry()]), [leaf], [ca.cert], NOW)
    binding = registry.bind_from_document(HOST, pin, "r1", "receipt", at=NOW)
    assert (binding.grade, binding.label, binding.independent_of, binding.bound_by) == (
        "I", None, ("tenant",), "domain-document")
    assert binding.evidence["leafSha256"] == hashlib.sha256(leaf).hexdigest() == pin.leaf_sha256
    assert registry.bind_rail_operator(HOST, pin, "r1", at=NOW).bound_by == "rail-operator"


def test_a_chain_for_another_name_or_root_or_time_or_none_is_refused() -> None:
    ca, rogue = Authority(), Authority("Rogue Root")
    body = document(HOST, [receipt_entry()])
    with raises("domain_chain_unverified"):
        registry.pin_key_document(HOST, body, [ca.leaf("tenant.example")], [ca.cert], NOW)
    with raises("domain_chain_unverified"):
        registry.pin_key_document(HOST, body, [rogue.leaf(HOST)], [ca.cert], NOW)
    with raises("domain_chain_unverified"):
        registry.pin_key_document(HOST, body, [ca.leaf(HOST, days=10)], [ca.cert], NOW + timedelta(days=11))
    with raises("domain_chain_missing"):
        registry.pin_key_document(HOST, body, [], [ca.cert], NOW)
    with raises("domain_roots_missing"):
        registry.pin_key_document(HOST, body, [ca.leaf(HOST)], [], NOW)
    with raises("domain_chain_invalid"):
        registry.pin_key_document(HOST, body, [b"not der"], [ca.cert], NOW)
    with raises("domain_document_too_large"):
        registry.pin_key_document(HOST, body + b" " * (registry.MAX_KEY_DOCUMENT_BYTES + 1), [ca.leaf(HOST)],
                                  [ca.cert], NOW)


def test_a_document_for_another_domain_expired_malformed_or_with_private_keys_is_refused() -> None:
    ca = Authority()
    chain = [ca.leaf(HOST)]
    entry = receipt_entry()

    def pin(body: bytes) -> registry.PinnedKeyDocument:
        return registry.pin_key_document(HOST, body, chain, [ca.cert], NOW)

    with raises("domain_document_wrong_domain"):
        pin(document("tenant.example", [entry]))
    with raises("domain_document_expired"):
        pin(document(HOST, [entry], not_after="2026-11-01T00:00:00Z"))
    with raises("domain_document_malformed"):
        pin(document(HOST, [entry], extra="x"))
    with raises("domain_document_malformed"):
        pin(document(HOST, [entry], not_after="2027-01-01"))
    with raises("domain_document_malformed"):
        pin(document(HOST, [entry], not_after="not-a-timeE".replace("E", "Z")))
    with raises("domain_document_malformed"):
        pin(json.dumps({"format": "other/v9", "domain": HOST, "keys": [entry], "notAfter": "2027-01-01T00:00:00Z"}
                       ).encode())
    with raises("domain_key_private_material"):
        pin(document(HOST, [{**entry, "jwk": {**entry["jwk"], "d": "AAAA"}}]))
    with raises("domain_key_malformed"):
        pin(document(HOST, []))
    with raises("domain_key_malformed"):
        pin(document(HOST, [entry, entry]))
    with raises("domain_key_malformed"):
        pin(document(HOST, [{**entry, "use": "signing"}]))
    with raises("domain_key_unsupported"):
        pin(document(HOST, [{**entry, "jwk": {"kty": "oct", "k2": "x"}}]))
    with raises("domain_key_unsupported"):
        pin(document(HOST, [{**entry, "jwk": {"kty": "OKP", "crv": "Ed25519"}}]))


def test_a_pin_binds_only_its_own_domain_kid_use_and_time() -> None:
    ca = Authority()
    pin = registry.pin_key_document(HOST, document(HOST, [receipt_entry()]), [ca.leaf(HOST)], [ca.cert], NOW)
    with raises("domain_document_wrong_domain"):
        registry.bind_from_document("other.example", pin, "r1", "receipt", at=NOW)
    with raises("domain_key_unknown"):
        registry.bind_from_document(HOST, pin, "r2", "receipt", at=NOW)
    with raises("domain_key_wrong_use"):
        registry.bind_from_document(HOST, pin, "r1", "passport-issuer", at=NOW)
    with raises("domain_document_expired"):
        registry.bind_from_document(HOST, pin, "r1", "receipt", at=datetime(2027, 1, 1, tzinfo=UTC))
    with pytest.raises(ValueError, match="zone"):
        registry.bind_from_document(HOST, pin, "r1", "receipt", at=datetime(2026, 11, 21))


def test_a_key_the_tenant_declares_is_graded_w_and_labelled() -> None:
    binding = registry.bind_tenant_declared(HOST, jwk_of(Ed25519PrivateKey.generate()), "r1")
    assert (binding.grade, binding.label, binding.independent_of) == ("W", "tenant-declared counterparty", ())


# --- the naming log's entries and heads -------------------------------------------------------------------------


class LogKey:
    def __init__(self) -> None:
        self.private = Ed25519PrivateKey.generate()
        self.public = self.private.public_key()

    def sign(self, data: bytes) -> bytes:
        return self.private.sign(data)


def entry_of(label: str = "pay", canonical_id: str = AGENT, tenant: str = "acme", keys: Any = None,
             **over: Any) -> dict[str, Any]:
    return {
        "format": registry.LEAF_FORMAT, "name": f"{label}.acme.example", "domain": "acme.example",
        "canonicalId": canonical_id, "tenant": tenant,
        "validation": {"issuer": ISSUER, "method": "dns-01", "issuedAt": CLOCK, "expiresAt": CLOCK + 600,
                       "digest": hashlib.sha256(label.encode()).hexdigest()},
        "keys": [receipt_entry()] if keys is None else keys, "admittedAtMs": CLOCK * 1000, **over}  # fmt: skip


@dataclass
class Log:
    key: LogKey = field(default_factory=LogKey)
    entries: list[dict[str, Any]] = field(default_factory=list)

    def add(self, entry: dict[str, Any]) -> int:
        self.entries.append(entry)
        return len(self.entries) - 1

    @property
    def vkey(self) -> witness.VerifierKey:
        return witness.vkey(ORIGIN, witness.SIG_ED25519, self.key.public)

    def leaves(self) -> list[bytes]:
        return [registry.leaf_bytes(e) for e in self.entries]

    def checkpoint(self, size: int | None = None) -> str:
        hashes_ = [witness.leaf_hash(b) for b in self.leaves()][:size]
        return witness.sign_checkpoint(witness.Checkpoint(ORIGIN, len(hashes_), witness.root(hashes_)), self.key)

    def inclusion(self, index: int, checkpoint: str | None = None) -> registry.Inclusion:
        text = checkpoint or self.checkpoint()
        size = witness.parse_checkpoint(witness.parse_note(text).text).size
        hashes_ = [witness.leaf_hash(b) for b in self.leaves()][:size]
        return registry.Inclusion(self.leaves()[index], index, tuple(witness.inclusion_proof(index, hashes_)), text)

    def head(self, label: str, index: int, at_ms: int = CLOCK * 1000, origin: str = ORIGIN) -> str:
        text = f"{registry.HEAD_FORMAT}\n{origin}\n{label}\n{index}\n{at_ms}\n"
        line = witness.SigLine(ORIGIN, witness.note_key_id(ORIGIN, witness.SIG_ED25519,
                                                           self.key.public.public_bytes_raw()),
                               self.key.sign(text.encode()))
        return witness.Note(text, (line,)).encode()


def test_an_entry_in_the_signed_tree_is_read_and_a_moved_leaf_is_not() -> None:
    log = Log()
    index = log.add(entry_of())
    log.add(entry_of("billing", OTHER))
    good = log.inclusion(index)
    assert registry.verify_entry(good, log.vkey)["canonicalId"] == AGENT
    swapped = replace(good, leaf=good.leaf.replace(AGENT.encode(), OTHER.encode()))
    with raises("naming_inclusion_unverified"):
        registry.verify_entry(swapped, log.vkey)
    with raises("naming_inclusion_unverified"):
        registry.verify_entry(replace(good, index=1), log.vkey)


def test_a_checkpoint_under_another_key_or_origin_or_garbled_is_refused() -> None:
    log = Log()
    index = log.add(entry_of())
    good = log.inclusion(index)
    rogue = witness.vkey(ORIGIN, witness.SIG_ED25519, Ed25519PrivateKey.generate().public_key())
    with raises("naming_checkpoint_unsigned"):
        registry.verify_entry(good, rogue)
    with raises("naming_checkpoint_invalid"):
        registry.verify_entry(replace(good, checkpoint="garbage"), log.vkey)
    foreign = witness.Checkpoint("other/log", 1, witness.root([witness.leaf_hash(good.leaf)])).text()
    line = witness.SigLine(ORIGIN, witness.note_key_id(ORIGIN, witness.SIG_ED25519,
                                                       log.key.public.public_bytes_raw()),
                           log.key.sign(foreign.encode()))
    with raises("naming_checkpoint_invalid"):
        registry.verify_entry(replace(good, checkpoint=witness.Note(foreign, (line,)).encode()), log.vkey)
    forged = witness.sign_checkpoint(witness.Checkpoint("other/log", 1, witness.root([witness.leaf_hash(good.leaf)])),
                                     log.key)
    with raises("naming_checkpoint_unsigned"):
        registry.verify_entry(replace(good, checkpoint=forged), log.vkey)
    badsig = witness.Note(good.checkpoint.split("\n\n")[0] + "\n", (replace(line, sig=b"\x00" * 64),)).encode()
    with raises("naming_checkpoint_invalid"):
        registry.verify_entry(replace(good, checkpoint=badsig), log.vkey)


@pytest.mark.parametrize("edit", [
    lambda e: {**e, "format": "other/v1"},
    lambda e: {**e, "extra": 1},
    lambda e: {k: v for k, v in e.items() if k != "tenant"},
    lambda e: {**e, "name": "pay.rival.example"},
    lambda e: {**e, "name": "Pay.acme.example"},
    lambda e: {**e, "name": AGENT + ".acme.example"},
    lambda e: {**e, "canonicalId": "agt_short"},
    lambda e: {**e, "tenant": 7},
    lambda e: {**e, "admittedAtMs": True},
    lambda e: {**e, "validation": {**e["validation"], "method": "x"}},
    lambda e: {**e, "validation": {**e["validation"], "extra": 1}},
    lambda e: {**e, "validation": {**e["validation"], "digest": "zz"}},
    lambda e: {**e, "keys": "none"},
])
def test_a_leaf_that_is_not_exactly_the_naming_entry_is_refused(edit) -> None:  # type: ignore[no-untyped-def]
    log = Log()
    index = log.add(edit(entry_of()))
    with raises("naming_leaf_malformed"):
        registry.verify_entry(log.inclusion(index), log.vkey)


def test_a_leaf_that_is_not_canonical_json_is_refused() -> None:
    log = Log()
    body = json.dumps(entry_of(), indent=1).encode()
    hashes_ = [witness.leaf_hash(body)]
    cp = witness.sign_checkpoint(witness.Checkpoint(ORIGIN, 1, witness.root(hashes_)), log.key)
    with raises("naming_leaf_malformed"):
        registry.verify_entry(registry.Inclusion(body, 0, (), cp), log.vkey)


def bind(log: Log, index: int, label: str = "pay", **over: Any) -> registry.KeyBinding:
    args: dict[str, Any] = {"head": log.head(f"{label}.acme.example", index), "now_ms": CLOCK * 1000,
                            "tenant": "buyer", **over}
    return registry.bind_from_naming(log.inclusion(index), log.vkey, "acme.example", "r1", "receipt", **args)


def test_a_current_entry_binds_grade_i_to_another_tenant_and_w_to_its_own() -> None:
    log = Log()
    index = log.add(entry_of())
    got = bind(log, index)
    assert (got.grade, got.bound_by, got.independent_of, got.label) == ("I", "naming-log", ("tenant",), None)
    assert got.evidence["index"] == index
    own = bind(log, index, tenant="acme")
    assert (own.grade, own.label, own.independent_of) == ("W", "tenant-declared counterparty", ())


def test_a_head_that_is_stale_for_another_name_or_a_newer_leaf_binds_nothing() -> None:
    log = Log()
    first = log.add(entry_of())
    second = log.add(entry_of("pay", OTHER, keys=[receipt_entry("r2")]))
    log.add(entry_of("billing", OTHER))
    with raises("naming_entry_superseded"):
        bind(log, first, head=log.head("pay.acme.example", second))
    with raises("naming_head_stale"):
        bind(log, first, now_ms=CLOCK * 1000 + registry.HEAD_MAX_AGE_MS + 1)
    with raises("naming_head_stale"):
        bind(log, first, now_ms=CLOCK * 1000 - registry.HEAD_SKEW_MS - 1)
    with raises("naming_head_wrong_name"):
        bind(log, first, head=log.head("billing.acme.example", first))
    with raises("naming_head_invalid"):
        bind(log, first, head=log.head("pay.acme.example", first, origin="other/log"))
    with raises("naming_head_invalid"):
        bind(log, first, head="not a note")
    rogue = Log()
    with raises("naming_head_unsigned"):
        bind(log, first, head=rogue.head("pay.acme.example", first).replace(ORIGIN, ORIGIN))
    with raises("naming_head_invalid"):
        bind(log, first, head=log.head("pay.acme.example", first).replace("\n0\n", "\n00\n"))


def test_a_binding_needs_the_target_domain_the_kid_and_the_use() -> None:
    log = Log()
    index = log.add(entry_of())
    head = log.head("pay.acme.example", index)
    inclusion = log.inclusion(index)
    kw: dict[str, Any] = {"head": head, "now_ms": CLOCK * 1000, "tenant": "buyer"}
    with raises("naming_wrong_domain"):
        registry.bind_from_naming(inclusion, log.vkey, "rival.example", "r1", "receipt", **kw)
    with raises("domain_key_unknown"):
        registry.bind_from_naming(inclusion, log.vkey, "acme.example", "r9", "receipt", **kw)
    with raises("domain_key_wrong_use"):
        registry.bind_from_naming(inclusion, log.vkey, "acme.example", "r1", "passport-issuer", **kw)


# --- passports --------------------------------------------------------------------------------------------------


def digest(disclosure: str) -> str:
    return b64(hashlib.sha256(disclosure.encode()).digest())


def disclosure(name_: str, value: Any, salt: bytes = b"s" * 16) -> str:
    return segment([b64(salt), name_, value]).replace(" ", "")


@dataclass
class Passport:
    issuer: Ed25519PrivateKey = field(default_factory=Ed25519PrivateKey.generate)
    holder: Ed25519PrivateKey = field(default_factory=Ed25519PrivateKey.generate)
    disclosures: dict[str, str] = field(default_factory=lambda: {"name": disclosure("name", "refunds")})

    def payload(self, **over: Any) -> dict[str, Any]:
        base = {"iss": ISSUER, "sub": AGENT, "tenant": "acme", "epoch": 3, "iat": CLOCK, "exp": CLOCK + 3600,
                "jti": "p1", "cnf": {"jwk": jwk_of(self.holder)}, "_sd_alg": "sha-256",
                "_sd": sorted(digest(d) for d in self.disclosures.values())}
        return {**base, **over}

    def jwt(self, **over: Any) -> str:
        return sign({"alg": "EdDSA", "kid": "k1", "typ": registry.PASSPORT_TYP}, self.payload(**over), self.issuer)

    def present(self, jwt: str | None = None, names: tuple[str, ...] = ("name",), audience: str = "rp",
                nonce: str = "n1", holder: Ed25519PrivateKey | None = None, sd_hash: str | None = None,
                iat: int = CLOCK, header: dict[str, Any] | None = None,
                extra: tuple[str, ...] = ()) -> str:
        prefix = "~".join([jwt or self.jwt(), *[self.disclosures[n] for n in names], *extra]) + "~"
        claims = {"aud": audience, "nonce": nonce, "iat": iat,
                  "sd_hash": sd_hash or b64(hashlib.sha256(prefix.encode()).digest())}
        head = header or {"alg": "EdDSA", "kid": "holder", "typ": registry.KB_TYP}
        return prefix + sign(head, claims, holder or self.holder)

    def verify(self, text: str, **over: Any) -> registry.VerifiedPassport:
        args: dict[str, Any] = {"audience": "rp", "now": CLOCK, **over}
        return registry.verify_presentation(text, pinned(ISSUER, self.issuer), **args)


def test_a_presentation_with_possession_and_chosen_disclosures_verifies() -> None:
    p = Passport()
    got = p.verify(p.present())
    assert got.disclosed == {"name": "refunds"} and got.subject == AGENT and got.epoch == 3
    assert got.holder_jkt == jwk_thumbprint(jwk_of(p.holder)) and got.nonce == "n1" and got.expires_at == CLOCK + 3600
    assert p.verify(p.present(names=())).disclosed == {}


def test_a_passport_without_a_key_binding_or_by_another_key_proves_nobody() -> None:
    p = Passport()
    with raises("passport_no_possession"):
        p.verify(p.jwt() + "~" + p.disclosures["name"] + "~")
    with raises("passport_possession_unproven"):
        p.verify(p.present(holder=Ed25519PrivateKey.generate()))
    with raises("passport_malformed"):
        p.verify("no tildes")
    with raises("passport_malformed"):
        p.verify(p.jwt() + "~~" + p.present().split("~", 1)[1])


@pytest.mark.parametrize(("over", "code"), [
    ({"audience": "other"}, "passport_kb_wrong_audience"),
    ({"sd_hash": "AAAA"}, "passport_kb_sd_hash_mismatch"),
    ({"iat": CLOCK - 301}, "passport_kb_stale"),
    ({"iat": CLOCK + 61}, "passport_kb_stale"),
    ({"nonce": ""}, "passport_kb_malformed"),
    ({"header": {"alg": "EdDSA", "kid": "h", "typ": "jwt"}}, "passport_kb_malformed"),
    ({"header": {"alg": "EdDSA", "kid": "h", "typ": "kb+jwt", "jwk": {"kty": "OKP"}}}, "passport_kb_names_a_key"),
])
def test_the_key_binding_holds_audience_hash_age_nonce_and_type(over: dict[str, Any], code: str) -> None:
    p = Passport()
    with raises(code):
        p.verify(p.present(**over))


def test_the_passport_times_and_claims_are_held() -> None:
    p = Passport()
    with raises("passport_expired"):
        p.verify(p.present(), now=CLOCK + 3600)
    with raises("passport_not_yet_valid"):
        p.verify(p.present(), now=CLOCK - 61)
    with raises("passport_lifetime_invalid"):
        p.verify(p.present(p.jwt(exp=CLOCK + registry.MAX_LIFE_S + 1)))
    with raises("passport_malformed"):
        p.verify(p.present(p.jwt(sub="not-an-id")))
    with raises("passport_malformed"):
        p.verify(p.present(p.jwt(epoch=0)))
    with raises("passport_holder_invalid"):
        p.verify(p.present(p.jwt(cnf={"jwk": {"kty": "oct"}})))
    with raises("passport_holder_invalid"):
        p.verify(p.present(p.jwt(cnf={"jwk": jwk_of(p.holder), "x": 1})))
    with raises("passport_sd_alg_unsupported"):
        p.verify(p.present(p.jwt(_sd_alg="sha-512")))
    with raises("passport_malformed"):
        p.verify(p.present(p.jwt(_sd=["a", "a"])))


def test_disclosures_are_held_to_what_the_issuer_signed() -> None:
    p = Passport()
    p.disclosures["extra"] = disclosure("extra", 1, b"t" * 16)
    unsigned = Passport(p.issuer, p.holder, {"name": p.disclosures["name"]})
    with raises("passport_disclosure_unreferenced"):
        unsigned.verify(p.present(unsigned.jwt(), names=("name", "extra")))
    with raises("passport_disclosure_repeated"):
        p.verify(p.present(names=("name",), extra=(p.disclosures["name"],)))
    for bad, code in [(disclosure("cnf", 1), "passport_disclosure_reserved"),
                      (disclosure("sub", 1), "passport_disclosure_reserved"),
                      (disclosure("name", 1, b"short"), "passport_disclosure_malformed"),
                      (segment(["only-two", "x"]), "passport_disclosure_malformed"),
                      (segment([7, "name", 1]), "passport_disclosure_malformed")]:
        q = Passport(p.issuer, p.holder, {"x": bad})
        with raises(code):
            q.verify(q.present(names=("x",)))
    twin = Passport(p.issuer, p.holder, {"a": disclosure("name", 1, b"u" * 16), "b": disclosure("name", 2, b"v" * 16)})
    with raises("passport_disclosure_repeated"):
        twin.verify(twin.present(names=("a", "b")))


# --- the codes this module holds ---------------------------------------------------------------------------------


def test_every_registered_registry_code_is_reached_by_this_file() -> None:
    registry_json = json.loads(resources.files("probity_records").joinpath("refusal_codes.json").read_text("utf-8"))
    held = {e["code"] for e in registry_json["codes"] if e["check"].startswith("registry.")}
    here = Path(__file__).read_text("utf-8")
    source = resources.files("probity_records").joinpath("registry.py").read_text("utf-8")
    assert held
    assert {c for c in held if f'"{c}"' not in here and f'raises("{c}")' not in here and c not in here} == set()
    assert {c for c in held if f'"{c}"' not in source} == set()
