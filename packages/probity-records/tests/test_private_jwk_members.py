"""One list of private JWK members, read by every key reader in Python and TypeScript.

A reader that keeps its own shorter list misses a member another reader refuses: the naming registry once read seven
members and passed a key carrying ``oth`` (RFC 7518 section 6.3.2.7) that the trust bundle refused. These tests hold
``identity.PRIVATE_JWK_MEMBERS`` equal to the TypeScript ``PRIVATE_JWK_MEMBERS``, fail when any source file spells a
list of its own, and refuse a key carrying each member through every reader.
"""

from __future__ import annotations

import ast
import copy
import re
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from probity_records import (
    identity,
    possession,
    registry,
    trust_bundle,
    verified_identities,
    verified_identities_vectors,
)
from probity_records.identity_vectors import base
from probity_records.registry import RegistryError
from probity_records.trust_bundle import AnchorRefused
from probity_records.verified_identities import TrustBundle, VerifiedIdentitiesRefused

PACKAGE = Path(__file__).resolve().parents[1]
SRC = PACKAGE / "src" / "probity_records"
TS_SRC = PACKAGE.parents[1] / "node" / "probity-records-verify" / "src"
MEMBERS = ["d", "dp", "dq", "k", "oth", "p", "priv", "q", "qi"]


def _members() -> frozenset[str]:
    """Read through the module, so code without the shared set fails on an assertion that names it, not a load error."""
    found = getattr(identity, "PRIVATE_JWK_MEMBERS", None)
    assert isinstance(found, frozenset), "identity has no PRIVATE_JWK_MEMBERS: each reader keeps its own list"
    return found


def test_the_set_is_every_private_member_of_the_jwk_registries() -> None:
    """RFC 7518 sections 6.2.2, 6.3.2 and 6.4.1, RFC 8037 section 2, and the AKP key type's priv."""
    assert _members() == set(MEMBERS)


def test_the_typescript_list_is_the_same_set() -> None:
    text = (TS_SRC / "verify.ts").read_text()
    found = re.findall(r"export const PRIVATE_JWK_MEMBERS: readonly string\[\] = \[([^\]]*)\];", text)
    assert len(found) == 1, "verify.ts defines PRIVATE_JWK_MEMBERS exactly once"
    assert set(re.findall(r'"([a-z]+)"', found[0])) == _members()


def _python_lists() -> list[str]:
    """Every collection literal of strings in the package that spells two or more private members, by file:line."""
    hits = []
    for path in sorted(SRC.glob("*.py")):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Set | ast.List | ast.Tuple):
                names = {e.value for e in node.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)}
                if len(names & _members() - {"d"}) >= 2:
                    hits.append(f"{path.name}:{node.lineno}")
    return hits


def test_no_python_reader_keeps_its_own_list() -> None:
    assert _python_lists() == [f"identity.py:{_definition_line()}"]


def _definition_line() -> int:
    for node in ast.walk(ast.parse((SRC / "identity.py").read_text())):
        if isinstance(node, ast.AnnAssign) and getattr(node.target, "id", "") == "PRIVATE_JWK_MEMBERS":
            return node.value.args[0].lineno  # type: ignore[attr-defined]
    raise AssertionError("identity.py defines PRIVATE_JWK_MEMBERS")


def test_no_typescript_reader_keeps_its_own_list() -> None:
    hits = []
    for path in sorted(TS_SRC.glob("*.ts")):
        for n, line in enumerate(path.read_text().splitlines(), 1):
            for literal in re.findall(r"\[([^\[\]]*)\]", line):
                names = set(re.findall(r'"([a-z]+)"', literal))
                if len(names & _members() - {"d"}) >= 2:
                    hits.append(f"{path.name}:{n}")
    assert len(hits) == 1 and hits[0].startswith("verify.ts:"), hits


def _okp() -> dict[str, str]:
    return possession.public_jwk(verified_identities_vectors.HOLDER_KEY)


@pytest.mark.parametrize("member", MEMBERS)
def test_the_naming_registry_refuses_each_member(member: str) -> None:
    with pytest.raises(RegistryError) as caught:
        registry.published_key({"kid": "k1", "use": "receipt", "jwk": {**_okp(), member: "AQAB"}})
    assert caught.value.code == "domain_key_private_material"


@pytest.mark.parametrize("member", MEMBERS)
def test_the_principal_reader_refuses_each_member(member: str) -> None:
    v = base()
    principal = copy.deepcopy(v["principals"]["agent"])
    principal["key"][member] = "AQAB"
    assert identity.check_principal(principal, v["at"], v["pins"]) == "principal_key_invalid"


@pytest.mark.parametrize("member", MEMBERS)
def test_the_dpop_header_reader_refuses_each_member(member: str) -> None:
    with pytest.raises(possession._JwkRefused, match="dpop_jwk_private"):
        possession._load_jwk("EdDSA", {**_okp(), member: "AQAB"})


@pytest.mark.parametrize("member", MEMBERS)
def test_the_anchor_reader_refuses_each_member(member: str) -> None:
    jwk = {**_okp(), member: "AQAB"}
    entry: dict[str, Any] = {"jwk": jwk, "thumbprint": identity.jwk_thumbprint(_okp()), "role": "receipt",
                             "status": "active", "notBefore": "2026-01-01T00:00:00Z",
                             "notAfter": "2027-01-01T00:00:00Z", "predicateTypes": ["x"]}  # fmt: skip
    with pytest.raises(AnchorRefused, match="public JWK"):
        trust_bundle.parse_anchor(entry)


@pytest.mark.parametrize("member", MEMBERS)
def test_the_verified_identities_bundle_refuses_each_member(member: str) -> None:
    doc = verified_identities_vectors.bundle()
    key = doc["issuers"][verified_identities_vectors.IDP]["keys"][0]
    key[member] = "AQAB"
    with pytest.raises(VerifiedIdentitiesRefused) as caught:
        TrustBundle.parse(doc)
    assert caught.value.code == "trust_bundle_malformed"


# --- every reader, found rather than listed --------------------------------------------------------------------------
#
# A hand-written list of readers missed two (the passport holder key and the JWKS pin). These tests find every function
# in the package that reads a JWK through a key primitive and fail until each one has a refusal test below, or a stated
# reason why the keys it reads are never received ones.

#: The key primitives: each refuses private material itself, so a reader that goes through one refuses it too.
PRIMITIVES = {"identity.public_jwk", "identity.jwk_thumbprint", "registry._alg_of", "possession._load_jwk"}
#: Key constructors that build a key from bytes. A function calling one reads its bytes from a primitive, or reads
#: bytes that are no JWK; the second kind is listed here with where its bytes come from.
CONSTRUCTORS = {"from_public_bytes", "EllipticCurvePublicNumbers", "RSAPublicNumbers", "from_encoded_point"}
NOT_A_JWK = {
    "bundle.read_evaluator": "hex public key of a pinned evaluator",
    "core.load_public": "PEM or raw Ed25519 bytes of a signer the auditor pins",
    "renewal.check_certificate_body": "base64 raw Ed25519 session key of a renewal certificate",
    "signing._raw_public": "raw Ed25519 bytes of a signer's public key",
    "stamp.verify_stamp": "raw key bytes the trust bundle reader already read through identity.public_jwk",
    "witness.VerifierKey.verify": "a C2SP note verifier key",
}
#: Functions that read only keys this package made from its own key objects, never received ones.
OWN_KEYS = {
    "possession.cnf_for_jwk": "the cnf of a key the caller holds",
}


def _module_functions() -> dict[str, tuple[str, ast.AST]]:
    out: dict[str, tuple[str, ast.AST]] = {}
    for path in sorted(SRC.glob("*.py")):
        if path.stem.endswith("_vectors"):
            continue  # vector builders: keys the generator made itself

        def walk(node: ast.AST, prefix: str, module: str = path.stem) -> None:
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef):
                    out[f"{module}.{prefix}{child.name}"] = (module, child)
                    walk(child, f"{prefix}{child.name}.")
                elif isinstance(child, ast.ClassDef):
                    walk(child, f"{prefix}{child.name}.")
        walk(ast.parse(path.read_text()), "")
    return out


def _resolver(module: str) -> dict[str, str]:
    """Local name -> qualified name for the names a module defines and the names it imports from the package."""
    tree = ast.parse((SRC / f"{module}.py").read_text())
    names = {n.name: f"{module}.{n.name}" for n in tree.body if isinstance(n, ast.FunctionDef | ast.ClassDef)}
    for n in tree.body:
        if isinstance(n, ast.ImportFrom) and n.level == 1 and n.module:
            names.update({a.asname or a.name: f"{n.module}.{a.name}" for a in n.names})
    return names


def _called(module: str, fn: ast.AST) -> set[str]:
    names, out = _resolver(module), set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            f = node.func
            local = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)
            if local is not None:
                out.add(names.get(local, local))
    return out


def _readers() -> set[str]:
    return {q for q, (m, fn) in _module_functions().items() if _called(m, fn) & PRIMITIVES and q not in PRIMITIVES}


def test_every_key_constructor_reads_its_bytes_from_a_primitive_or_reads_no_jwk() -> None:
    found = {q for q, (m, fn) in _module_functions().items()
             if _called(m, fn) & CONSTRUCTORS and not _called(m, fn) & PRIMITIVES and q not in PRIMITIVES}
    assert found == set(NOT_A_JWK), f"read a JWK through identity.public_jwk, or say why: {sorted(found ^ set(NOT_A_JWK))}"


def test_every_reader_found_has_a_refusal_test() -> None:
    found = _readers()
    assert found, "the discovery found no reader: the scan is broken, not the package clean"
    assert found == set(READERS) | set(OWN_KEYS), f"give each a refusal test in READERS: {sorted(found ^ (set(READERS) | set(OWN_KEYS)))}"


def _ed() -> tuple[Any, dict[str, str]]:
    key = Ed25519PrivateKey.generate()
    raw = key.public_key().public_bytes_raw()
    return key, {"kty": "OKP", "crv": "Ed25519", "x": identity.b64url(raw)}


def _refuses_signature(verify: Any) -> Any:
    def check(member: str) -> None:
        key, jwk = _ed()
        sig = key.sign(b"data")
        assert verify(jwk, sig), "the control (no private member) must verify, or the refusal proves nothing"
        assert not verify({**jwk, member: "AQAB"}, sig)
    return check


def _raises(exc: type[BaseException], call: Any, code: str | None = None) -> Any:
    def check(member: str) -> None:
        _, jwk = _ed()
        with pytest.raises(exc) as caught:
            call({**jwk, "kid": "k1", member: "AQAB"})
        if code is not None:
            assert getattr(caught.value, "code", str(caught.value)) == code
    return check


def _presentation(member: str) -> None:
    from test_r6g_verify_attacks import (  # the verifier's own builders
        ISSUER,
        _okp,
        _sign,
    )

    issuer, holder = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    payload = {"iss": ISSUER, "sub": "agt_" + "a" * 26, "tenant": "acme", "epoch": 3, "iat": 1_800_000_000,
               "exp": 1_800_003_600, "cnf": {"jwk": {**_okp(holder), member: "AQAB"}}}  # fmt: skip
    jwt = _sign({"alg": "EdDSA", "kid": "k1", "typ": registry.PASSPORT_TYP}, payload, issuer)
    pins = {ISSUER: registry.PinnedKeys.of(ISSUER, {"keys": [{**_okp(issuer), "kid": "k1"}]})}
    with pytest.raises(RegistryError) as caught:
        registry.verify_presentation(f"{jwt}~kb", pins, audience="rp", now=1_800_000_000)
    assert caught.value.code == "passport_holder_invalid"


def _principal(member: str) -> None:
    test_the_principal_reader_refuses_each_member(member)


def _bundle(member: str) -> None:
    test_the_verified_identities_bundle_refuses_each_member(member)


def _anchor(member: str) -> None:
    test_the_anchor_reader_refuses_each_member(member)


def _header(member: str) -> None:
    _, jwk = _ed()
    head = {"typ": "dpop+jwt", "alg": "EdDSA", "jwk": {**jwk, member: "AQAB"}}
    segment = identity.b64url(__import__("json").dumps(head).encode())
    assert possession._header(segment, identity.jwk_thumbprint(jwk))[2] == "dpop_jwk_private"


def _select(member: str) -> None:
    _, jwk = _ed()
    pinned = registry.PinnedKeys("https://i.example", ({**jwk, "kid": "k1", member: "AQAB"},), frozenset())
    with pytest.raises(RegistryError) as caught:
        pinned.select("k1")
    assert caught.value.code == "jws_key_invalid"


def _raw(member: str) -> None:
    # The exception class is named when the check runs, not when the table is built: on code before the class
    # existed the module still collects, and each check fails on its own.
    _raises(identity.PrivateKeyMaterial, verified_identities._raw)(member)


READERS: dict[str, Any] = {
    "identity.check_principal": _principal,
    "identity._verify_jws": _refuses_signature(lambda jwk, sig: identity._verify_jws("EdDSA", jwk, b"data", sig)),
    "registry.verify_signature": _refuses_signature(lambda jwk, sig: registry.verify_signature("EdDSA", jwk, b"data", sig)),
    "registry.PinnedKeys.of": _raises(ValueError, lambda k: registry.PinnedKeys.of("https://i.example", {"keys": [k]})),
    "registry.PinnedKeys.select": _select,
    "registry.published_key": _raises(RegistryError, lambda k: registry.published_key({"kid": "k1", "use": "receipt",
                                                                                         "jwk": k}),
                                      "domain_key_private_material"),
    "registry.verify_presentation": _presentation,
    "possession._header": _header,
    "trust_bundle._public": _raises(AnchorRefused, trust_bundle._public),
    "trust_bundle.parse_anchor": _anchor,
    "verified_identities._issuer": _bundle,
    "verified_identities._raw": _raw,
}


@pytest.mark.parametrize("member", MEMBERS)
@pytest.mark.parametrize("primitive", sorted(PRIMITIVES))
def test_every_key_primitive_refuses_each_member(primitive: str, member: str) -> None:
    _, jwk = _ed()
    bad = {**jwk, member: "AQAB"}
    if primitive == "registry._alg_of":
        assert registry._alg_of(jwk) == "EdDSA" and registry._alg_of(bad) is None
    elif primitive == "possession._load_jwk":
        with pytest.raises(possession._JwkRefused, match="dpop_jwk_private"):
            possession._load_jwk("EdDSA", bad)
    else:
        fn = getattr(identity, primitive.split(".")[1])
        fn(jwk)
        with pytest.raises(identity.PrivateKeyMaterial):
            fn(bad)


@pytest.mark.parametrize("member", MEMBERS)
@pytest.mark.parametrize("reader", sorted(READERS))
def test_every_reader_found_refuses_each_member(reader: str, member: str) -> None:
    READERS[reader](member)
