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
from probity_records import (
    identity,
    possession,
    registry,
    trust_bundle,
    verified_identities_vectors,
)
from probity_records.identity_vectors import base
from probity_records.registry import RegistryError
from probity_records.trust_bundle import AnchorRefused
from probity_records.verified_identities import TrustBundle, VerifiedIdentitiesRefused

PACKAGE = Path(__file__).resolve().parents[1]
SRC = PACKAGE / "src" / "probity_records"
TS_SRC = PACKAGE.parents[1] / "node" / "probity-records-verify" / "src"
MEMBERS = sorted(identity.PRIVATE_JWK_MEMBERS)


def test_the_set_is_every_private_member_of_the_jwk_registries() -> None:
    """RFC 7518 sections 6.2.2, 6.3.2 and 6.4.1, RFC 8037 section 2, and the AKP key type's priv."""
    assert identity.PRIVATE_JWK_MEMBERS == {"d", "p", "q", "dp", "dq", "qi", "oth", "k", "priv"}


def test_the_typescript_list_is_the_same_set() -> None:
    text = (TS_SRC / "verify.ts").read_text()
    found = re.findall(r"export const PRIVATE_JWK_MEMBERS: readonly string\[\] = \[([^\]]*)\];", text)
    assert len(found) == 1, "verify.ts defines PRIVATE_JWK_MEMBERS exactly once"
    assert set(re.findall(r'"([a-z]+)"', found[0])) == identity.PRIVATE_JWK_MEMBERS


def _python_lists() -> list[str]:
    """Every collection literal of strings in the package that spells two or more private members, by file:line."""
    hits = []
    for path in sorted(SRC.glob("*.py")):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Set | ast.List | ast.Tuple):
                names = {e.value for e in node.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)}
                if len(names & identity.PRIVATE_JWK_MEMBERS - {"d"}) >= 2:
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
                if len(names & identity.PRIVATE_JWK_MEMBERS - {"d"}) >= 2:
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
