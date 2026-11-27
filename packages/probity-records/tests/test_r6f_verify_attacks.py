"""Attacks of the r6f verify round on the key readers and on the Python/TypeScript differential."""

from __future__ import annotations

import base64
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from probity_records import registry
from probity_records.registry import RegistryError

PACKAGE = Path(__file__).resolve().parents[1]
SRC = PACKAGE / "src" / "probity_records"


def _okp() -> dict[str, str]:
    raw = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {"kty": "OKP", "crv": "Ed25519", "x": base64.urlsafe_b64encode(raw).rstrip(b"=").decode()}


def test_a_published_key_carrying_oth_is_private_material() -> None:
    """RFC 7518 section 6.3.2.7: ``oth`` holds the other primes, their exponents and coefficients of a multi-prime RSA
    private key. trust_bundle and verified_identities refuse it as private material; the naming registry must too."""
    jwk = {**_okp(), "oth": [{"r": "AQAB", "d": "AQAB", "t": "AQAB"}]}
    with pytest.raises(RegistryError) as caught:
        registry.published_key({"kid": "k1", "use": "receipt", "jwk": jwk})
    assert caught.value.code == "domain_key_private_material"


def _reader_codes() -> set[str]:
    """Every registered refusal code the verified-identities reader and its possession checks spell in their source."""
    registered = {c["code"] for c in json.loads((SRC / "refusal_codes.json").read_text())["codes"]}
    text = (SRC / "verified_identities.py").read_text() + (SRC / "possession.py").read_text()
    return {code for code in re.findall(r'"([a-z][a-z0-9_]+)"', text) if code in registered}


def test_the_differential_reaches_every_refusal_code_the_reader_can_give(tmp_path: Path) -> None:
    """A code no generated case reaches is never compared between the two readers, so its parity is unproven."""
    out = tmp_path / "cases.json"
    subprocess.run([sys.executable, str(PACKAGE / "tests" / "parity_r6c" / "gen_cases.py"),
                    str(PACKAGE / "vectors" / "shared" / "verified_identities.json"), str(out)],
                   check=True, cwd=PACKAGE, capture_output=True)
    reached = {c["python"]["refused"] for c in json.loads(out.read_text())
               if isinstance(c["python"], dict) and "refused" in c["python"]}
    missing = sorted(_reader_codes() - reached)
    assert not missing, f"{len(missing)} codes no differential case reaches: {' '.join(missing)}"
