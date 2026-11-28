"""Attacks of the r6g verify round: private key material in the passport and pin readers, and DPoP proofs the two
verified-identities readers judge differently (a target URI with characters Python's urlsplit strips, an x5c whose
base64 Python refuses and Node decodes)."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from probity_records import registry

PACKAGE = Path(__file__).resolve().parents[1]
PARITY = PACKAGE / "tests" / "parity_r6c"
sys.path.insert(0, str(PARITY))
from gen_cases import verdict
from signed_edits import HOLDER_CERT, _proof_parts, _proof_signer, sign_proof

ISSUER = "https://passport.example.com"
CLOCK = 1_800_000_000


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _sign(head: dict[str, Any], claims: dict[str, Any], key: Ed25519PrivateKey) -> str:
    h = _b64url(json.dumps(head, separators=(",", ":")).encode())
    b = _b64url(json.dumps(claims, separators=(",", ":")).encode())
    return f"{h}.{b}.{_b64url(key.sign(f'{h}.{b}'.encode()))}"


def _okp(key: Ed25519PrivateKey) -> dict[str, str]:
    return {"kty": "OKP", "crv": "Ed25519", "x": _b64url(key.public_key().public_bytes_raw())}


def test_a_passport_whose_holder_key_carries_private_material_is_refused() -> None:
    """A cnf key whose private half the passport publishes proves nobody holds it (R-B); the DPoP header reader
    refuses the same key as dpop_jwk_private, so the passport reader refuses it as passport_holder_invalid."""
    issuer, holder = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    salt = _b64url(b"s" * 16)
    disclosure = _b64url(json.dumps([salt, "name", "refunds"], separators=(",", ":")).encode())
    payload = {"iss": ISSUER, "sub": "agt_" + "a" * 26, "tenant": "acme", "epoch": 3, "iat": CLOCK,
               "exp": CLOCK + 3600, "cnf": {"jwk": {**_okp(holder), "d": _b64url(b"\x01" * 32)}},
               "_sd_alg": "sha-256", "_sd": [_b64url(hashlib.sha256(disclosure.encode()).digest())]}
    jwt = _sign({"alg": "EdDSA", "kid": "k1", "typ": registry.PASSPORT_TYP}, payload, issuer)
    prefix = f"{jwt}~{disclosure}~"
    kb = _sign({"alg": "EdDSA", "typ": registry.KB_TYP},
               {"aud": "rp", "nonce": "n1", "iat": CLOCK, "sd_hash": _b64url(hashlib.sha256(prefix.encode()).digest())},
               holder)  # fmt: skip
    pins = {ISSUER: registry.PinnedKeys.of(ISSUER, {"keys": [{**_okp(issuer), "kid": "k1"}]})}
    with pytest.raises(registry.RegistryError) as caught:
        registry.verify_presentation(prefix + kb, pins, audience="rp", now=CLOCK)
    assert caught.value.code == "passport_holder_invalid"


def test_a_pin_whose_jwks_key_carries_private_material_is_refused() -> None:
    """A JWKS that publishes an issuer's private key is no trust anchor: anyone can sign as that issuer."""
    key = Ed25519PrivateKey.generate()
    with pytest.raises(ValueError):
        registry.PinnedKeys.of(ISSUER, {"keys": [{**_okp(key), "kid": "k1", "d": _b64url(b"\x01" * 32)}]})


# --- the differential: signed DPoP edits the generator does not make ---------------------------------------------

def _x5c_respelled() -> str:
    """The holder's certificate in a base64 spelling Python's b64decode(validate=True) refuses and Node decodes."""
    text = base64.b64encode(HOLDER_CERT).decode()
    return text.rstrip("=") if text.endswith("=") else text + "=="


HTU_EDITS = {
    "htu-leading-space": lambda url: " " + url,
    "htu-leading-nul": lambda url: "\x00" + url,
    "htu-tab-in-path": lambda url: url[: len(url) - 3] + "\t" + url[len(url) - 3:],
    "htu-trailing-newline": lambda url: url + "\n",
}


def _cases() -> list[dict[str, Any]]:
    rows = json.loads((PACKAGE / "vectors" / "shared" / "verified_identities.json").read_text())
    cases = []
    for row in rows:
        proof = (row.get("request") or {}).get("dpop")
        if not isinstance(proof, str) or proof.count(".") != 2:
            continue
        head, body = _proof_parts(proof)
        key = _proof_signer(head)
        if key is None:
            continue
        edits: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
        if isinstance(body.get("htu"), str):
            edits += [(name, head, {**body, "htu": f(body["htu"])}) for name, f in HTU_EDITS.items()]
        edits.append(("x5c-holder-respelled", {**head, "x5c": [_x5c_respelled()]}, body))
        for name, h, b in edits:
            r = copy.deepcopy(row)
            r["request"]["dpop"] = sign_proof(key, h, b)
            cases.append({"case": f"{row['id']}/r6g/{name}", "kind": "request", "row": r})
    for c in cases:
        c["python"] = verdict(c["kind"], c["row"])
    return cases


def test_both_readers_judge_every_signed_htu_and_x5c_respelling_alike(tmp_path: Path) -> None:
    cases = _cases()
    assert cases, "no shared row carries a DPoP proof the fixture keys signed"
    (tmp_path / "cases.json").write_text(json.dumps(cases, ensure_ascii=True))
    subprocess.run(["node", str(PARITY / "judge_ts.ts"), str(tmp_path / "cases.json"), str(tmp_path / "ts.json")],
                   cwd=PACKAGE, check=True, capture_output=True)  # fmt: skip
    ts = json.loads((tmp_path / "ts.json").read_text())
    differ = sorted({"/".join(c["case"].split("/")[-1:]) + f" py={json.dumps(c['python'])[:60]} "
                     f"ts={json.dumps(ts.get(c['case']))[:60]}" for c in cases if c["python"] != ts.get(c["case"])})
    assert not differ, f"{len(differ)} edit kinds judged differently: " + " | ".join(differ)
