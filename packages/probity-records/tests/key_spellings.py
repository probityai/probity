"""Second spellings of one public key, shared by test_key_spellings.py and parity_r6c/gen_cases.py.

Each edit keeps the key (or a key the lenient reader decodes to the same bytes or number) and changes only its text,
and ``lenient_thumbprint`` is the RFC 7638 thumbprint a reader computes without checking the members, so a bundle can
pin the second spelling. ``identity.public_jwk`` refuses every one of them.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from collections.abc import Callable
from typing import Any

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
MEMBERS = {"RSA": ("e", "kty", "n"), "EC": ("crv", "kty", "x", "y"), "OKP": ("crv", "kty", "x")}


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def unb64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _stray_bits(text: str) -> str:
    """The same bytes with nonzero unused low bits in the last digit (RFC 4648 section 3.5)."""
    if len(text) % 4 not in (2, 3):
        return text + " "
    return text[:-1] + ALPHABET[ALPHABET.index(text[-1]) | 1]


TEXT_EDITS: dict[str, Callable[[str], Any]] = {
    "padded": lambda s: s + "=" * (-len(s) % 4 or 4),
    "space": lambda s: s[:4] + " " + s[4:],
    "newline": lambda s: s[:4] + "\n" + s[4:],
    "std-alphabet": lambda s: s.replace("-", "+").replace("_", "/") if ("-" in s or "_" in s) else s + "+",
    "stray-bits": _stray_bits,
    "leading-zero": lambda s: b64u(b"\0" + unb64u(s)),
    "short": lambda s: b64u(unb64u(s)[1:]),
    "not-a-string": lambda s: len(s),
}


#: A key's name members (kty, crv) given as another JSON type or as a prototype member name. A reader that turns the
#: value into a string first (JavaScript ``String(["P-256"])`` is ``"P-256"``) or looks it up in a plain object
#: (``{}["constructor"]``) reads a second spelling of the key, or raises.
NAME_EDITS: dict[str, Callable[[str], Any]] = {
    "in-a-list": lambda s: [s],
    "not-a-string": lambda s: len(s),
    "prototype-name": lambda s: "constructor",
}
KEY_MEMBERS = ("x", "y", "n", "e")
NAME_MEMBERS = ("kty", "crv")


def lenient_thumbprint(jwk: dict[str, Any], kty: str | None = None) -> str:
    """The thumbprint over the members of ``kty`` (default: the key's own), read without checking any of them."""
    members = MEMBERS[kty if kty is not None else str(jwk["kty"])]
    data = json.dumps({m: jwk[m] for m in members}, sort_keys=True, separators=(",", ":")).encode()
    return b64u(hashlib.sha256(data).digest())


def key_edits(row: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Every row copy with one bundle key member respelled and its pin moved to the respelled key's thumbprint.

    Each string x, y, n or e gets every TEXT_EDITS spelling and each string kty or crv every NAME_EDITS one, so the
    count is fixed by the rows: sum over bundle keys of 8 x (string key members) + 3 x (string name members)."""
    bundle = row.get("bundle")
    if not isinstance(bundle, dict) or not isinstance(bundle.get("issuers"), dict):
        return []
    out = []
    for issuer, entry in bundle["issuers"].items():
        for k, jwk in enumerate(entry.get("keys", [])):
            if not isinstance(jwk, dict) or jwk.get("kty") not in MEMBERS:
                continue
            old = lenient_thumbprint(jwk)
            plan = [(m, TEXT_EDITS) for m in KEY_MEMBERS if isinstance(jwk.get(m), str)]
            plan += [(m, NAME_EDITS) for m in NAME_MEMBERS if isinstance(jwk.get(m), str)]
            for member, edits in plan:
                for name, edit in edits.items():
                    r = copy.deepcopy(row)
                    key = r["bundle"]["issuers"][issuer]["keys"][k]
                    key[member] = edit(jwk[member])
                    for pin in r["bundle"]["issuers"][issuer]["pins"]:
                        if pin.get("thumbprint") == old:
                            pin["thumbprint"] = lenient_thumbprint(key, str(jwk["kty"]))
                    out.append((f"{row['id']}/key/{issuer}/{k}/{member}/{name}", r))
    return out
