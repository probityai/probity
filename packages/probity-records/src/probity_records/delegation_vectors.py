"""Conformance vectors for the session-key certificate ``probity-key-delegation/v2`` (``signing``).

Each vector is ``{"id", "description", "certificate", "roots", "covers", "expected"}``. ``roots`` are the pinned root
public keys, raw and base64; ``expected`` is ``{"refused": <code>}`` or ``{"delegation": {...}}``, the members a reader
returns for an accepted certificate (scope, window, root and session key ids). ``covers`` lists instants and whether the
accepted certificate's half-open window [notBefore, notAfter) holds each. Keys and times are fixed and Ed25519 signs
deterministically, so the file is byte-identical on every run. The file is written by ``scripts/gen_shared_vectors.py``
as ``vectors/shared/delegation.json``; a reader parses it keeping integers and floats apart (``windowS`` 600.0 is a
float and refused).
"""

from __future__ import annotations

import copy
import hashlib
from collections.abc import Callable
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .core import _b64, canonical, key_id
from .signing import DELEGATION_DOMAIN, DELEGATION_FORMAT, verify_delegation

NOT_BEFORE, NOT_AFTER = "2026-11-23T12:00:00.000000Z", "2026-11-23T12:10:00.000000Z"
WINDOW_S = 600


def _key(seed: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(seed.encode()).digest())


ROOT, OTHER_ROOT, UNPINNED = _key("deleg2/root"), _key("deleg2/other-root"), _key("deleg2/unpinned")
SESSION = _key("deleg2/session")


def _raw(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _id(key: Ed25519PrivateKey) -> str:
    return key_id(key.public_key())


def body(root: Ed25519PrivateKey = ROOT, **members: Any) -> dict[str, Any]:
    """A well-formed v2 body naming ``root``; ``members`` replace members or add ones the format does not define."""
    out: dict[str, Any] = {"custody": "ours", "format": DELEGATION_FORMAT, "hierarchy": "record",
                           "notAfter": NOT_AFTER, "notBefore": NOT_BEFORE, "rootKeyId": _id(root),
                           "rootProvenance": {"backend": "local"}, "sessionKey": _b64(_raw(SESSION)),
                           "tenant": "tenant-a", "windowS": WINDOW_S}
    out.update(members)
    return out


def signed(content: dict[str, Any], root: Ed25519PrivateKey = ROOT,
           domain: bytes = DELEGATION_DOMAIN) -> dict[str, Any]:
    return {"body": content, "sig": _b64(root.sign(domain + canonical(content)))}


def _without(member: str) -> dict[str, Any]:
    out = body()
    del out[member]
    return signed(out)


def _edit(cert: dict[str, Any], edit: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
    out = copy.deepcopy(cert)
    edit(out)
    return out


def _v1() -> dict[str, Any]:
    old = {"format": "probity-key-delegation/v1", "notAfter": NOT_AFTER, "notBefore": NOT_BEFORE,
           "rootKeyId": _id(ROOT), "rootProvenance": {"backend": "local", "probityScope": {
               "custody": "ours", "hierarchy": "record", "tenant": "tenant-a", "windowS": WINDOW_S}},
           "sessionKey": _b64(_raw(SESSION))}
    return signed(old, domain=b"probity-key-delegation-v1\x00")


GOOD = signed(body())
COVERS = [
    {"at": NOT_BEFORE, "description": "the notBefore instant is inside"},
    {"at": "2026-11-23T11:59:59.999999Z", "description": "one microsecond before notBefore is outside"},
    {"at": "2026-11-23T12:09:59.999999Z", "description": "one microsecond before notAfter is inside"},
    {"at": NOT_AFTER, "description": "the notAfter instant is outside (half-open)"},
    {"at": "2026-11-23T13:05:00+01:00", "description": "an explicit offset names the same instant: inside"},
    {"at": "2026-11-23T13:10:00+01:00", "description": "notAfter written with an offset is still outside"},
    {"at": "2026-11-23T12:05:00", "description": "an instant with no offset names no instant: outside"},
    {"at": "2026-11-23 12:05:00Z", "description": "outside the timestamp grammar: outside"},
]

#: (id, description, certificate, pinned roots, the code a reader must refuse with, or None for an accepted one).
CASES: list[tuple[str, str, Any, list[Ed25519PrivateKey], str | None]] = [
    ("DG01", "a record window key under a root in our custody", GOOD, [ROOT], None),
    ("DG02", "an authority window key under a customer-held root, the second of two pinned roots",
     signed(body(OTHER_ROOT, hierarchy="authority", custody="customer", tenant="acme"), OTHER_ROOT),
     [ROOT, OTHER_ROOT], None),
    ("DG03", "an identity window key under a custodian's root, whole-second times, the window exactly as declared",
     signed(body(hierarchy="identity", custody="custodian", notBefore="2026-11-23T12:00:00Z",
                 notAfter="2026-11-23T12:10:00Z")), [ROOT], None),
    ("DG04", "a v1 certificate, scope inside rootProvenance: refused by name", _v1(), [ROOT],
     "delegation_format_retired"),
    ("DG05", "an unknown format", signed(body(format="probity-key-delegation/v3")), [ROOT],
     "delegation_format_unknown"),
    ("DG06", "the certificate carries a member beside body and sig", _edit(GOOD, lambda c: c.update(note="x")),
     [ROOT], "delegation_shape"),
    ("DG07", "the body is not an object", {"body": [GOOD["body"]], "sig": GOOD["sig"]}, [ROOT], "delegation_shape"),
    ("DG08", "the signature is not canonical base64", _edit(GOOD, lambda c: c.update(sig=c["sig"].rstrip("="))),
     [ROOT], "delegation_shape"),
    ("DG09", "a member the format does not define", signed(body(probityScope={"tenant": "tenant-a"})), [ROOT],
     "delegation_members_invalid"),
    ("DG10", "no tenant member", _without("tenant"), [ROOT], "delegation_members_invalid"),
    ("DG11", "a hierarchy the format does not define", signed(body(hierarchy="witness")), [ROOT],
     "delegation_hierarchy_invalid"),
    ("DG12", "custody named by a word the format does not define", signed(body(custody="tenant")), [ROOT],
     "delegation_custody_invalid"),
    ("DG13", "a record root the customer holds", signed(body(custody="customer")), [ROOT],
     "delegation_record_root_customer_custody"),
    ("DG14", "a tenant with a space", signed(body(tenant="tenant a")), [ROOT], "delegation_tenant_invalid"),
    ("DG15", "an empty tenant", signed(body(tenant="")), [ROOT], "delegation_tenant_invalid"),
    ("DG16", "a tenant of 257 characters", signed(body(tenant="t" * 257)), [ROOT], "delegation_tenant_invalid"),
    ("DG17", "a tenant outside printable ASCII", signed(body(tenant="tenant-é")), [ROOT],
     "delegation_tenant_invalid"),
    ("DG18", "a declared window of zero seconds", signed(body(windowS=0)), [ROOT], "delegation_window_invalid"),
    ("DG19", "a declared window written as a float", signed(body(windowS=600.0)), [ROOT],
     "delegation_window_invalid"),
    ("DG20", "a declared window written as true", signed(body(windowS=True)), [ROOT], "delegation_window_invalid"),
    ("DG21", "a declared window written as text", signed(body(windowS="600")), [ROOT], "delegation_window_invalid"),
    ("DG22", "notAfter with a +00:00 offset rather than Z", signed(body(notAfter="2026-11-23T12:10:00+00:00")),
     [ROOT], "delegation_time_invalid"),
    ("DG23", "notBefore with seven fraction digits", signed(body(notBefore="2026-11-23T12:00:00.0000000Z")),
     [ROOT], "delegation_time_invalid"),
    ("DG24", "notAfter equal to notBefore", signed(body(notAfter=NOT_BEFORE)), [ROOT], "delegation_window_empty"),
    ("DG25", "a window one microsecond longer than declared", signed(body(notAfter="2026-11-23T12:10:00.000001Z")),
     [ROOT], "delegation_window_exceeds_declared"),
    ("DG26", "rootProvenance is a list", signed(body(rootProvenance=["local"])), [ROOT],
     "delegation_root_provenance_invalid"),
    ("DG27", "a session key of 31 bytes", signed(body(sessionKey=_b64(_raw(SESSION)[:31]))), [ROOT],
     "delegation_session_key_invalid"),
    ("DG28", "the tenant changed after the root signed", _edit(GOOD, lambda c: c["body"].update(tenant="tenant-b")),
     [ROOT], "delegation_unverified"),
    ("DG29", "the hierarchy changed after the root signed",
     _edit(GOOD, lambda c: c["body"].update(hierarchy="authority")), [ROOT], "delegation_unverified"),
    ("DG30", "signed by a root nobody pinned", signed(body(UNPINNED), UNPINNED), [ROOT], "delegation_unverified"),
    ("DG31", "the pinned root signed a body naming another root key", signed(body(rootKeyId=_id(OTHER_ROOT))),
     [ROOT], "delegation_root_key_id_mismatch"),
]


def _accepted(cert: dict[str, Any], roots: list[Ed25519PrivateKey]) -> dict[str, Any]:
    d = verify_delegation(cert, [r.public_key() for r in roots])
    return {"delegation": {**d.scope.members(), "notAfter": d.not_after, "notBefore": d.not_before,
                           "rootKeyId": d.root_key_id, "sessionKeyId": d.session_key_id}}


def _judge(cert: Any, roots: list[Ed25519PrivateKey]) -> dict[str, Any]:
    try:
        return _accepted(cert, roots)
    except ValueError as exc:
        return {"refused": str(exc)}


def vectors() -> list[dict[str, Any]]:
    """Every case with this package's own verdict; a case whose verdict is not the one it was written for raises."""
    rows = []
    for vid, description, cert, roots, code in CASES:
        expected = _judge(cert, roots)
        if expected.get("refused") != code:
            raise AssertionError(f"{vid}: expected {code}, got {expected}")
        covers: list[dict[str, Any]] = []
        if code is None:
            d = verify_delegation(cert, [r.public_key() for r in roots])
            covers = [{**c, "expected": d.covers(c["at"])} for c in (COVERS if vid == "DG01" else COVERS[:4])]
        rows.append({"certificate": cert, "covers": covers, "description": description, "expected": expected,
                     "id": vid, "roots": [_b64(_raw(r)) for r in roots]})
    return rows


def check(rows: list[dict[str, Any]]) -> list[str]:
    """The vector ids whose verdict this package does not reproduce from the file's own bytes."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    from .core import _unb64

    bad = []
    for row in rows:
        roots = [Ed25519PublicKey.from_public_bytes(_unb64(r)) for r in row["roots"]]
        try:
            d = verify_delegation(row["certificate"], roots)
            got: dict[str, Any] = {"delegation": {**d.scope.members(), "notAfter": d.not_after,
                                                  "notBefore": d.not_before, "rootKeyId": d.root_key_id,
                                                  "sessionKeyId": d.session_key_id}}
            covers_ok = all(d.covers(c["at"]) == c["expected"] for c in row["covers"])
        except ValueError as exc:
            got, covers_ok = {"refused": str(exc)}, not row["covers"]
        if got != row["expected"] or not covers_ok:
            bad.append(row["id"])
    return bad
