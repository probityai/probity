"""Differential edits that keep a signature valid: the edited token or DPoP proof is signed again by the key that signed
it, so the case reaches the checks after the signature (time, act chains, cnf, the request, the client certificate),
which a byte edit of a signed segment never passes. Every edit applies to every shared row where its target exists.

``request_edits(row)`` yields (name, row) for the verified-identities reader. ``possession_cases(rows)``,
``record_cases(rows)`` and ``spent_cases(rows)`` yield (name, case) for the possession checks a request never reaches
alone: check_possession with no access token or no cnf, possession_record_problem and duplicate_proofs.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from probity_records import verified_identities_vectors as v
from probity_records.identity import _verify_jws, b64url
from probity_records.possession import cnf_for_certificate, cnf_for_jwk, public_jwk

Row = dict[str, Any]
KEYS = [v.USER_KEY, v.ROGUE_KEY, v.STAMP_KEY, v.HOLDER_KEY, v.OTHER_HOLDER, v.OTHER_STAMP_KEY, v._ec(), v._rsa()]
DIGEST = b64url(hashlib.sha256(b"another key").digest())


def _json(segment: str) -> Any:
    return json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))


def _signer(token: str) -> Any:
    """The fixture key whose signature ``token`` carries, or None (a forged row keeps its signature)."""
    try:
        head, body, sig = token.split(".")
        alg = _json(head)["alg"]
        raw = base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4))
    except (ValueError, KeyError, TypeError):
        return None
    for key in KEYS:
        if _verify_jws(str(alg), v._jwk(key, None), f"{head}.{body}".encode("ascii"), raw):
            return key
    return None


def resign(token: str, edit: Callable[[dict[str, Any]], None], *, header: bool = False) -> str | None:
    """``token`` with its claims (or its header) edited in place by ``edit`` and signed again; None when unsigned."""
    key = _signer(token)
    if key is None:
        return None
    head, body = (_json(s) for s in token.split(".")[:2])
    edit(head if header else body)
    return v._sign(key, head, body)


def _cert(start: datetime, days: int, seed: int = 7) -> bytes:
    key = v._ed(seed)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "agent-refunds")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(20261127).not_valid_before(start).not_valid_after(start + timedelta(days=days))
            .sign(key, None))  # fmt: skip
    return cert.public_bytes(serialization.Encoding.DER)


EXPIRED = _cert(datetime(2026, 1, 1, tzinfo=UTC), 30)
NOT_YET = _cert(datetime(2027, 1, 1, tzinfo=UTC), 30)
NOT_A_CERT = b"\x30\x03\x02\x01\x00"
HOLDER_CERT = _cert(datetime(2026, 11, 1, tzinfo=UTC), 60, seed=4)  # the DPoP holder key's own certificate


def _set(**members: Any) -> Callable[[dict[str, Any]], None]:
    def edit(doc: dict[str, Any]) -> None:
        for name, value in members.items():
            if value is _DROP:
                doc.pop(name, None)
            else:
                doc[name] = value
    return edit


_DROP = object()

TOKEN_EDITS: dict[str, tuple[tuple[str, ...], Callable[[dict[str, Any]], None]]] = {
    "iat-future": (("user", "agent", "sponsor"), _set(iat=v.NOW + 60, exp=v.NOW + 400)),
    "iat-at-exp": (("agent",), _set(iat=v.NOW + 300)),
    "act-sub-int": (("user",), _set(act={"sub": 5})),
    "act-sub-empty": (("user",), _set(act={"sub": ""})),
    "act-iss-empty": (("user",), _set(act={"sub": "agent-refunds", "iss": ""})),
    "act-iss-int": (("user",), _set(act={"sub": "agent-refunds", "iss": 7})),
    "act-string": (("user",), _set(act="agent-refunds")),
    "act-list": (("user",), _set(act=[{"sub": "agent-refunds"}])),
    "act-null": (("user",), _set(act=None)),
    "act-nested-bad": (("user",), _set(act={"sub": "agent-refunds", "act": {"sub": ""}})),
    "act-nested-iss": (("user",), _set(act={"sub": "agent-refunds", "act": {"sub": "orchestrator",
                                                                               "iss": "https://o.example"}})),
    "cnf-short": (("agent", "user"), _set(cnf={"jkt": "short"})),
    "cnf-null": (("agent", "user"), _set(cnf=None)),
    "cnf-list": (("agent", "user"), _set(cnf=[])),
    "cnf-empty": (("agent", "user"), _set(cnf={})),
    "cnf-two": (("agent",), _set(cnf={"jkt": DIGEST, "x5t#S256": DIGEST})),
    "cnf-other-method": (("agent",), _set(cnf={"jwk": DIGEST})),
    "cnf-nested": (("agent",), _set(cnf={"jkt": [DIGEST]})),
    "cnf-padded": (("agent",), _set(cnf={"jkt": DIGEST + "="})),
    "cnf-other-key": (("agent",), _set(cnf=cnf_for_jwk(public_jwk(v.OTHER_HOLDER)))),
    "cnf-drop": (("agent", "user"), _set(cnf=_DROP)),
}

PAIR_EDITS: dict[str, tuple[Any, Any]] = {  # (user cnf, agent cnf): both tokens bound
    "pair-other-key": (cnf_for_jwk(public_jwk(v.OTHER_HOLDER)), v.HOLDER_CNF),
    "pair-same": (v.HOLDER_CNF, v.HOLDER_CNF),
    "pair-nested-same": ({"jkt": {"a": "b"}}, {"jkt": {"a": "b"}}),
    "pair-list-same": ({"jkt": [DIGEST]}, {"jkt": [DIGEST]}),
    "pair-true-one": ({"jkt": True}, {"jkt": 1}),
    "pair-member-order": ({"jkt": DIGEST, "x5t#S256": DIGEST}, {"x5t#S256": DIGEST, "jkt": DIGEST}),
    "pair-null-null": (None, None),
}


def _proof_parts(proof: str) -> tuple[dict[str, Any], dict[str, Any]]:
    head, body, _ = proof.split(".")
    return _json(head), _json(body)


def _proof_signer(head: dict[str, Any]) -> Any:
    for key in (v.HOLDER_KEY, v.OTHER_HOLDER):
        if public_jwk(key) == head.get("jwk"):
            return key
    return None


def sign_proof(key: Any, head: dict[str, Any], body: dict[str, Any]) -> str:
    h = b64url(json.dumps(head, separators=(",", ":")).encode())
    b = b64url(json.dumps(body, separators=(",", ":")).encode())
    return f"{h}.{b}.{b64url(key.sign(f'{h}.{b}'.encode('ascii')))}"


def _ath(token: str) -> str:
    return b64url(hashlib.sha256(token.encode("ascii")).digest())


DPOP_CLAIM_EDITS: dict[str, Callable[[dict[str, Any]], None]] = {
    "htm-get": _set(htm="GET"), "htm-lower": _set(htm="post"), "htm-int": _set(htm=1),
    "htu-other": _set(htu=v.PAYOUT), "htu-query": _set(htu=v.URL + "?a=1"), "htu-int": _set(htu=5),
    "htu-port": _set(htu="https://billing.example.com:443/mcp/refund"), "htu-relative": _set(htu="/mcp/refund"),
    "ath-drop": _set(ath=_DROP), "ath-other": _set(ath=_ath("another token")), "ath-int": _set(ath=5),
    "iat-stale": _set(iat=v.NOW - 121), "iat-edge-old": _set(iat=v.NOW - 120), "iat-future": _set(iat=v.NOW + 121),
    "iat-edge-new": _set(iat=v.NOW + 120), "iat-string": _set(iat=str(v.NOW)), "iat-bool": _set(iat=True),
    "iat-drop": _set(iat=_DROP),
    "jti-empty": _set(jti=""), "jti-int": _set(jti=7), "jti-129": _set(jti="j" * 129), "jti-128": _set(jti="j" * 128),
    "jti-multibyte-129": _set(jti="é" * 64 + "j"), "jti-drop": _set(jti=_DROP),
    "content-drop": _set(ans_content_digest=_DROP), "content-null": _set(ans_content_digest=None),
    "content-other": _set(ans_content_digest=b64url(hashlib.sha256(b"{}").digest())),
    "content-int": _set(ans_content_digest=5),
}

DPOP_HEADER_EDITS: dict[str, Callable[[dict[str, Any]], None]] = {
    "typ-jwt": _set(typ="JWT"), "typ-drop": _set(typ=_DROP), "alg-rs256": _set(alg="RS256"),
    "alg-es256": _set(alg="ES256"), "alg-none": _set(alg="none"), "kid-extra": _set(kid="k1"),
    "jwk-drop": _set(jwk=_DROP), "jwk-string": _set(jwk="key"),
    "jwk-extra": lambda h: h["jwk"].__setitem__("use", "sig"),
    "jwk-d": lambda h: h["jwk"].__setitem__("d", "AQAB"), "jwk-oth": lambda h: h["jwk"].__setitem__("oth", []),
    "jwk-priv": lambda h: h["jwk"].__setitem__("priv", "AQAB"),
    "jwk-crv": lambda h: h["jwk"].__setitem__("crv", "X25519"), "jwk-x-short": lambda h: h["jwk"].__setitem__("x", "AQAB"),
    "x5c-empty": _set(x5c=[]), "x5c-string": _set(x5c="cert"), "x5c-not-base64": _set(x5c=["!!"]),
    "x5c-not-cert": _set(x5c=[base64.b64encode(NOT_A_CERT).decode()]),
    "x5c-other-key": _set(x5c=[base64.b64encode(v.certificate()).decode()]),
    "x5c-holder": _set(x5c=[base64.b64encode(HOLDER_CERT).decode()]),
    "x5c-two": _set(x5c=[base64.b64encode(HOLDER_CERT).decode()] * 2),
}


def _dpop_edits(row: Row) -> Iterator[tuple[str, Row]]:
    proof = (row.get("request") or {}).get("dpop")
    if not isinstance(proof, str) or proof.count(".") != 2:
        return
    head, body = _proof_parts(proof)
    key = _proof_signer(head)
    if key is None:
        return
    for where, table in (("claims", DPOP_CLAIM_EDITS), ("header", DPOP_HEADER_EDITS)):
        for name, edit in table.items():
            h, b = copy.deepcopy(head), copy.deepcopy(body)
            edit(h if where == "header" else b)
            r = copy.deepcopy(row)
            r["request"]["dpop"] = sign_proof(key, h, b)
            yield f"dpop-{where}/{name}", r
    r = copy.deepcopy(row)
    r["request"]["dpop"] = sign_proof(key, head, {**body, "pad": "p" * 8200})
    yield "dpop-size/too-large", r


def _cert_edits(row: Row) -> Iterator[tuple[str, Row]]:
    agent = row["tokens"].get("agent")
    request = row.get("request")
    if not isinstance(agent, str) or request is None or "x5t#S256" not in str(_signed_claim(agent, "cnf")):
        return
    for name, der, bound in (("expired", EXPIRED, EXPIRED), ("not-yet-valid", NOT_YET, NOT_YET),
                             ("not-a-certificate", NOT_A_CERT, NOT_A_CERT), ("other", EXPIRED, v.certificate()),
                             ("missing", None, v.certificate())):  # fmt: skip
        token = resign(agent, _set(cnf=cnf_for_certificate(bound)))
        if token is None:
            continue
        r = copy.deepcopy(row)
        r["tokens"]["agent"] = token
        r["request"]["clientCertificateB64"] = None if der is None else base64.b64encode(der).decode()
        yield f"mtls/{name}", r


def _signed_claim(token: str, name: str) -> Any:
    try:
        return _json(token.split(".")[1]).get(name)
    except (ValueError, IndexError, AttributeError):
        return None


def request_edits(row: Row) -> Iterator[tuple[str, Row]]:
    """Every signed edit of one shared row, named ``<row id>/<family>/<edit>[/<role>]``."""
    for name, (roles, edit) in TOKEN_EDITS.items():
        for role in roles:
            token = row["tokens"].get(role)
            new = resign(token, edit) if isinstance(token, str) else None
            if new is not None:
                r = copy.deepcopy(row)
                r["tokens"][role] = new
                yield f"{row['id']}/token-claims/{name}/{role}", r
    user, agent = row["tokens"].get("user"), row["tokens"].get("agent")
    if isinstance(user, str) and isinstance(agent, str):
        for name, (ucnf, acnf) in PAIR_EDITS.items():
            nu, na = resign(user, _set(cnf=ucnf)), resign(agent, _set(cnf=acnf))
            if nu is not None and na is not None:
                r = copy.deepcopy(row)
                r["tokens"].update(user=nu, agent=na)
                yield f"{row['id']}/token-pair/{name}", r
    for name, r in _dpop_edits(row):
        yield f"{row['id']}/{name}", r
    for name, r in _cert_edits(row):
        yield f"{row['id']}/{name}", r


# --- the possession checks a request does not reach alone ----------------------------------------------------------

def possession_cases(rows: list[Row]) -> Iterator[tuple[str, dict[str, Any]]]:
    """check_possession over each bound row's request, with the token's ath, with none, and with other cnf values."""
    for row in rows:
        request, agent = row.get("request"), row["tokens"].get("agent")
        cnf = _signed_claim(agent, "cnf") if isinstance(agent, str) else None
        if request is None or cnf is None:
            continue
        for name, c, token in (("as-presented", cnf, agent), ("no-token", cnf, None), ("other-token", cnf, "x.y.z"),
                               ("cnf-missing", None, agent), ("cnf-invalid", {"jkt": "x"}, agent),
                               ("cnf-string", "jkt", agent), ("cnf-two", {"jkt": DIGEST, "x5t#S256": DIGEST}, agent),
                               ("cnf-not-ascii-token", cnf, "tést")):  # fmt: skip
            yield f"{row['id']}/possession/{name}", {"cnf": c, "request": request, "at": row["at"], "accessToken": token}


def _record_variants(record: dict[str, Any], cnf: dict[str, Any]) -> Iterator[tuple[str, Any, Any]]:
    yield "as-recorded", record, cnf
    for member in record:
        yield f"drop-{member}", {k: x for k, x in record.items() if k != member}, cnf
    yield "extra-member", {**record, "extra": 1}, cnf
    for name, method in (("method-other", "jwt"), ("method-int", 1), ("method-list", ["dpop"]),
                         ("method-null", None), ("method-object", {"m": "dpop"})):  # fmt: skip
        yield name, {**record, "method": method}, cnf
    if record["method"] == "dpop":
        for name, iat in (("iat-string", "1"), ("iat-bool", True), ("iat-null", None), ("iat-float", 1.5)):
            yield name, {**record, "iat": iat}, cnf
        for name, jti in (("jti-empty", ""), ("jti-int", 3), ("jti-129", "j" * 129), ("jti-128", "j" * 128)):
            yield name, {**record, "jti": jti}, cnf
        yield "jkt-int", {**record, "jkt": 5}, {"jkt": 5}
    yield "cnf-other", record, {"jkt": DIGEST} if record["method"] == "dpop" else {"x5t#S256": DIGEST}
    yield "cnf-other-method", record, {"x5t#S256": DIGEST} if record["method"] == "dpop" else {"jkt": DIGEST}
    yield "cnf-not-object", record, ["jkt"]
    yield "cnf-null", record, None
    yield "not-object", [record], cnf


def record_cases(rows: list[Row]) -> Iterator[tuple[str, dict[str, Any]]]:
    """possession_record_problem over the possession record of every row whose proof verified, and its edits."""
    for row in rows:
        proof = (row.get("expected") or {}).get("proof")
        agent = row["tokens"].get("agent")
        if not isinstance(proof, dict) or not isinstance(agent, str):
            continue
        record = {k: x for k, x in proof.items() if k not in ("key", "expires")}
        for name, rec, cnf in _record_variants(record, _signed_claim(agent, "cnf")):
            yield f"{row['id']}/record/{name}", {"record": rec, "cnf": cnf}


def _authorize(n: int, record: Any, at: Any, permit: Any) -> list[Any]:
    pred: dict[str, Any] = {"phase": "authorize", "authority": {"possession": record}, "permitId": permit}
    if at is not _DROP:
        pred["at"] = at
    return [n, {"predicate": pred}]


def spent_cases(rows: list[Row]) -> Iterator[tuple[str, dict[str, Any]]]:
    """duplicate_proofs over journals that spend each verified DPoP proof once, twice, late, and at no readable time."""
    for row in rows:
        proof = (row.get("expected") or {}).get("proof")
        if not isinstance(proof, dict) or proof.get("method") != "dpop":
            continue
        rec = {k: proof[k] for k in ("iat", "jkt", "jti", "method")}
        live, late = row["at"], datetime.fromtimestamp(proof["expires"] + 1, UTC).isoformat()
        journals = {
            "once": [_authorize(1, rec, live, "p1")],
            "twice-two-permits": [_authorize(1, rec, live, "p1"), _authorize(2, rec, live, "p2")],
            "twice-one-permit": [_authorize(1, rec, live, "p1"), _authorize(2, rec, live, "p1")],
            "twice-after-expiry": [_authorize(1, rec, live, "p1"), _authorize(2, rec, late, "p2")],
            "no-permit-twice": [_authorize(1, rec, live, None), _authorize(2, rec, live, None)],
            "time-unreadable": [_authorize(1, rec, "not a time", "p1")],
            "time-int": [_authorize(1, rec, 5, "p1")],
            "time-missing": [_authorize(1, rec, _DROP, "p1")],
            "time-unreadable-second": [_authorize(1, rec, live, "p1"), _authorize(2, rec, "yesterday", "p2")],
            "iat-bool": [_authorize(1, {**rec, "iat": True}, live, "p1"), _authorize(2, {**rec, "iat": True}, live, "p2")],
            "other-phase": [[1, {"predicate": {"phase": "observe", "authority": {"possession": rec}}}]],
        }
        for name, records in journals.items():
            yield f"{row['id']}/spent/{name}", {"records": records}
