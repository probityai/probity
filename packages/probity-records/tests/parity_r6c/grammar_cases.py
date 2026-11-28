"""Differential cases generated from the grammar files (``grammar/*.json``), one family per received text.

Each production's accepted and refused texts, and the edits the grammar file lists as derived, are placed at every place
the production is read: judged alone (kinds ``timestamp``, ``uri``, ``certificate``, ``sf-bytes``) and inside a request
(a bundle anchor, a token signed again, a DPoP proof signed again, a client certificate, a stamp field). A case may carry
what the grammar says of it: ``expect`` ``accept`` (the reader takes it; with ``code``, it is at least not refused with
that code), ``refuse`` (with ``code``, by that code), and ``value`` (the exact verdict). ``compare.py`` fails on a
case either reader judges otherwise, and on a production with no accepted and no refused case in both readers.
"""

from __future__ import annotations

import base64
import copy
import json
import re
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID
from probity_records import verified_identities_vectors as v
from probity_records.identity import jwk_thumbprint
from signed_edits import (
    DIGEST,
    HOLDER_CERT,
    _proof_parts,
    _proof_signer,
    _set,
    cnf_for_certificate,
    resign,
    sign_proof,
)

GRAMMAR = Path(__file__).resolve().parents[2] / "grammar"
Row = dict[str, Any]
Case = dict[str, Any]


def grammar(name: str) -> dict[str, Any]:
    return json.loads((GRAMMAR / f"{name}.json").read_text())


def case(name: str, kind: str, row: Any, production: str, expect: str | None = None, code: str | None = None,
         **more: Any) -> Case:  # fmt: skip
    return {"case": f"grammar/{name}", "kind": kind, "row": row, "production": production, "expect": expect,
            "code": code, **more}  # fmt: skip


# --- a request, edited and signed again ---------------------------------------------------------------------------

class Rows:
    def __init__(self, rows: list[Row]) -> None:
        by_id = {r["id"]: r for r in rows}
        self.tokens, self.stamped, self.dpop, self.mtls = by_id["VI1"], by_id["VI9"], by_id["VI10"], by_id["VI11"]
        self.mtls_der = base64.b64decode(self.mtls["request"]["clientCertificateB64"])

    def token(self, role: str, edit: Callable[[dict[str, Any]], None], *, header: bool = False, row: Row | None = None) -> Row:
        out = copy.deepcopy(row or self.tokens)
        signed = resign(out["tokens"][role], edit, header=header)
        assert signed is not None, f"the {role} token is signed by no fixture key"
        out["tokens"][role] = signed
        return out

    def proof(self, edit_header: Callable[[dict[str, Any]], None] | None = None,
              edit_claims: Callable[[dict[str, Any]], None] | None = None) -> Row:  # fmt: skip
        head, body = (copy.deepcopy(part) for part in _proof_parts(self.dpop["request"]["dpop"]))
        key = _proof_signer(head)
        assert key is not None
        if edit_header is not None:
            edit_header(head)
        if edit_claims is not None:
            edit_claims(body)
        out = copy.deepcopy(self.dpop)
        out["request"]["dpop"] = sign_proof(key, head, body)
        return out

    def bundle(self, edit: Callable[[dict[str, Any]], None]) -> Row:
        out = copy.deepcopy(self.tokens)
        edit(out["bundle"])
        return out

    def anchored(self, **changes: Any) -> Row:
        key = {m: x for m, x in v._jwk(v.STAMP_KEY, None).items() if m in ("kty", "crv", "x")}
        anchor = {"jwk": key, "thumbprint": jwk_thumbprint(key), "role": "release", "status": "active",
                  "notBefore": "2026-01-01T00:00:00Z", "notAfter": None, "predicateTypes": ["https://example.com/p/v1"]}
        return self.bundle(lambda b: b.__setitem__("anchors", [{**anchor, **changes}]))

    def certificate(self, blob: bytes) -> Row:
        out = self.token("agent", _set(cnf=cnf_for_certificate(blob)), row=self.mtls)
        out["request"]["clientCertificateB64"] = base64.b64encode(blob).decode()
        return out

    def header(self, name: str, edit: Callable[[str], str], row: Row | None = None) -> Row:
        out = copy.deepcopy(row or self.stamped)
        out["request"]["headers"] = [[n, edit(val) if n.lower() == name else val] for n, val in out["request"]["headers"]]
        return out


# --- timestamps -----------------------------------------------------------------------------------------------------

OTHER_DIGITS = {"arabic-indic": 0x0660, "fullwidth": 0xFF10, "devanagari": 0x0966, "math-bold": 0x1D7CE}
ADDED = {"space": " ", "tab": "\t", "newline": "\n", "nul": "\x00", "nbsp": " ", "zero": "0", "z": "Z"}
NOT_TEXT: dict[str, Any] = {"null": None, "number": 20260101, "float": 1.5, "true": True, "list": ["2026-01-01T00:00:00Z"],
                            "object": {"0": "2026-01-01T00:00:00Z"}, "empty-list": [], "empty-object": {}}


def timestamp_cases(rows: Rows) -> Iterator[Case]:
    rule = grammar("timestamp")["productions"]["date-time"]
    site = rule["siteRefusal"]["anchor"]
    refused: list[tuple[str, Any, str]] = [(f"listed-{i}", text, code) for i, (text, code) in enumerate(rule["refuse"])]
    for i, (text, _) in enumerate(rule["accept"]):
        for script, zero in OTHER_DIGITS.items():
            for at, ch in enumerate(text):
                if "0" <= ch <= "9":
                    refused.append((f"accept-{i}-{script}-{at}", text[:at] + chr(zero + ord(ch) - 48) + text[at + 1:], rule["refusal"]))
        for name, ch in ADDED.items():
            refused.append((f"accept-{i}-{name}-before", ch + text, rule["refusal"]))
            refused.append((f"accept-{i}-{name}-after", text + ch, rule["refusal"]))
    refused += [(f"not-text-{name}", value, rule["refusal"]) for name, value in NOT_TEXT.items()]
    for i, (text, micros) in enumerate(rule["accept"]):
        yield case(f"timestamp/accept-{i}", "timestamp", {"text": text}, "timestamp#date-time", "accept", value={"micros": micros})
        yield case(f"timestamp/anchor-not-before/accept-{i}", "request", rows.anchored(notBefore=text), "timestamp#date-time", "accept")
        yield case(f"timestamp/anchor-not-after/accept-{i}", "request", rows.anchored(notAfter=text), "timestamp#date-time")
    for name, text, code in refused:
        yield case(f"timestamp/refuse-{name}", "timestamp", {"text": text}, "timestamp#date-time", "refuse", code)
        yield case(f"timestamp/anchor-not-before/refuse-{name}", "request", rows.anchored(notBefore=text), "timestamp#date-time", "refuse", site)
        if text is not None:  # null is an anchor with no end
            yield case(f"timestamp/anchor-not-after/refuse-{name}", "request", rows.anchored(notAfter=text), "timestamp#date-time", "refuse", site)


# --- integers -------------------------------------------------------------------------------------------------------

def integer_cases(rows: Rows) -> Iterator[Case]:
    rule = grammar("integer")["productions"]["exact-integer"]
    sites = rule["sites"]
    jkt = DIGEST
    for kind, values in (("accept", rule["accept"]), ("refuse", rule["refuse"])):
        for i, value in enumerate(values):
            name = f"{kind}-{i}"
            # nbf: an accepted value is read (and is then in the past or the future); a refused one is malformed.
            yield case(f"integer/token-nbf/{name}", "request", rows.token("agent", _set(nbf=value)), "integer#exact-integer",
                       "not-code" if kind == "accept" else "refuse", sites["token.nbf"])
            for claim in ("iat", "exp"):  # an accepted value may still fail "exp is after iat" with the same code
                yield case(f"integer/token-{claim}/{name}", "request", rows.token("agent", _set(**{claim: value})),
                           "integer#exact-integer", None if kind == "accept" else "refuse", sites[f"token.{claim}"])
                yield case(f"integer/user-token-{claim}/{name}", "request", rows.token("user", _set(**{claim: value})),
                           "integer#exact-integer", None if kind == "accept" else "refuse", sites[f"token.{claim}"])
            yield case(f"integer/dpop-iat/{name}", "request", rows.proof(None, _set(iat=value)), "integer#exact-integer",
                       "not-code" if kind == "accept" else "refuse", sites["dpop.iat"])
            if isinstance(value, float) and value.is_integer():
                continue  # a record case is judged after a plain JSON parse, which cannot tell 1.0 from 1; the token
                # and proof sites above carry the float spelling inside signed bytes, where both readers see it
            record = {"iat": value, "jkt": jkt, "jti": "one", "method": "dpop"}
            yield case(f"integer/record-iat/{name}", "record", {"record": record, "cnf": {"jkt": jkt}}, "integer#exact-integer",
                       "not-code" if kind == "accept" else "refuse", sites["record.iat"])
    # exp one past iat at the edge of the exact range: 2**53 and 2**53 + 1 are one double
    top = rule["bounds"]["max"]
    for name, iat, exp in (("at-the-bound", top - 1, top), ("past-the-bound", top + 1, top + 2), ("across-the-bound", top, top + 1)):
        yield case(f"integer/token-iat-exp/{name}", "request", rows.token("agent", _set(iat=iat, exp=exp)), "integer#exact-integer")


# --- target URIs ----------------------------------------------------------------------------------------------------

def uri_cases(rows: Rows) -> Iterator[Case]:
    doc = grammar("target-uri")["productions"]
    port, alphabet = doc["port"], doc["uri-text"]["alphabet"]
    host, path = "billing.example.com", "/mcp/refund"
    assert v.URL == f"https://{host}{path}"
    with_port = lambda text: f"https://{host}:{text}{path}"
    for i, (text, value) in enumerate(port["accept"]):
        yield case(f"uri/port/accept-{i}", "uri", {"text": with_port(text)}, "target-uri#port", "accept",
                   value=["https", host, value, path, ""])
        yield case(f"uri/htu-port/accept-{i}", "request", rows.proof(None, _set(htu=with_port(text))), "target-uri#port",
                   "accept" if value == 443 else "refuse", None if value == 443 else port["siteRefusal"]["dpop.htu"])
    for i, text in enumerate(port["refuse"]):
        yield case(f"uri/port/refuse-{i}", "uri", {"text": with_port(text)}, "target-uri#port", "refuse")
        yield case(f"uri/htu-port/refuse-{i}", "request", rows.proof(None, _set(htu=with_port(text))), "target-uri#port",
                   "refuse", port["siteRefusal"]["dpop.htu"])
    for zeros in port["long"]["zeros"]:
        text = "0" * zeros + "443"
        yield case(f"uri/port/long-{zeros}", "uri", {"text": with_port(text)}, "target-uri#port", "accept",
                   value=["https", host, 443, path, ""])
        yield case(f"uri/htu-port/long-{zeros}", "request", rows.proof(None, _set(htu=with_port(text))), "target-uri#port")
    for code in [*range(0x80), 0x80, 0xA0, 0xE9, 0x3002, 0x2028, 0xFF0F, 0xD800, 0x1F600]:
        ch = chr(code)
        if ch == "%":
            continue
        expect = "accept" if ch in alphabet else "refuse"
        yield case(f"uri/alphabet/path-{code:04x}", "uri", {"text": f"https://{host}/a{ch}b"}, "target-uri#uri-text", expect)
        yield case(f"uri/alphabet/host-{code:04x}", "uri", {"text": f"https://a{ch}b.example/"}, "target-uri#uri-text")
        yield case(f"uri/alphabet/htu-{code:04x}", "request", rows.proof(None, _set(htu=f"{v.URL}{ch}")), "target-uri#uri-text")
    for name, text in (("escape", "%41"), ("escape-lower", "%7e"), ("escape-short", "%4"), ("escape-not-hex", "%4g"),
                       ("escape-bare", "%"), ("escape-fullwidth", "%4１")):  # fmt: skip
        yield case(f"uri/alphabet/{name}", "uri", {"text": f"https://{host}/a{text}"}, "target-uri#uri-text",
                   "accept" if name in ("escape", "escape-lower") else "refuse")
    for name, value in NOT_TEXT.items():
        yield case(f"uri/not-text-{name}", "uri", {"text": value}, "target-uri#uri-text", "refuse")


# --- certificates ---------------------------------------------------------------------------------------------------

def _other_cert(key: Any, algorithm: Any) -> bytes:
    from datetime import UTC, datetime, timedelta

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "agent-refunds")])
    start = datetime(2026, 11, 1, tzinfo=UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(20261127).not_valid_before(start).not_valid_after(start + timedelta(days=60))
            .sign(key, algorithm))  # fmt: skip
    return cert.public_bytes(serialization.Encoding.DER)


def _nodes(der: bytes, start: int, end: int, depth: int, path: tuple[int, ...] = ()) -> list[dict[str, Any]]:
    """The DER elements of [start, end) as a tree, constructed elements opened ``depth`` levels down."""
    out: list[dict[str, Any]] = []
    at, i = start, 0
    while at < end:
        tag, length, body = der[at], der[at + 1], at + 2
        if length >= 0x80:
            count = length & 0x7F
            length = int.from_bytes(der[body:body + count], "big")
            body += count
        node: dict[str, Any] = {"tag": tag, "path": (*path, i), "body": der[body:body + length], "kids": None}
        if depth > 0 and tag & 0x20:
            node["kids"] = _nodes(der, body, body + length, depth - 1, (*path, i))
        out.append(node)
        at, i = body + length, i + 1
    return out


def _length(n: int, mode: str | None) -> bytes:
    if mode == "indefinite":
        return b"\x80"
    raw = n.to_bytes(max(1, (n.bit_length() + 7) // 8), "big")
    if mode == "long":  # one length byte more than the shortest form
        raw = (b"\x00" + raw) if n >= 0x80 else raw
        return bytes([0x80 | len(raw)]) + raw
    return bytes([n]) if n < 0x80 else bytes([0x80 | len(raw)]) + raw


def _encode(node: dict[str, Any], path: tuple[int, ...] | None = None, op: Any = None) -> bytes:
    """The DER of ``node``; the element at ``path`` is written as ``op`` says."""
    body = b"".join(_encode(k, path, op) for k in node["kids"]) if node["kids"] is not None else node["body"]
    tag, mode, copies = node["tag"], None, 1
    if path == node["path"]:
        if op in ("long", "indefinite"):
            mode = op
        elif op == "tag":
            tag = 0x05 if tag == 0x04 else 0x04
        elif op == "drop":
            return b""
        elif op == "twice":
            copies = 2
        else:
            tag, body = op
    return (bytes([tag]) + _length(len(body), mode) + body + (b"\x00\x00" if mode == "indefinite" else b"")) * copies


def _flat(nodes: list[dict[str, Any]]) -> Iterator[dict[str, Any]]:
    for node in nodes:
        yield node
        if node["kids"] is not None:
            yield from _flat(node["kids"])


def certificate_edits(der: bytes) -> Iterator[tuple[str, bytes, str | None]]:
    """(name, bytes, expect) for one certificate: the grammar's derived edits of x509.json."""
    rule = grammar("x509")["productions"]
    root = _nodes(der, 0, len(der), 3)[0]
    assert _encode(root) == der
    pem = x509.load_der_x509_certificate(der).public_bytes(serialization.Encoding.PEM)
    yield "unchanged", der, "accept"
    for name, blob in (("pem", pem), ("pem-no-newline", pem.rstrip(b"\n")), ("then-a-byte", der + b"\x00"), ("twice", der * 2),
                       ("then-another", der + HOLDER_CERT), ("short-by-one", der[:-1]), ("empty", b""), ("one-byte", der[:1]),
                       ("after-a-byte", b"\x00" + der), ("high-tag", b"\x3f\x00" + der[1:]),
                       ("base64-text", base64.b64encode(der))):  # fmt: skip
        yield name, blob, "refuse"
    tbs = root["kids"][0]
    version = next((k for k in tbs["kids"] if k["tag"] == 0xA0), None)
    validity = tbs["kids"][(1 if version else 0) + 3]
    opened = {root["path"], *(k["path"] for k in root["kids"]), *(k["path"] for k in tbs["kids"]),
              *(k["path"] for k in validity["kids"]), *(k["path"] for k in (version["kids"] if version else []))}
    for node in _flat([root]):
        where = "-".join(map(str, node["path"]))
        walked = node["path"] in opened
        for op in ("long", "indefinite"):
            # an element the outline does not open is bytes to both readers, so its own encoding is not judged
            yield f"{op}-length-{where}", _encode(root, node["path"], op), "refuse" if walked else None
        if walked:
            for op in ("tag", "drop", "twice"):
                yield f"{op}-{where}", _encode(root, node["path"], op), None
    for which, node in zip(("not-before", "not-after"), validity["kids"], strict=True):
        for i, text in enumerate(rule["time"]["refuseTexts"]):
            for tag in (0x17, 0x18):
                yield f"{which}-text-{i}-tag-{tag:02x}", _encode(root, node["path"], (tag, text.encode("latin-1"))), "refuse"
        utc = node["body"].decode("latin-1")
        assert node["tag"] == 0x17 and re.fullmatch(rule["time"]["utcTime"]["pattern"], utc)
        yield f"{which}-generalized", _encode(root, node["path"], (0x18, ("20" + utc).encode())), "accept"
        yield f"{which}-generalized-as-utc", _encode(root, node["path"], (0x17, ("20" + utc).encode())), "refuse"
        yield f"{which}-utc-as-generalized", _encode(root, node["path"], (0x18, utc.encode())), "refuse"
        for name, text in (("year-0001", "00010101000000Z"), ("year-9999", "99991231235959Z"), ("year-0050", "00500101000000Z"),
                           ("leap-day", "20240229000000Z")):  # fmt: skip
            yield f"{which}-{name}", _encode(root, node["path"], (0x18, text.encode())), "accept"
        for name, text in (("utc-1950", "500101000000Z"), ("utc-2049", "491231235959Z")):
            yield f"{which}-{name}", _encode(root, node["path"], (0x17, text.encode())), "accept"
    if version is not None:
        for value in (0, 1, 2, 3):
            yield f"version-{value}", _encode(root, version["kids"][0]["path"], (0x02, bytes([value]))), "accept" if value in (1, 2) else "refuse"
        yield "version-absent", _encode(root, version["path"], "drop"), "accept"
        yield "version-two-bytes", _encode(root, version["kids"][0]["path"], (0x02, b"\x00\x02")), "refuse"


def certificate_cases(rows: Rows) -> Iterator[Case]:
    site = grammar("x509")["siteRefusal"]
    certs = {"holder": HOLDER_CERT, "client": rows.mtls_der, "p256": _other_cert(v._ec(), hashes.SHA256()),
             "rsa": _other_cert(v._rsa(), hashes.SHA256())}
    for which, der in certs.items():
        for name, blob, expect in certificate_edits(der):
            row = {"derB64": base64.b64encode(blob).decode()}
            yield case(f"certificate/{which}/{name}", "certificate", row, "x509#certificate", expect)
            if which == "holder":
                proof = rows.proof(_set(x5c=[base64.b64encode(blob).decode()]))
                yield case(f"certificate/x5c/{name}", "request", proof, "x509#certificate",
                           "refuse" if expect == "refuse" else None, site["dpop.x5c"] if expect == "refuse" else None)
            if which in ("client", "rsa"):
                yield case(f"certificate/mtls-{which}/{name}", "request", rows.certificate(blob), "x509#certificate",
                           "refuse" if expect == "refuse" else None, site["mtls"] if expect == "refuse" else None)
    for which in ("p256", "rsa"):  # a certificate of another key than the proof's
        proof = rows.proof(_set(x5c=[base64.b64encode(certs[which]).decode()]))
        yield case(f"certificate/x5c-other-key/{which}", "request", proof, "x509#certificate")


# --- stamp fields ---------------------------------------------------------------------------------------------------

def stamp_cases(rows: Rows) -> Iterator[Case]:
    doc = grammar("stamp")["productions"]
    seq, value, order = doc["byte-sequence"], doc["field-value"], doc["order"]
    stamp = {n.lower(): val for n, val in rows.stamped["request"]["headers"]}
    for i, (text, hexed) in enumerate(seq["accept"]):
        yield case(f"stamp/bytes/accept-{i}", "sf-bytes", {"text": text}, "stamp#byte-sequence", "accept", value={"hex": hexed})
    for i, text in enumerate(seq["refuse"]):
        yield case(f"stamp/bytes/refuse-{i}", "sf-bytes", {"text": text}, "stamp#byte-sequence", "refuse")
    for field, label in (("signature", "probity"), ("content-digest", "sha-256")):
        for i, (text, _) in enumerate(seq["accept"]):
            yield case(f"stamp/{field}/accept-{i}", "request", rows.header(field, lambda s, t=text, k=label: f"{k}=:{t}:"),
                       "stamp#byte-sequence", "not-code", seq["refusal"])
        for i, text in enumerate(seq["refuse"]):
            yield case(f"stamp/{field}/refuse-{i}", "request", rows.header(field, lambda s, t=text, k=label: f"{k}=:{t}:"),
                       "stamp#byte-sequence", "refuse", seq["refusal"])
        digits = re.fullmatch(rf"{label}=:([A-Za-z0-9+/]+)(=*):", stamp[field])
        assert digits is not None
        own = digits[1]
        for name, text in (("no-padding", own), ("one-more-digit", own + "A"), ("one-more-digit-padded", own + "A="),
                           ("three-more", own + "AAA="), ("pad-three", own + "==="), ("padding-inside", own[:4] + "=" + own[4:])):  # fmt: skip
            yield case(f"stamp/{field}/own-{name}", "request", rows.header(field, lambda s, t=text, k=label: f"{k}=:{t}:"),
                       "stamp#byte-sequence")
    yield case("stamp/order/control", "request", rows.stamped, "stamp#order", "accept")
    other_key = rows.header("signature-input", lambda s: re.sub(r'keyid="[0-9a-f]{4}', 'keyid="0000', s))
    wrong_params = rows.header("signature-input", lambda s: s.replace('alg="ed25519"', 'alg="x"'))
    for field in order["fields"]:
        for name, base in (("alone", rows.stamped), ("key-unknown", other_key), ("params-wrong", wrong_params)):
            yield case(f"stamp/order/{field}-unreadable-{name}", "request",
                       rows.header(field, lambda s: order["unreadable"], base), "stamp#order", "refuse", order["refusal"])
    for field in stamp:
        for ch in value["ows"]:
            for name, edit in (("before", lambda s, c=ch: c + s), ("after", lambda s, c=ch: s + c), ("both", lambda s, c=ch: c + c + s + c)):
                yield case(f"stamp/trim/{field}/ows-{ord(ch):04x}-{name}", "request", rows.header(field, edit), "stamp#field-value", "accept")
        for ch in [*value["notOws"], "\r", "\n", "\x00", "\x7f"]:
            for name, edit in (("before", lambda s, c=ch: c + s), ("after", lambda s, c=ch: s + c)):
                yield case(f"stamp/trim/{field}/other-{ord(ch):04x}-{name}", "request", rows.header(field, edit), "stamp#field-value", "refuse")


# --- every member of every document in every other JSON type --------------------------------------------------------

OTHER_TYPES: dict[str, Callable[[Any], Any]] = {
    "in-a-list": lambda x: [x], "in-an-object": lambda x: {"0": x}, "empty-list": lambda x: [], "empty-object": lambda x: {},
    "number": lambda x: 1, "float": lambda x: 1.5, "null": lambda x: None, "true": lambda x: True, "empty-text": lambda x: "",
    "past-exact-integer": lambda x: 2**53,
}


def _paths(doc: Any, at: tuple[Any, ...] = ()) -> Iterator[tuple[Any, ...]]:
    if isinstance(doc, dict):
        for name, value in doc.items():
            yield (*at, name)
            yield from _paths(value, (*at, name))
    elif isinstance(doc, list):
        for i, value in enumerate(doc):
            yield (*at, i)
            yield from _paths(value, (*at, i))


def _at(doc: Any, path: tuple[Any, ...]) -> Any:
    for step in path:
        doc = doc[step]
    return doc


def walk(doc: Any) -> Iterator[tuple[str, Any]]:
    """(name, copy of ``doc``) with one member in another JSON type, then with one object given a member whose name
    JavaScript finds on every object."""
    rule = grammar("compact-jws")
    assert sorted(rule["otherTypes"]) == sorted(OTHER_TYPES)
    for path in _paths(doc):
        for name, make in OTHER_TYPES.items():
            out = copy.deepcopy(doc)
            holder = _at(out, path[:-1])
            holder[path[-1]] = make(holder[path[-1]])
            yield f"{'.'.join(map(str, path))}={name}", out
    for path in [(), *_paths(doc)]:
        if isinstance(_at(doc, path), dict):
            for member in rule["ownMembers"]:
                out = copy.deepcopy(doc)
                _at(out, path)[member] = "x"
                yield f"{'.'.join(map(str, path)) or '<root>'}+{member}", out


def member_cases(rows: Rows) -> Iterator[Case]:
    for name, bundle in walk(rows.tokens["bundle"]):
        yield case(f"members/bundle/{name}", "request", {**copy.deepcopy(rows.tokens), "bundle": bundle}, "trust-bundle#bundle")
    for name, anchors in walk(rows.anchored()["bundle"]["anchors"]):
        yield case(f"members/anchors/{name}", "request", rows.bundle(lambda b, a=anchors: b.__setitem__("anchors", a)), "trust-bundle#anchor")
    put = lambda doc: (lambda target: (target.clear(), target.update(doc)))
    for role in ("agent", "user"):
        head, claims = (json.loads(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))) for s in rows.tokens["tokens"][role].split(".")[:2])
        for name, doc in walk(head):
            yield case(f"members/token-header/{role}/{name}", "request", rows.token(role, put(doc), header=True), "compact-jws#token-header")
        for name, doc in walk(claims):
            yield case(f"members/token-claims/{role}/{name}", "request", rows.token(role, put(doc)), "compact-jws#token-claims")
    head, body = _proof_parts(rows.dpop["request"]["dpop"])
    for name, doc in walk(head):
        yield case(f"members/dpop-header/{name}", "request", rows.proof(put(doc)), "compact-jws#dpop-header")
    for name, doc in walk(body):
        yield case(f"members/dpop-claims/{name}", "request", rows.proof(None, put(doc)), "compact-jws#dpop-claims")
    for role in ("agent",):  # the key-bound token of the DPoP and certificate rows: its cnf in every other type
        for row_name, row in (("dpop", rows.dpop), ("mtls", rows.mtls)):
            claims = json.loads(base64.urlsafe_b64decode((s := row["tokens"][role].split(".")[1]) + "=" * (-len(s) % 4)))
            for name, doc in walk({"cnf": claims["cnf"]}):
                yield case(f"members/token-cnf/{row_name}/{name}", "request", rows.token(role, _set(cnf=doc.get("cnf")), row=row),
                           "compact-jws#token-claims")


FAMILIES = (timestamp_cases, integer_cases, uri_cases, certificate_cases, stamp_cases, member_cases)
#: Every production a family must give an accepted and a refused case for, in both readers.
JUDGED_PRODUCTIONS = ("timestamp#date-time", "integer#exact-integer", "target-uri#port", "target-uri#uri-text",
                      "x509#certificate", "stamp#byte-sequence", "stamp#order", "stamp#field-value")


def grammar_cases(rows: list[Row]) -> Iterator[Case]:
    world = Rows(rows)
    for family in FAMILIES:
        yield from family(world)
