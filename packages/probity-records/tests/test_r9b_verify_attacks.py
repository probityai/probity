"""Attacks of the r9b verify round.

Three classes, each found by reading the two readers side by side and none reached by the parity generator:

- a received value that is not the JSON type a member takes (an ``alg`` in a list, a pin's ``roles`` holding a list or
  an object), which one reader coerces to text and the other does not, or which raises instead of refusing;
- a platform parser that is lenient in its own way: Node reads an X.509 certificate from PEM text and ignores bytes
  after the DER, Python's ``\\d`` reads other scripts' digits, JavaScript's ``Date.UTC`` moves years 0 to 99 into
  the 1900s, Python's ``int`` refuses a port of more than 4300 digits, Node decodes a base64 run with one digit left
  over, and JavaScript rounds an integer past 2**53;
- a reader that answers in a different order (the stamp's key is looked up before or after its other fields are read).

``walk`` replaces every member of a trust bundle, and of a token's and a DPoP proof's header and claims signed again,
with a value of another JSON type. Neither reader may raise and both must answer alike. The same walk, for raises
only, runs over a record bundle (``verify_bundle``), which has no TypeScript twin.
"""

from __future__ import annotations

import base64
import copy
import json
import re
import subprocess
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from probity_records import identity
from probity_records import verified_identities_vectors as v
from probity_records.bundle import BundleRefused, verify_bundle
from probity_records.grants import ts
from probity_records.identity import jwk_thumbprint

PACKAGE = Path(__file__).resolve().parents[1]
PARITY = PACKAGE / "tests" / "parity_r6c"
sys.path.insert(0, str(PARITY))
sys.path.insert(0, str(PACKAGE / "tests"))
from gen_cases import verdict
from signed_edits import (
    HOLDER_CERT,
    _proof_parts,
    _proof_signer,
    _set,
    cnf_for_certificate,
    resign,
    sign_proof,
)
from test_bundle import NOW, World

Row = dict[str, Any]
ROWS: dict[str, Row] = {r["id"]: r for r in json.loads((PACKAGE / "vectors/shared/verified_identities.json").read_text())}
TOKENS, STAMPED, DPOP, MTLS = ROWS["VI1"], ROWS["VI9"], ROWS["VI10"], ROWS["VI11"]
#: A value of each JSON type a member may be replaced with; ``[x]`` and ``{"0": x}`` wrap the member's own value.
OTHER_TYPES: dict[str, Callable[[Any], Any]] = {
    "in-a-list": lambda x: [x], "in-an-object": lambda x: {"0": x}, "empty-list": lambda x: [], "empty-object": lambda x: {},
    "number": lambda x: 1, "float": lambda x: 1.5, "null": lambda x: None, "true": lambda x: True, "empty-text": lambda x: "",
}


def _paths(doc: Any, at: tuple[Any, ...] = ()) -> Iterator[tuple[Any, ...]]:
    """Every member and element of a JSON value, containers included, as a path from the root."""
    if isinstance(doc, dict):
        for name, value in doc.items():
            yield (*at, name)
            yield from _paths(value, (*at, name))
    elif isinstance(doc, list):
        for i, value in enumerate(doc):
            yield (*at, i)
            yield from _paths(value, (*at, i))


def _replaced(doc: Any, path: tuple[Any, ...], make: Callable[[Any], Any]) -> Any:
    out = copy.deepcopy(doc)
    holder = out
    for step in path[:-1]:
        holder = holder[step]
    holder[path[-1]] = make(holder[path[-1]])
    return out


def walk(doc: Any) -> Iterator[tuple[str, Any]]:
    """(name, copy of ``doc``) with one member replaced by a value of another JSON type, for every member."""
    for path in _paths(doc):
        for name, make in OTHER_TYPES.items():
            yield f"{'.'.join(map(str, path))}={name}", _replaced(doc, path, make)


def _header(row: Row, name: str, edit: Callable[[str], str]) -> Row:
    out = copy.deepcopy(row)
    out["request"]["headers"] = [[n, edit(val) if n.lower() == name else val] for n, val in row["request"]["headers"]]
    return out


def _token(row: Row, role: str, edit: Callable[[dict[str, Any]], None], *, header: bool = False) -> Row:
    out = copy.deepcopy(row)
    signed = resign(row["tokens"][role], edit, header=header)
    assert signed is not None, f"the {role} token of {row['id']} is signed by no fixture key"
    out["tokens"][role] = signed
    return out


def _whole(row: Row, role: str, value: dict[str, Any], *, header: bool) -> Row:
    def put(doc: dict[str, Any]) -> None:
        doc.clear()
        doc.update(value)
    return _token(row, role, put, header=header)


def _proof(edit_header: Callable[[dict[str, Any]], None] | None = None,
           edit_claims: Callable[[dict[str, Any]], None] | None = None) -> Row:  # fmt: skip
    head, body = (copy.deepcopy(part) for part in _proof_parts(DPOP["request"]["dpop"]))
    key = _proof_signer(head)
    assert key is not None
    if edit_header is not None:
        edit_header(head)
    if edit_claims is not None:
        edit_claims(body)
    out = copy.deepcopy(DPOP)
    out["request"]["dpop"] = sign_proof(key, head, body)
    return out


def _bundle(edit: Callable[[dict[str, Any]], None], row: Row = TOKENS) -> Row:
    out = copy.deepcopy(row)
    edit(out["bundle"])
    return out


ANCHOR_KEY = {m: x for m, x in v._jwk(v.STAMP_KEY, None).items() if m in ("kty", "crv", "x")}


def _anchored(**changes: Any) -> Row:
    anchor = {"jwk": ANCHOR_KEY, "thumbprint": jwk_thumbprint(ANCHOR_KEY), "role": "release", "status": "active",
              "notBefore": "2026-01-01T00:00:00Z", "notAfter": None, "predicateTypes": ["https://example.com/p/v1"]}
    return _bundle(lambda b: b.__setitem__("anchors", [{**anchor, **changes}]))


def _mtls(blob: bytes) -> Row:
    out = _token(MTLS, "agent", _set(cnf=cnf_for_certificate(blob)))
    out["request"]["clientCertificateB64"] = base64.b64encode(blob).decode()
    return out


STAMP = {n.lower(): val for n, val in STAMPED["request"]["headers"]}
SIGNATURE_DIGITS = re.fullmatch(r"probity=:([A-Za-z0-9+/]+)=*:", STAMP["signature"])
DIGEST_DIGITS = re.fullmatch(r"sha-256=:([A-Za-z0-9+/]+)=*:", STAMP["content-digest"])
assert SIGNATURE_DIGITS is not None and DIGEST_DIGITS is not None
PEM = x509.load_der_x509_certificate(HOLDER_CERT).public_bytes(serialization.Encoding.PEM)
MTLS_DER = base64.b64decode(MTLS["request"]["clientCertificateB64"])
MTLS_PEM = x509.load_der_x509_certificate(MTLS_DER).public_bytes(serialization.Encoding.PEM)
ISSUER = next(iter(TOKENS["bundle"]["issuers"]))
OTHER_KEYID = _header(STAMPED, "signature-input", lambda s: re.sub(r'keyid="[0-9a-f]{4}', 'keyid="0000', s))


def _pin(member: str, value: Any) -> Row:
    return _bundle(lambda b: b["issuers"][ISSUER]["pins"][0].__setitem__(member, value))


#: Rows both readers accept: a control for every family below, so a twin that does not run fails here by name.
CONTROLS: dict[str, Row] = {
    "tokens": TOKENS, "stamp": STAMPED, "dpop": DPOP, "mtls": MTLS,
    "anchor": _anchored(), "x5c-der": _proof(_set(x5c=[base64.b64encode(HOLDER_CERT).decode()])),
    "htu-port-zeros": _proof(None, _set(htu=v.URL.replace(".com/", ".com:" + "0" * 40 + "443/"))),
}

#: A case whose answer a specification decides, with the refusal code both readers must give.
PINNED: dict[str, tuple[Row, str]] = {
    # RFC 7515 section 4.1.1: alg is a string. JavaScript's String(["EdDSA"]) is "EdDSA", so the twin verified these.
    "token-alg-in-a-list/agent": (_token(TOKENS, "agent", lambda h: h.__setitem__("alg", [h["alg"]]), header=True),
                                  "token_signature_unverified"),
    "token-alg-in-a-list/user": (_token(TOKENS, "user", lambda h: h.__setitem__("alg", [h["alg"]]), header=True),
                                 "token_signature_unverified"),
    # RFC 7515 section 4.1.6: each x5c string is the base64 of one DER certificate. Node also reads PEM text and stops
    # at the end of the first DER value, so the twin took these for the holder's certificate.
    "x5c-pem": (_proof(_set(x5c=[base64.b64encode(PEM).decode()])), "dpop_x5c_invalid"),
    "x5c-der-then-a-byte": (_proof(_set(x5c=[base64.b64encode(HOLDER_CERT + b"\x00").decode()])), "dpop_x5c_invalid"),
    "x5c-der-twice": (_proof(_set(x5c=[base64.b64encode(HOLDER_CERT * 2).decode()])), "dpop_x5c_invalid"),
    # RFC 8705 section 3.1: the thumbprint is over the DER certificate; bytes that are not one DER value are no certificate.
    "mtls-pem": (_mtls(MTLS_PEM), "mtls_certificate_invalid"),
    "mtls-der-then-a-byte": (_mtls(MTLS_DER + b"\x00"), "mtls_certificate_invalid"),
    # RFC 3339 section 5.6: DIGIT is %x30-39. Python's \d also matches the digits of other scripts.
    "anchor-arabic-indic-digits": (_anchored(notBefore="٢٠٢٦-01-01T00:00:00Z"), "trust_bundle_malformed"),
    "anchor-fullwidth-digit": (_anchored(notBefore="2026-01-01T00:00:0０Z"), "trust_bundle_malformed"),
    # A pin's roles is a list of names; a member that is a list or an object made set() raise TypeError.
    "pin-roles-hold-a-list": (_pin("roles", [["user"]]), "trust_bundle_malformed"),
    "pin-roles-hold-an-object": (_pin("roles", [{}]), "trust_bundle_malformed"),
    # RFC 8941 section 4.2.7: a byte sequence that cannot be base64 decoded fails parsing. One digit left over after
    # whole groups decodes to nothing: Python refuses it, Node drops it and the twin reads the rest.
    "stamp-signature-one-digit-over": (_header(STAMPED, "signature", lambda s: f"probity=:{SIGNATURE_DIGITS[1]}AAA=:"),
                                       "stamp_malformed"),
    "stamp-signature-one-digit": (_header(STAMPED, "signature", lambda s: "probity=:A==:"), "stamp_malformed"),
    "stamp-digest-one-digit-over": (_header(STAMPED, "content-digest", lambda s: f"sha-256=:{DIGEST_DIGITS[1]}AA=:"),
                                    "stamp_malformed"),
}

#: A case with no one right answer in a specification: the two readers must give the same one, and neither may raise.
ALIKE: dict[str, Row] = {
    # Python's int() refuses more than 4300 digits (ValueError, read as a mismatch); parseInt reads the port as 443.
    "htu-port-4400-zeros": _proof(None, _set(htu=v.URL.replace(".com/", ".com:" + "0" * 4400 + "443/"))),
    # 2**53 and 2**53 + 1 are one number in JavaScript and two in Python, so "exp is after iat" has two answers.
    "token-iat-and-exp-past-2-53": _token(TOKENS, "agent", _set(iat=2**53, exp=2**53 + 1)),
    # Date.UTC reads a year 0 to 99 as 1900 to 1999, so the twin refuses every instant before year 100.
    "anchor-year-50": _anchored(notBefore="0050-01-01T00:00:00Z"),
    "anchor-year-1-offset": _anchored(notBefore="0001-01-01T00:00:00+23:59"),
    # Python reads all three stamp fields before it looks the key up; the twin looks the key up first.
    "stamp-digest-unreadable-and-key-unknown": _header(OTHER_KEYID, "content-digest", lambda s: "@@@"),
    "stamp-digest-unreadable-and-params-wrong": _header(
        _header(STAMPED, "signature-input", lambda s: s.replace('alg="ed25519"', 'alg="x"')), "content-digest", lambda s: "@@@"),
    # str.strip() removes U+001F and String.prototype.trim() does not, so the two build different signature bases.
    "stamp-principals-then-unit-separator": _header(STAMPED, "probity-principals", lambda s: s + "\x1f"),
    "stamp-principals-after-unit-separator": _header(STAMPED, "probity-principals", lambda s: "\x1f" + s),
}


def _walked() -> dict[str, Row]:
    """Every member of a bundle, a token header and claim set, and a DPoP header and claim set, in another JSON type."""
    out: dict[str, Row] = {}
    for name, bundle in walk(TOKENS["bundle"]):
        out[f"walk/bundle/{name}"] = {**copy.deepcopy(TOKENS), "bundle": bundle}
    for name, bundle in walk(_anchored()["bundle"]["anchors"]):
        out[f"walk/anchors/{name}"] = _bundle(lambda b, a=bundle: b.__setitem__("anchors", a))
    for role in ("agent", "user"):
        head, claims = (json.loads(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))
                        for s in TOKENS["tokens"][role].split(".")[:2])
        for name, doc in walk(head):
            out[f"walk/token-header/{role}/{name}"] = _whole(TOKENS, role, doc, header=True)
        for name, doc in walk(claims):
            out[f"walk/token-claims/{role}/{name}"] = _whole(TOKENS, role, doc, header=False)
    head, body = _proof_parts(DPOP["request"]["dpop"])
    for name, doc in walk(head):
        out[f"walk/dpop-header/{name}"] = _proof(lambda h, d=doc: (h.clear(), h.update(d)))  # signed by the first key
    for name, doc in walk(body):
        out[f"walk/dpop-claims/{name}"] = _proof(None, lambda b, d=doc: (b.clear(), b.update(d)))
    return out


def _judged(cases: dict[str, Row], folder: Path) -> dict[str, tuple[Any, Any]]:
    """Each case's (Python verdict, TypeScript verdict), judged as the parity differential judges a request."""
    listed = [{"case": name, "kind": "request", "row": row} for name, row in cases.items()]
    (folder / "cases.json").write_text(json.dumps(listed, ensure_ascii=True))
    done = subprocess.run(["node", str(PARITY / "judge_ts.ts"), str(folder / "cases.json"), str(folder / "ts.json")],
                          capture_output=True, text=True, check=False)  # fmt: skip
    assert done.returncode == 0, f"the TypeScript twin did not run (npm ci in node/probity-records-verify?): {done.stderr[-800:]}"
    twin = json.loads((folder / "ts.json").read_text())
    return {name: (verdict("request", row), twin[name]) for name, row in cases.items()}


@pytest.fixture(scope="module")
def judged(tmp_path_factory: pytest.TempPathFactory) -> dict[str, tuple[Any, Any]]:
    cases = {**{f"control/{n}": r for n, r in CONTROLS.items()}, **{f"pinned/{n}": r for n, (r, _) in PINNED.items()},
             **{f"alike/{n}": r for n, r in ALIKE.items()}, **_walked()}  # fmt: skip
    return _judged(cases, tmp_path_factory.mktemp("r9b"))


@pytest.mark.parametrize("name", sorted(CONTROLS))
def test_both_readers_accept_the_control(judged: dict[str, tuple[Any, Any]], name: str) -> None:
    py, twin = judged[f"control/{name}"]
    assert isinstance(py, dict) and "identities" in py, f"Python does not accept the control: {py}"
    assert py == twin, f"the twin differs on a control: {twin}"


@pytest.mark.parametrize("name", sorted(PINNED))
def test_both_readers_refuse_with_the_code_the_specification_gives(judged: dict[str, tuple[Any, Any]], name: str) -> None:
    py, twin = judged[f"pinned/{name}"]
    code = PINNED[name][1]
    assert (py, twin) == ({"refused": code}, {"refused": code}), f"python={str(py)[:120]} typescript={str(twin)[:120]}"


@pytest.mark.parametrize("name", sorted(ALIKE))
def test_both_readers_answer_alike(judged: dict[str, tuple[Any, Any]], name: str) -> None:
    py, twin = judged[f"alike/{name}"]
    assert not isinstance(py, str) and not isinstance(twin, str), f"a reader raised: python={py} typescript={twin}"
    assert py == twin, f"python={str(py)[:120]} typescript={str(twin)[:120]}"


@pytest.mark.parametrize("family", ["bundle", "anchors", "token-header", "token-claims", "dpop-header", "dpop-claims"])
def test_a_member_of_another_json_type_never_raises_and_both_readers_answer_alike(
        judged: dict[str, tuple[Any, Any]], family: str) -> None:  # fmt: skip
    found = {name: pair for name, pair in judged.items() if name.startswith(f"walk/{family}/")}
    assert len(found) > 20, f"the walk made {len(found)} cases for {family}"
    raised = sorted(n for n, (py, twin) in found.items() if isinstance(py, str) or isinstance(twin, str))
    differ = sorted(n for n, (py, twin) in found.items() if py != twin and n not in raised)
    lines = [f"{n}: python={str(found[n][0])[:70]} typescript={str(found[n][1])[:70]}" for n in (raised + differ)[:12]]
    assert not raised and not differ, f"{len(raised)} raised, {len(differ)} differ, of {len(found)}:\n" + "\n".join(lines)


# --- Python alone ---------------------------------------------------------------------------------------------------

def test_a_token_whose_signature_has_a_second_spelling_is_not_a_token_and_does_not_raise() -> None:
    """``token_segments`` says it returns None for anything that is not a compact JWS; the signature segment is decoded
    outside its try, so a signature with stray low bits (``AB`` for ``AA``) raised ValueError out of ``verify_token``."""
    head = identity.b64url(b'{"alg":"EdDSA"}')
    claims = identity.b64url(b'{"sub":"a"}')
    assert identity.token_segments(f"{head}.{claims}.AA") is not None
    assert identity.token_segments(f"{head}.{claims}.AB") is None


@pytest.mark.parametrize("text", ["٢٠٢٦-01-01T00:00:00Z", "2026-01-01T00:00:0０Z",
                                  "2026-01-01T00:00:00+0٥:00", "2026-01-01T00:00:00.١Z"])  # fmt: skip
def test_a_timestamp_is_written_in_ascii_digits_only(text: str) -> None:
    """RFC 3339 section 5.6 DIGIT is 0 to 9; the TypeScript ``ts`` refuses every other digit and so must this one, or
    one instant has many spellings and a grant, a principal or an anchor has two verdicts."""
    with pytest.raises(ValueError, match="grant_timestamp_invalid"):
        ts(text)


def test_a_record_bundle_member_of_another_json_type_is_refused_and_never_raises() -> None:
    """``verify_bundle`` answers a registered refusal (BundleRefused) or a grade for every bundle; no member of another
    JSON type may raise anything else. It has no TypeScript twin, so this checks raises only."""
    world = World()
    bundle, trust = world.bundle(), world.trust()
    assert verify_bundle(bundle, trust, NOW).grade == "I"
    raised: list[str] = []
    count = 0
    for name, doc in walk(bundle):
        count += 1
        try:
            verify_bundle(doc, trust, NOW)
        except BundleRefused:
            pass
        except Exception as exc:  # noqa: BLE001 - any other raise is the finding
            raised.append(f"{name}: {type(exc).__name__}: {str(exc)[:60]}")
    assert count > 100
    assert not raised, f"{len(raised)} of {count} raised:\n" + "\n".join(raised[:15])
