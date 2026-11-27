"""Proof of possession: verify that the party presenting a grant holds the key its ``cnf`` names.

Every grant names a confirmation key (RFC 7800 section 3.1) in ``cnf``, by exactly one method:

- ``jkt``: the RFC 7638 SHA-256 thumbprint of the holder's public JWK (RFC 9449 section 6.1). The holder proves
  possession on each request with a DPoP proof (RFC 9449 section 4) signed by that key.
- ``x5t#S256``: the SHA-256 thumbprint of the holder's client certificate (RFC 8705 section 3.1). The holder
  proves possession by completing mutual TLS with that certificate at the endpoint that checks the grant.

Everything here is a stateless check: ``check_dpop`` and ``check_client_certificate`` verify one proof against
an issuer-signed ``cnf``, and ``check_possession`` picks the check the ``cnf`` method names. None of them
remembers a proof. A DPoP proof is single-use, and the record of each use is what lets anyone check that offline:
``possession_record`` is the form a tool-call record carries, ``possession_record_problem`` verifies it against
the grant's ``cnf``, and ``duplicate_proofs`` finds a proof a journal shows spent twice inside its lifetime.
``proof_key`` is the single-use key, so a live store and the offline check count the same thing.

The DPoP checks follow RFC 9449 section 4.3 and the ANS SDK ``pop`` verifier (ans-sdk-go ``pop/``, Apache-2.0,
commit a36e0195b2dc): strict header, pinned algorithms, the content digest claim ``ans_content_digest`` so a hop
that terminates TLS cannot rewrite the body, and ``ath`` if and only if a token is presented. Two choices differ
from ANS: the accepted key is the one the issuer-signed ``cnf`` names (the header's ``jwk`` is trusted only after
its thumbprint matches), and both ES256 and EdDSA (Ed25519) are accepted.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .certificate import CertificateRefused, certificate_facts, spki_key
from .core import (
    TOKEN_MAX_DEPTH,
    JsonRefused,
    Signer,
    admitted_loads,
    ascii_lower,
    decimal,
    exact_int,
    same_text,
    unb64,
)
from .grants import micros
from .identity import b64url, has_private_member, jwk_thumbprint, unb64url
from .identity import public_jwk as jwk_bytes

CNF_METHODS = ("jkt", "x5t#S256")
DPOP_TYP = "dpop+jwt"
DPOP_ALGS = ("ES256", "EdDSA")
CONTENT_DIGEST_CLAIM = "ans_content_digest"
MAX_PROOF_BYTES = 8 << 10
MAX_JTI_BYTES = 128
DEFAULT_SKEW = 120
REPLAY_GRACE = 5
_HEADER_MEMBERS = {"typ", "alg", "jwk", "x5c"}
_JWK_MEMBERS = {"ES256": ("crv", "kty", "x", "y"), "EdDSA": ("crv", "kty", "x")}
_JWK_CURVE = {"ES256": ("EC", "P-256"), "EdDSA": ("OKP", "Ed25519")}


# ---------- confirmation (cnf) ----------

def _is_digest(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 43:
        return False
    try:
        return len(unb64url(value)) == 32 and b64url(unb64url(value)) == value
    except (ValueError, TypeError):
        return False


def cnf_problem(cnf: Any) -> str | None:
    """None when ``cnf`` names exactly one confirmation method with a well-formed SHA-256 thumbprint."""
    if cnf is None:
        return "cnf_missing"
    if not isinstance(cnf, dict) or len(cnf) != 1:
        return "cnf_invalid"
    (method, value), = cnf.items()
    if method not in CNF_METHODS or not _is_digest(value):
        return "cnf_invalid"
    return None


def public_jwk(key: Any) -> dict[str, str]:
    """The public JWK of an EC P-256 or Ed25519 key (private or public), with only the RFC 7638 members."""
    if isinstance(key, Signer):
        key = key.key
    if isinstance(key, Ed25519PrivateKey | ec.EllipticCurvePrivateKey):
        key = key.public_key()
    if isinstance(key, Ed25519PublicKey):
        return {"crv": "Ed25519", "kty": "OKP", "x": b64url(key.public_bytes(Encoding.Raw, PublicFormat.Raw))}
    if isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1):
        nums = key.public_numbers()
        return {"crv": "P-256", "kty": "EC", "x": b64url(nums.x.to_bytes(32, "big")),
                "y": b64url(nums.y.to_bytes(32, "big"))}
    raise ValueError("key_unsupported")


def cnf_for_jwk(jwk: Mapping[str, Any]) -> dict[str, str]:
    return {"jkt": jwk_thumbprint(jwk)}


def cnf_for_signer(signer: Signer) -> dict[str, str]:
    """The ``cnf`` that lets the grant's Ed25519 holder key also present the grant."""
    return cnf_for_jwk(public_jwk(signer))


def cnf_for_certificate(der: bytes) -> dict[str, str]:
    return {"x5t#S256": b64url(hashlib.sha256(der).digest())}


# ---------- DPoP ----------

@dataclass(frozen=True)
class DpopProof:
    """A DPoP proof that passed every RFC 9449 section 4.3 check. It stays single-use: ``proof_key`` names it,
    and ``replay_exp`` is the last second at which it could still pass the freshness check."""

    jkt: str
    jti: str
    iat: int
    replay_exp: int


def _segment_json(segment: str) -> Any:
    """One DPoP segment as JSON, read by the package's strict reader; ``JsonRefused`` otherwise."""
    return admitted_loads(unb64url(segment), max_depth=TOKEN_MAX_DEPTH)  # unb64url reads only the canonical spelling


def _segment_refusal(exc: ValueError) -> str:
    """The registered code for a segment that did not read: a repeated member, or anything else malformed."""
    duplicate = isinstance(exc, JsonRefused) and exc.variant == "DuplicateMember"
    return "dpop_duplicate_member" if duplicate else "dpop_malformed"


#: RFC 3986 section 2: the only characters a URI is written with (unreserved, reserved, and ``%`` followed by two hex
#: digits). Anything else (a space, a control byte, a tab or line break, a non-ASCII character, a backslash) makes the
#: text something other than the request URI it is compared with (RFC 9449 section 4.3). Python's ``urlsplit`` strips
#: leading spaces and C0 controls and deletes tabs and line breaks, so the reader refuses them before it splits.
_URI_TEXT = re.compile(r"(?:[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=]|%[0-9A-Fa-f]{2})*")
#: scheme "://" authority path, then a query or fragment (RFC 3986 section 3).
_HTU_PARTS = re.compile(r"([A-Za-z][A-Za-z0-9+.\-]*)://([^/?#]*)([^?#]*)([?#].*)?", re.DOTALL)
_IP_LITERAL = re.compile(r"\[([0-9A-Fa-f:.]+)\](?::([0-9]*))?")
_REG_NAME = re.compile(r"[A-Za-z0-9\-._~!$&'()*+,;=%]+")
#: ``grammar/target-uri.json``: any number of leading zeros, then at most five digits; never ``int`` on the whole run
#: (Python refuses a run of more than 4300 digits, JavaScript reads it).
PORT = re.compile(r"0*([0-9]{1,5})")
#: The default port of each scheme an http target URI may carry.
DEFAULT_PORTS: Final = {"http": 80, "https": 443}


def http_uri_parts(url: object) -> tuple[str, str, int | None, str, str]:
    """(scheme, host, port, path, rest) of an absolute http or https URI; ``rest`` is its query and fragment text.

    The one reader of a request target in this package (a DPoP ``htu`` and a stamp's ``@target-uri``), with the
    TypeScript twin ``httpUriParts``: the text is read only when it is written in the RFC 3986 alphabet, so a space, a
    control byte, a tab or line break, a non-ASCII character or a backslash is ``ValueError`` (Python's ``urlsplit``
    strips or deletes some of them and WHATWG URL parsing rewrites others, so two readers would see two URIs). Scheme
    and host come back in lower case, a bracketed IP literal keeps its brackets, and userinfo (RFC 9110 section 4.2.4),
    an empty host, and an empty, non-numeric or out-of-range port are ``ValueError``."""
    if not isinstance(url, str) or not _URI_TEXT.fullmatch(url):
        raise ValueError("uri_not_in_the_uri_alphabet")
    parts = _HTU_PARTS.fullmatch(url)
    if parts is None:
        raise ValueError("uri_not_absolute")
    scheme, authority, path, rest = ascii_lower(parts[1]), parts[2], parts[3], parts[4] or ""
    if scheme not in DEFAULT_PORTS or "@" in authority:
        raise ValueError("uri_not_absolute")
    literal = _IP_LITERAL.fullmatch(authority)
    if literal is not None:
        host, port_text = f"[{ascii_lower(literal[1])}]", literal[2]
    elif "[" in authority or "]" in authority:
        raise ValueError("uri_not_absolute")
    else:
        name, colon, after = authority.partition(":")
        host, port_text = ascii_lower(name), (after if colon else None)
        if not _REG_NAME.fullmatch(host):
            raise ValueError("uri_not_absolute")
    if port_text is None:
        return scheme, host, None, path, rest
    digits = PORT.fullmatch(port_text)
    if digits is None or decimal(digits[1]) > 65535:
        raise ValueError("uri_port_invalid")
    return scheme, host, decimal(digits[1]), path, rest


def uri_authority(scheme: str, host: str, port: int | None) -> str:
    """The host, with the port only when it is not the scheme's default (RFC 9421 ``@authority``, RFC 9449 htu)."""
    return host if port is None or port == DEFAULT_PORTS[scheme] else f"{host}:{port}"


def normalize_htu(url: str) -> str:
    """RFC 9449 section 4.3 target URI: scheme and host lower case, default port dropped, no query or fragment,
    an empty path as ``/``. The path is otherwise compared exactly; ``ValueError`` as ``http_uri_parts`` refuses."""
    scheme, host, port, path, _ = http_uri_parts(url)
    return f"{scheme}://{uri_authority(scheme, host, port)}{path or '/'}"


class _JwkRefused(ValueError):
    """A proof's header key that is refused; the message is the refusal code the proof check reports."""


def _load_jwk(alg: str, jwk: Any) -> Any:
    """The public key of a JWK of exactly the shape ``alg`` takes, or ``_JwkRefused`` naming the defect."""
    if not isinstance(jwk, dict):
        raise _JwkRefused("dpop_jwk_invalid")
    if has_private_member(jwk):
        raise _JwkRefused("dpop_jwk_private")
    kty, crv = _JWK_CURVE[alg]
    if set(jwk) != set(_JWK_MEMBERS[alg]) or jwk.get("kty") != kty or jwk.get("crv") != crv:
        raise _JwkRefused("dpop_jwk_invalid")
    try:
        raw = jwk_bytes(jwk)  # identity.public_jwk: canonical members, full-size coordinates, nothing private
        if alg == "EdDSA":
            return Ed25519PublicKey.from_public_bytes(raw["x"])
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + raw["x"] + raw["y"])
    except (ValueError, TypeError, KeyError) as exc:
        raise _JwkRefused("dpop_jwk_invalid") from exc


def _verify_sig(alg: str, key: Any, signing_input: bytes, sig: bytes) -> bool:
    try:
        if alg == "EdDSA":
            key.verify(sig, signing_input)
        else:
            if len(sig) != 64:
                return False
            der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
            key.verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError):
        return False
    return True


def _x5c_problem(x5c: Any, jwk: Mapping[str, Any]) -> str | None:
    """An ``x5c`` is tolerated only as one certificate presenting the very key in ``jwk``."""
    if not isinstance(x5c, list) or len(x5c) != 1 or not isinstance(x5c[0], str):
        return "dpop_x5c_invalid"
    try:  # one DER certificate (certificate.py: no PEM, no byte after it, no second encoding); unb64: canonical only
        presented = spki_key(certificate_facts(unb64(x5c[0])).spki)
    except ValueError:
        return "dpop_x5c_invalid"
    if presented is None:  # neither an Ed25519 nor a P-256 key
        return "dpop_x5c_invalid"
    held = jwk_bytes(jwk)  # the proof key's coordinates; _load_jwk read this JWK already
    same = (presented["kty"], presented["crv"]) == (jwk["kty"], jwk["crv"]) and all(
        presented[m] == held[m] for m in held)
    return None if same else "dpop_x5c_key_mismatch"


def _header(segment: str, expected_jkt: str) -> tuple[str, Any, str | None]:
    """(alg, public key, None) for a header that passes, or ("", None, refusal)."""
    try:
        h = _segment_json(segment)
    except ValueError as exc:
        return "", None, _segment_refusal(exc)
    if not isinstance(h, dict):
        return "", None, "dpop_malformed"
    if set(h) - _HEADER_MEMBERS:
        return "", None, "dpop_header_member_unknown"
    if h.get("typ") != DPOP_TYP:
        return "", None, "dpop_typ_invalid"
    alg = h.get("alg")
    if alg not in DPOP_ALGS:
        return "", None, "dpop_alg_not_allowed"
    try:
        key = _load_jwk(alg, h.get("jwk"))
    except _JwkRefused as exc:
        return "", None, str(exc)
    if "x5c" in h:
        problem = _x5c_problem(h["x5c"], h["jwk"])
        if problem:
            return "", None, problem
    if not same_text(jwk_thumbprint(h["jwk"]), expected_jkt):
        return "", None, "dpop_key_not_confirmed"
    return alg, key, None


def _jti_ok(jti: Any) -> bool:
    """A non-empty string of at most ``MAX_JTI_BYTES`` UTF-8 bytes; a lone surrogate counts as its three bytes."""
    return isinstance(jti, str) and bool(jti) and len(jti.encode("utf-8", "surrogatepass")) <= MAX_JTI_BYTES


def _int_claim(value: Any) -> bool:
    return exact_int(value)


def _claims_problem(p: Any, method: str, url: str, now: int, skew: int, access_token: str | None,
                    content: bytes, require_content_binding: bool) -> str | None:
    if not isinstance(p, dict):
        return "dpop_malformed"
    if p.get("htm") != method:
        return "dpop_htm_mismatch"
    try:
        if not isinstance(p.get("htu"), str) or normalize_htu(p["htu"]) != normalize_htu(url):
            return "dpop_htu_mismatch"
    except ValueError:
        return "dpop_htu_mismatch"
    if access_token is None:
        if "ath" in p:
            return "dpop_ath_unexpected"
    elif "ath" not in p:
        return "dpop_ath_missing"
    elif (not isinstance(access_token, str) or not access_token.isascii()
          or not same_text(p["ath"], b64url(hashlib.sha256(access_token.encode("ascii")).digest()))):
        return "dpop_ath_mismatch"  # a token that is not ASCII is none a proof can have hashed
    if not _int_claim(p.get("iat")):
        return "dpop_malformed"
    if p["iat"] < now - skew:
        return "dpop_iat_stale"
    if p["iat"] > now + skew:
        return "dpop_iat_future"
    if not _jti_ok(p.get("jti")):
        return "dpop_jti_invalid"
    digest = p.get(CONTENT_DIGEST_CLAIM)
    if digest is None:
        return "dpop_content_unbound" if require_content_binding else None
    if not same_text(digest, b64url(hashlib.sha256(content).digest())):
        return "dpop_content_mismatch"
    return None


def check_dpop(proof: str, method: str, url: str, at: str, *, expected_jkt: str, access_token: str | None,
               content: bytes = b"", skew: int = DEFAULT_SKEW,
               require_content_binding: bool = True) -> tuple[DpopProof | None, str]:
    """Every RFC 9449 section 4.3 check of one proof that needs no memory of earlier proofs.

    ``url`` is the verifier's own external URL for the request, never one built from the client's Host
    header. ``expected_jkt`` comes from issuer-signed content (the grant's ``cnf``, the token's ``cnf``),
    never from the proof. Returns the proof or the refusal code."""
    if not isinstance(proof, str) or not proof.isascii():  # a request header is ASCII; the signing input is built from it
        return None, "dpop_malformed"
    if len(proof) > MAX_PROOF_BYTES:
        return None, "dpop_too_large"
    parts = proof.split(".")
    if len(parts) != 3 or not all(parts):
        return None, "dpop_malformed"
    head, body, sig = parts
    alg, key, problem = _header(head, expected_jkt)
    if problem:
        return None, problem
    try:
        signature = unb64url(sig)
    except (ValueError, TypeError):
        return None, "dpop_malformed"
    if not _verify_sig(alg, key, f"{head}.{body}".encode("ascii"), signature):
        return None, "dpop_signature_unverified"
    try:
        claims = _segment_json(body)
    except ValueError as exc:
        return None, _segment_refusal(exc)
    now = micros(at) // 1_000_000  # whole seconds, by floor
    problem = _claims_problem(claims, method, url, now, skew, access_token, content, require_content_binding)
    if problem:
        return None, problem
    return DpopProof(jkt=expected_jkt, jti=claims["jti"], iat=claims["iat"],
                     replay_exp=claims["iat"] + skew + REPLAY_GRACE), "ok"


def sign_dpop(key: Any, method: str, url: str, *, iat: int, jti: str, access_token: str | None = None,
              content: bytes | None = b"") -> str:
    """A DPoP proof by ``key`` (EC P-256 or Ed25519, or a ``Signer``) for one request. ``content`` None leaves
    the content digest claim out, which a verifier requiring content binding refuses."""
    if isinstance(key, Signer):
        key = key.key
    jwk = public_jwk(key)
    alg = "EdDSA" if jwk["kty"] == "OKP" else "ES256"
    claims: dict[str, Any] = {"htm": method, "htu": normalize_htu(url), "iat": iat, "jti": jti}
    if access_token is not None:
        claims["ath"] = b64url(hashlib.sha256(access_token.encode("ascii")).digest())
    if content is not None:
        claims[CONTENT_DIGEST_CLAIM] = b64url(hashlib.sha256(content).digest())
    head = b64url(json.dumps({"alg": alg, "jwk": jwk, "typ": DPOP_TYP}, separators=(",", ":")).encode())
    body = b64url(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{head}.{body}".encode("ascii")
    if alg == "EdDSA":
        sig = key.sign(signing_input)
    else:
        r, s = decode_dss_signature(key.sign(signing_input, ec.ECDSA(hashes.SHA256())))
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return f"{head}.{body}.{b64url(sig)}"


# ---------- mutual TLS ----------

def check_client_certificate(der: bytes | None, expected: str, at: str) -> str:
    """``ok`` when ``der`` (the certificate the TLS endpoint authenticated) has the confirmed thumbprint and is
    within its validity period at ``at``."""
    if der is None:
        return "mtls_certificate_missing"
    if not same_text(cnf_for_certificate(der)["x5t#S256"], expected):
        return "mtls_certificate_not_confirmed"
    try:
        facts = certificate_facts(der)
    except CertificateRefused:
        return "mtls_certificate_invalid"
    when = micros(at)
    if when < facts.not_before:
        return "mtls_certificate_not_yet_valid"
    if when > facts.not_after:
        return "mtls_certificate_expired"
    return "ok"


# ---------- one cnf, one presentation ----------

@dataclass(frozen=True)
class CertificateProof:
    """A client certificate the TLS endpoint authenticated that has the confirmed thumbprint and is valid."""

    x5t: str


def check_possession(cnf: Mapping[str, str], *, method: str, url: str, at: str, access_token: str | None,
                     dpop: str | None = None, client_certificate: bytes | None = None, content: bytes = b"",
                     skew: int = DEFAULT_SKEW,
                     require_content_binding: bool = True) -> tuple[DpopProof | CertificateProof | None, str]:
    """Verify that one request proves possession of the key ``cnf`` names, by the method ``cnf`` names.

    ``cnf`` comes from issuer-signed content (the leaf grant, the agent token), never from the request. A ``jkt``
    needs a DPoP proof and ignores any client certificate; an ``x5t#S256`` needs the certificate and ignores any
    DPoP header, so a proof by the other method never stands in. Returns the proof or the refusal code."""
    problem = cnf_problem(cnf)
    if problem:
        return None, problem
    if "jkt" in cnf:
        if dpop is None:
            return None, "dpop_proof_missing"
        return check_dpop(dpop, method, url, at, expected_jkt=cnf["jkt"], access_token=access_token,
                          content=content, skew=skew, require_content_binding=require_content_binding)
    reason = check_client_certificate(client_certificate, cnf["x5t#S256"], at)
    return (CertificateProof(cnf["x5t#S256"]), "ok") if reason == "ok" else (None, reason)


# ---------- the record of a use, and replay found offline ----------

def proof_key(jkt: str, jti: str) -> str:
    """The single-use key of a DPoP proof: SHA-256 over the confirmed key's thumbprint and the proof's ``jti``,
    so a store's entries are bounded in bytes whatever the proof carried. A thumbprint never contains ``.``."""
    return b64url(hashlib.sha256(f"{jkt}.{jti}".encode()).digest())


def possession_record(proof: DpopProof | CertificateProof) -> dict[str, Any]:
    """What a tool-call record's grant evidence carries as ``possession`` for a verified proof."""
    if isinstance(proof, DpopProof):
        return {"iat": proof.iat, "jkt": proof.jkt, "jti": proof.jti, "method": "dpop"}
    return {"method": "mtls", "x5t#S256": proof.x5t}


_RECORD_MEMBERS = {"dpop": {"iat", "jkt", "jti", "method"}, "mtls": {"method", "x5t#S256"}}


def possession_record_problem(record: Any, cnf: Any) -> str | None:
    """None when ``record`` is a well-formed possession record for the key the grant's ``cnf`` confirms."""
    if not isinstance(record, dict) or not isinstance(record.get("method"), str) \
            or record["method"] not in _RECORD_MEMBERS:  # a list or object method is unhashable: refuse, never raise
        return "possession_record_malformed"
    method = record["method"]
    if set(record) != _RECORD_MEMBERS[method]:
        return "possession_record_malformed"
    if method == "dpop" and (not _int_claim(record["iat"]) or not _jti_ok(record["jti"])):
        return "possession_record_malformed"
    member, value = ("jkt", record["jkt"]) if method == "dpop" else ("x5t#S256", record["x5t#S256"])
    if not isinstance(cnf, dict) or member not in cnf or not isinstance(value, str) \
            or not same_text(value, cnf[member]):
        return "possession_not_the_grant_key"
    return None


def _spent_proof(body: Mapping[str, Any]) -> tuple[str, int, Any] | None:
    """(proof key, iat, use time) for an ``authorize`` record whose grant evidence carries a DPoP use."""
    pred = body.get("predicate")
    if not isinstance(pred, Mapping) or pred.get("phase") != "authorize":
        return None
    evidence = pred.get("authority")
    record = evidence.get("possession") if isinstance(evidence, Mapping) else None
    if not isinstance(record, Mapping) or record.get("method") != "dpop":
        return None
    jkt, jti, iat = record.get("jkt"), record.get("jti"), record.get("iat")
    if not isinstance(jkt, str) or not isinstance(jti, str) or not exact_int(iat):
        return None
    return proof_key(jkt, jti), iat, pred.get("at")


def duplicate_proofs(records: Iterable[tuple[int, Mapping[str, Any]]], *,
                     skew: int = DEFAULT_SKEW) -> list[tuple[int, str]]:
    """Each record that spends a DPoP proof an earlier record already spent inside the proof's lifetime.

    ``records`` are numbered verified statement bodies in journal order (``verify_journal`` passes its lines).
    An ``authorize`` record whose grant evidence carries a ``dpop`` possession record spends that proof; one
    permit's records spend it once, however often a retry re-records the permit. The proof stays live until
    ``iat + skew + REPLAY_GRACE``, the last second it could pass the freshness check, with ``skew`` the one the
    auditor pins. Returns ``(n, "dpop_proof_replayed:<m>")`` for record ``n`` spending what record ``m`` spent,
    and ``(n, "dpop_proof_use_time_invalid")`` when the record's own time cannot be read."""
    first: dict[str, tuple[int, int, Any]] = {}  # proof key -> (record, iat, permit)
    found: list[tuple[int, str]] = []
    for n, body in records:
        spent = _spent_proof(body)
        if spent is None:
            continue
        key, iat, at = spent
        permit = body["predicate"].get("permitId")
        try:
            used = micros(at)  # a use time that is not a timestamp (any other JSON type included) is refused by ts
        except (ValueError, TypeError):
            found.append((n, "dpop_proof_use_time_invalid"))
            continue
        earlier = first.get(key)
        if earlier is not None and earlier[2] != permit and used <= (earlier[1] + skew + REPLAY_GRACE) * 1_000_000:
            found.append((n, f"dpop_proof_replayed:{earlier[0]}"))
            continue
        if earlier is None or used > (earlier[1] + skew + REPLAY_GRACE) * 1_000_000:
            first[key] = (n, iat, permit)
    return found
