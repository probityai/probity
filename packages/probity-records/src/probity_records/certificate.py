"""The outline of an X.509 certificate, read from its DER bytes by the grammar in ``grammar/x509.json``.

The readers take two facts from a certificate: its validity period (a client certificate, RFC 8705) and its subject
public key (a DPoP ``x5c``). Both come from this walk, and the TypeScript twin (``x509.ts``) walks the same bytes by the
same rules. No platform certificate parser stands behind it: each platform's parser accepts its own set of
non-canonical encodings (Node reads PEM text and stops at the end of the first DER value), so two readers would see two
certificates. A certificate's signature is not checked here; who vouches for it is the caller's question (the TLS
endpoint for a client certificate, the confirmed key for a DPoP ``x5c``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final

from .core import decimal
from .grants import micros_of


class CertificateRefused(ValueError):
    """Bytes that are not one DER certificate of the outline the grammar gives."""


def _bad(why: str) -> CertificateRefused:
    return CertificateRefused(f"certificate_not_der:{why}")


@dataclass(frozen=True)
class _Tlv:
    tag: int
    start: int
    body: int
    end: int


def _tlv(der: bytes, at: int, limit: int) -> _Tlv:
    """One DER tag-length-value at ``at``, inside [at, limit): a one-byte tag, a definite length in its shortest form."""
    if at + 2 > limit:
        raise _bad("truncated")
    tag = der[at]
    if tag & 0x1F == 0x1F:
        raise _bad("tag")
    length, body = der[at + 1], at + 2
    if length >= 0x80:
        count = length & 0x7F
        if count == 0 or count > 4 or body + count > limit:
            raise _bad("length")
        length = int.from_bytes(der[body : body + count], "big")
        if der[body] == 0 or length < 0x80:
            raise _bad("length_not_minimal")
        body += count
    if body + length > limit:
        raise _bad("truncated")
    return _Tlv(tag, at, body, body + length)


def _children(der: bytes, parent: _Tlv) -> list[_Tlv]:
    """The elements that fill ``parent`` exactly."""
    out: list[_Tlv] = []
    at = parent.body
    while at < parent.end:
        child = _tlv(der, at, parent.end)
        out.append(child)
        at = child.end
    return out


UTC_TIME: Final = re.compile(r"[0-9]{12}Z")
GENERALIZED_TIME: Final = re.compile(r"[0-9]{14}Z")


def _time(der: bytes, at: _Tlv) -> int:
    """A Time (RFC 5280 section 4.1.2.5) as microseconds since the epoch: UTCTime ``YYMMDDHHMMSSZ`` (YY 50 to 99 is 19YY,
    00 to 49 is 20YY) or GeneralizedTime ``YYYYMMDDHHMMSSZ``, seconds present, no fraction, no offset."""
    text = der[at.body : at.end].decode("latin-1")
    if at.tag == 0x17 and UTC_TIME.fullmatch(text):
        yy = decimal(text[:2])
        year, rest = (1900 + yy if yy >= 50 else 2000 + yy), text[2:]
    elif at.tag == 0x18 and GENERALIZED_TIME.fullmatch(text):
        year, rest = decimal(text[:4]), text[4:]
    else:
        raise _bad("time")
    month, day, hour, minute, second = (decimal(rest[i : i + 2]) for i in (0, 2, 4, 6, 8))
    try:
        return micros_of(datetime(year, month, day, hour, minute, second, tzinfo=UTC))
    except ValueError:
        raise _bad("time") from None


@dataclass(frozen=True)
class CertificateFacts:
    """What the readers take from a certificate: its validity in microseconds since the epoch, and its
    SubjectPublicKeyInfo bytes."""

    not_before: int
    not_after: int
    spki: bytes


#: serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo
_OUTLINE: Final = (0x02, 0x30, 0x30, 0x30, 0x30, 0x30)
#: then, each at most once and in this order: issuerUniqueID [1], subjectUniqueID [2], extensions [3]
_OPTIONAL: Final = (0x81, 0x82, 0xA3)


def certificate_facts(der: bytes) -> CertificateFacts:
    """The facts of ``der`` when it is exactly one DER certificate of the grammar's outline; ``CertificateRefused``
    otherwise."""
    if not isinstance(der, bytes):
        raise _bad("bytes")
    cert = _tlv(der, 0, len(der))
    if cert.tag != 0x30 or cert.end != len(der):
        raise _bad("certificate")
    top = _children(der, cert)
    if len(top) != 3 or (top[0].tag, top[1].tag, top[2].tag) != (0x30, 0x30, 0x03):
        raise _bad("certificate")
    tbs = _children(der, top[0])
    i = 0
    if tbs and tbs[0].tag == 0xA0:  # [0] EXPLICIT Version: v2 (1) or v3 (2); DER never writes the default v1
        version = _children(der, tbs[0])
        if (len(version) != 1 or version[0].tag != 0x02 or version[0].end - version[0].body != 1
                or der[version[0].body] not in (1, 2)):  # fmt: skip
            raise _bad("version")
        i = 1
    if len(tbs) < i + len(_OUTLINE) or any(tbs[i + k].tag != tag for k, tag in enumerate(_OUTLINE)):
        raise _bad("tbs")
    validity = _children(der, tbs[i + 3])
    if len(validity) != 2:
        raise _bad("validity")
    allowed = _OPTIONAL
    for extra in tbs[i + len(_OUTLINE) :]:
        if extra.tag not in allowed:
            raise _bad("tbs")
        allowed = allowed[allowed.index(extra.tag) + 1 :]
    spki = tbs[i + 5]
    return CertificateFacts(_time(der, validity[0]), _time(der, validity[1]), der[spki.start : spki.end])


#: The SubjectPublicKeyInfo of the two key types a DPoP proof may use, as the bytes before the key (RFC 8410 section 4
#: for Ed25519; RFC 5480 section 2 for P-256, a named curve and an uncompressed point).
SPKI_ED25519: Final = bytes.fromhex("302a300506032b6570032100")
SPKI_P256: Final = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004")


def spki_key(spki: bytes) -> dict[str, str | bytes] | None:
    """The public key a SubjectPublicKeyInfo holds, as a JWK's members with the coordinates as bytes: ``kty``, ``crv``,
    ``x`` and, for P-256, ``y``; None for any other key type or encoding."""
    if len(spki) == len(SPKI_ED25519) + 32 and spki.startswith(SPKI_ED25519):
        return {"kty": "OKP", "crv": "Ed25519", "x": spki[len(SPKI_ED25519) :]}
    if len(spki) == len(SPKI_P256) + 64 and spki.startswith(SPKI_P256):
        at = len(SPKI_P256)
        return {"kty": "EC", "crv": "P-256", "x": spki[at : at + 32], "y": spki[at + 32 :]}
    return None
