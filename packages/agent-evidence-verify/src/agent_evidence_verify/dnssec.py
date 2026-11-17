"""Offline DNSSEC validation of one RRset under a chain of DNS records and a consumer trust anchor.

A DNS answer says what a name holds. Only its DNSSEC chain says the zone owner published it: a
signature over the RRset (RRSIG) by a key of the zone (DNSKEY), whose digest the parent zone signed
(DS), up to a key the consumer trusts. This module checks that chain from bytes alone, with no
resolver and no network, at an instant the consumer names.

The chain is a series of resource records in DNS wire format, each one uncompressed (owner name,
type, class, TTL, RDATA length, RDATA), in any order: the form of RFC 9102 section 3 and of what
``agent-evidence-observer`` records at call time. The consumer's trust anchor is a zone and its DS
records in presentation form (``"20326 8 2 E06D44B8..."``); for the DNS root, IANA publishes them at
https://data.iana.org/root-anchors/root-anchors.xml.

The rules, written from RFC 4034 and RFC 4035, so that a second reader of the same bytes agrees:

- An RRset is the records of one owner, class and type; repeated records count once, and the
  signed form sorts them by RDATA (RFC 4034 section 6.3). The signature input is the RRSIG RDATA
  without its signature, then each record as owner (lowercase), type, class, the RRSIG's original
  TTL, length and RDATA (section 3.1.8.1).
- A signature counts only inside its validity window at the instant, in serial-number arithmetic
  (RFC 4034 section 3.1.5), when its signer is the owner or an ancestor of it (the parent for a DS
  RRset, the owner itself for a DNSKEY RRset), and when its key tag and algorithm name a key the
  chain trusts. One such signature that verifies validates the RRset.
- A zone's keys are trusted when its DNSKEY RRset holds a zone key (flag bit 7, protocol 3) whose
  digest is in the DS set that vouches for the zone (the consumer's anchor, or a DS RRset the
  parent signed) and that key signed the DNSKEY RRset. Every zone key of a validated DNSKEY RRset
  may then sign the zone's data.
- An RRSIG whose label count is below the owner's label count says the answer was expanded from a
  wildcard; checking it needs a proof that no closer name exists, which this reader does not read,
  so such an RRset is not validated.
- Names in the RDATA of the types read here are not lowercased, because none of them is in the
  list of RFC 4034 section 6.2 (as RFC 6840 section 5.1 left it). Other types are not validated.

Outcomes: ``secure`` (the RRset is validated), ``bogus`` with a reason (the chain is present and a
check fails: a signature that does not verify, a window that does not cover the instant, a DS that
matches no key), and ``indeterminate`` with a reason (a record the chain needs is missing, or an
algorithm is not read). An adapter maps them to ``supported``, ``contradicted`` and
``not_established``; a missing chain never reads as validated.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

SECURE, BOGUS, INDETERMINATE = "secure", "bogus", "indeterminate"
CLASS_IN = 1
TYPES = {"A": 1, "TXT": 16, "AAAA": 28, "DS": 43, "RRSIG": 46, "DNSKEY": 48, "TLSA": 52,
         "SVCB": 64, "HTTPS": 65}
TYPE_NAMES = {number: name for name, number in TYPES.items()}
#: Types whose RDATA carries no name RFC 4034 section 6.2 lowercases: the signed form is the RDATA.
VALIDATED_TYPES = frozenset({1, 16, 28, 43, 48, 52, 64, 65})
#: Signing algorithms read (RFC 8624 section 3.1 MUST and RECOMMENDED validation algorithms).
ALGORITHMS = {8: "RSASHA256", 10: "RSASHA512", 13: "ECDSAP256SHA256", 14: "ECDSAP384SHA384",
              15: "ED25519", 16: "ED448"}
#: DS digest types read: SHA-256 and SHA-384. SHA-1 (type 1) is not read (RFC 8624 section 3.3).
DIGESTS = {2: hashlib.sha256, 4: hashlib.sha384}
MAX_CHAIN_RECORDS = 4096
MAX_DEPTH = 32
_ZONE_KEY, _REVOKE = 0x0100, 0x0080
_DS_TEXT = re.compile(r"\s*(\d{1,5})\s+(\d{1,3})\s+(\d{1,3})\s+([0-9A-Fa-f]+)\s*")


class ChainError(ValueError):
    """The chain bytes are not a series of uncompressed DNS records."""


@dataclass(frozen=True)
class Record:
    owner: tuple[bytes, ...]  # lowercase labels, root last omitted
    rtype: int
    rclass: int
    ttl: int
    rdata: bytes


@dataclass
class Result:
    """One answer: the outcome, why, and the records it rests on."""

    outcome: str
    reason: str
    records: list[bytes] = field(default_factory=list)
    signers: list[str] = field(default_factory=list)

    def check(self, name: str, rtype: int) -> dict:
        return {"id": "dnssec_chain", "status": {SECURE: "pass", BOGUS: "fail",
                                                 INDETERMINATE: "unavailable"}[self.outcome],
                "name": name, "type": TYPE_NAMES.get(rtype, f"TYPE{rtype}"),
                "outcome": self.outcome, "reason": self.reason, "signers": self.signers,
                "rdata_sha256": [hashlib.sha256(r).hexdigest() for r in self.records]}


# ------------------------------------------------------------------ names
def name_labels(text: Any, label: str = "name") -> tuple[bytes, ...]:
    """Lowercase labels of a presentation name (``example.com.`` or ``example.com``; ``.`` is root)."""
    if not isinstance(text, str) or not text.isascii() or not text or "\\" in text:
        raise ValueError(f"{label}: expected an ASCII domain name")
    if text == ".":
        return ()
    body = text.removesuffix(".")
    labels = tuple(part.lower().encode("ascii") for part in body.split("."))
    if any(not part or len(part) > 63 for part in labels) or sum(len(p) + 1 for p in labels) + 1 > 255:
        raise ValueError(f"{label}: expected an ASCII domain name")
    return labels


def name_text(labels: tuple[bytes, ...]) -> str:
    return "".join(part.decode("ascii", "backslashreplace") + "." for part in labels) or "."


def _name_wire(labels: tuple[bytes, ...]) -> bytes:
    return b"".join(bytes([len(part)]) + part for part in labels) + b"\x00"


def _read_name(data: bytes, offset: int) -> tuple[tuple[bytes, ...], int]:
    labels: list[bytes] = []
    total = 1
    while True:
        if offset >= len(data):
            raise ChainError("name runs past the end")
        length = data[offset]
        offset += 1
        if length == 0:
            return tuple(labels), offset
        if length > 63:
            raise ChainError("a compressed or extended label is not read")
        if offset + length > len(data):
            raise ChainError("label runs past the end")
        total += length + 1
        if total > 255:
            raise ChainError("name longer than 255 octets")
        labels.append(data[offset:offset + length].lower())
        offset += length


def is_within(name: tuple[bytes, ...], zone: tuple[bytes, ...]) -> bool:
    """Whether ``name`` is ``zone`` or a name under it."""
    return len(name) >= len(zone) and name[len(name) - len(zone):] == zone


# ------------------------------------------------------------------ wire
def parse_chain(data: Any) -> list[Record]:
    """Every record of a chain, in order; :class:`ChainError` for anything else."""
    if not isinstance(data, bytes):
        raise ChainError("expected chain bytes")
    records, offset = [], 0
    while offset < len(data):
        owner, offset = _read_name(data, offset)
        if offset + 10 > len(data):
            raise ChainError("record header runs past the end")
        rtype = int.from_bytes(data[offset:offset + 2], "big")
        rclass = int.from_bytes(data[offset + 2:offset + 4], "big")
        ttl = int.from_bytes(data[offset + 4:offset + 8], "big")
        length = int.from_bytes(data[offset + 8:offset + 10], "big")
        offset += 10
        if offset + length > len(data):
            raise ChainError("RDATA runs past the end")
        records.append(Record(owner, rtype, rclass, ttl, data[offset:offset + length]))
        offset += length
        if len(records) > MAX_CHAIN_RECORDS:
            raise ChainError(f"more than {MAX_CHAIN_RECORDS} records")
    return records


@dataclass(frozen=True)
class _Sig:
    covered: int
    algorithm: int
    labels: int
    original_ttl: int
    expiration: int
    inception: int
    key_tag: int
    signer: tuple[bytes, ...]
    head: bytes  # the RDATA up to and including the signer name, as signed
    signature: bytes


def _rrsig(rdata: bytes) -> _Sig:
    if len(rdata) < 19:
        raise ChainError("RRSIG RDATA too short")
    signer, end = _read_name(rdata, 18)
    signature = rdata[end:]
    if not signature:
        raise ChainError("RRSIG carries no signature")
    return _Sig(int.from_bytes(rdata[0:2], "big"), rdata[2], rdata[3],
                int.from_bytes(rdata[4:8], "big"), int.from_bytes(rdata[8:12], "big"),
                int.from_bytes(rdata[12:16], "big"), int.from_bytes(rdata[16:18], "big"),
                signer, rdata[:18] + _name_wire(signer), signature)


def key_tag(rdata: bytes) -> int:
    """RFC 4034 Appendix B over a DNSKEY RDATA (not algorithm 1, which is never read here)."""
    total = sum(byte << 8 if index % 2 == 0 else byte for index, byte in enumerate(rdata))
    total += (total >> 16) & 0xFFFF
    return total & 0xFFFF


def ds_digest(owner: tuple[bytes, ...], dnskey: bytes, digest_type: int) -> bytes:
    """The DS digest of a DNSKEY RDATA under its owner name (RFC 4509, RFC 6605 section 2)."""
    return DIGESTS[digest_type](_name_wire(owner) + dnskey).digest()


def parse_ds_text(text: Any, label: str = "ds") -> tuple[int, int, int, bytes]:
    """``(key_tag, algorithm, digest_type, digest)`` of a DS record in presentation form."""
    match = _DS_TEXT.fullmatch(text) if isinstance(text, str) else None
    if match is None or len(match.group(4)) % 2:
        raise ValueError(f"{label}: expected '<key tag> <algorithm> <digest type> <hex digest>'")
    tag, algorithm, digest_type = (int(match.group(n)) for n in (1, 2, 3))
    if tag > 0xFFFF or algorithm > 255 or digest_type > 255:
        raise ValueError(f"{label}: a field is out of range")
    return tag, algorithm, digest_type, bytes.fromhex(match.group(4))


def _ds_rdata(rdata: bytes) -> tuple[int, int, int, bytes]:
    if len(rdata) < 5:
        raise ChainError("DS RDATA too short")
    return int.from_bytes(rdata[:2], "big"), rdata[2], rdata[3], rdata[4:]


# ------------------------------------------------------------------ signatures
def _rsa_key(key: bytes):
    if not key:
        raise ValueError("empty RSA key")
    if key[0]:
        exp_len, rest = key[0], key[1:]
    else:
        if len(key) < 3:
            raise ValueError("short RSA key")
        exp_len, rest = int.from_bytes(key[1:3], "big"), key[3:]
    exponent, modulus = rest[:exp_len], rest[exp_len:]
    if len(exponent) != exp_len or not modulus or modulus[0] == 0:
        raise ValueError("malformed RSA key")
    n = int.from_bytes(modulus, "big")
    if n.bit_length() < 1024:
        raise ValueError("RSA modulus below 1024 bits")
    return rsa.RSAPublicNumbers(int.from_bytes(exponent, "big"), n).public_key()


def verify_signature(algorithm: int, key: bytes, signature: bytes, data: bytes) -> bool:
    """Whether ``signature`` verifies over ``data`` under a DNSKEY public key; False if unreadable."""
    try:
        if algorithm in (8, 10):
            digest = hashes.SHA256() if algorithm == 8 else hashes.SHA512()
            _rsa_key(key).verify(signature, data, padding.PKCS1v15(), digest)
        elif algorithm in (13, 14):
            curve, size, digest = ((ec.SECP256R1(), 32, hashes.SHA256()) if algorithm == 13
                                   else (ec.SECP384R1(), 48, hashes.SHA384()))
            if len(key) != 2 * size or len(signature) != 2 * size:
                return False
            public = ec.EllipticCurvePublicKey.from_encoded_point(curve, b"\x04" + key)
            der = encode_dss_signature(int.from_bytes(signature[:size], "big"),
                                       int.from_bytes(signature[size:], "big"))
            public.verify(der, data, ec.ECDSA(digest))
        elif algorithm == 15:
            ed25519.Ed25519PublicKey.from_public_bytes(key).verify(signature, data)
        elif algorithm == 16:
            ed448.Ed448PublicKey.from_public_bytes(key).verify(signature, data)
        else:
            return False
    except (InvalidSignature, ValueError):
        return False
    return True


def _serial_le(a: int, b: int) -> bool:
    """``a <= b`` in RFC 1982 serial-number arithmetic over 32 bits."""
    return (b - a) % 2**32 < 2**31


def _signed_data(sig: _Sig, owner: tuple[bytes, ...], rtype: int, rclass: int,
                 rdatas: list[bytes]) -> bytes:
    prefix = (_name_wire(owner) + rtype.to_bytes(2, "big") + rclass.to_bytes(2, "big")
              + sig.original_ttl.to_bytes(4, "big"))
    return sig.head + b"".join(prefix + len(r).to_bytes(2, "big") + r for r in sorted(set(rdatas)))


# ------------------------------------------------------------------ validation
#: The order in which a failing signature's reason is reported: present evidence that fails first.
_RANK = {"signature_invalid": 0, "rrsig_expired": 1, "rrsig_not_yet_valid": 2,
         "rrsig_key_not_trusted": 3}


class Validator:
    """Validate RRsets of one chain at one instant under one trust anchor."""

    def __init__(self, records: list[Record], anchor_zone: tuple[bytes, ...],
                 anchor_ds: list[tuple[int, int, int, bytes]], now: int) -> None:
        self.anchor_zone, self.anchor_ds, self.now = anchor_zone, anchor_ds, now
        self.rrsets: dict[tuple[tuple[bytes, ...], int], list[bytes]] = {}
        self.sigs: dict[tuple[tuple[bytes, ...], int], list[_Sig]] = {}
        self.malformed_sigs = 0
        for record in records:
            if record.rclass != CLASS_IN:
                continue
            if record.rtype == TYPES["RRSIG"]:
                try:
                    sig = _rrsig(record.rdata)
                except ChainError:
                    self.malformed_sigs += 1
                    continue
                self.sigs.setdefault((record.owner, sig.covered), []).append(sig)
            else:
                rdatas = self.rrsets.setdefault((record.owner, record.rtype), [])
                if record.rdata not in rdatas:
                    rdatas.append(record.rdata)
        self._keys: dict[tuple[bytes, ...], Result | list[tuple[int, int, bytes]]] = {}

    def zone_keys(self, zone: tuple[bytes, ...], depth: int = 0) -> Result | list[tuple[int, int, bytes]]:
        """The trusted ``(key tag, algorithm, key)`` of a zone, or the Result that says why none."""
        if zone in self._keys:
            return self._keys[zone]
        if depth > MAX_DEPTH or not is_within(zone, self.anchor_zone):
            return Result(INDETERMINATE, "signer_outside_trust_anchor")
        if zone == self.anchor_zone:
            ds_set = self.anchor_ds
        else:
            ds = self.validate(zone, TYPES["DS"], depth + 1)
            if ds.outcome != SECURE:
                self._keys[zone] = ds if ds.reason != "rrset_missing" else Result(
                    INDETERMINATE, "ds_missing")
                return self._keys[zone]
            try:
                ds_set = [_ds_rdata(r) for r in ds.records]
            except ChainError:
                self._keys[zone] = Result(BOGUS, "ds_malformed")
                return self._keys[zone]
        dnskeys = self.rrsets.get((zone, TYPES["DNSKEY"]))
        if not dnskeys:
            self._keys[zone] = Result(INDETERMINATE, "dnskey_missing")
            return self._keys[zone]
        usable_ds = [d for d in ds_set if d[2] in DIGESTS and d[1] in ALGORITHMS]
        if not usable_ds:
            self._keys[zone] = Result(INDETERMINATE, "ds_algorithm_unsupported")
            return self._keys[zone]
        keys = [(key_tag(r), r[3], r[4:]) for r in dnskeys
                if len(r) > 4 and r[2] == 3 and int.from_bytes(r[:2], "big") & _ZONE_KEY]
        entry = [(key_tag(r), r[3], r[4:]) for r in dnskeys
                 if len(r) > 4 and r[2] == 3 and int.from_bytes(r[:2], "big") & _ZONE_KEY
                 and not int.from_bytes(r[:2], "big") & _REVOKE
                 and any(d[0] == key_tag(r) and d[1] == r[3] and ds_digest(zone, r, d[2]) == d[3]
                         for d in usable_ds)]
        if not entry:
            self._keys[zone] = Result(BOGUS, "ds_mismatch")
            return self._keys[zone]
        checked = self._check(zone, TYPES["DNSKEY"], dnskeys, entry, zone)
        self._keys[zone] = keys if checked.outcome == SECURE else checked
        return self._keys[zone]

    def _check(self, owner: tuple[bytes, ...], rtype: int, rdatas: list[bytes],
               keys: list[tuple[int, int, bytes]], signer: tuple[bytes, ...]) -> Result:
        """Whether one RRSIG by ``signer`` under one of ``keys`` validates the RRset."""
        failures: list[str] = []
        for sig in self.sigs.get((owner, rtype), []):
            if sig.signer != signer:
                continue
            if sig.labels != len(owner) or sig.algorithm not in ALGORITHMS:
                continue
            matching = [k for k in keys if k[0] == sig.key_tag and k[1] == sig.algorithm]
            if not matching:
                failures.append("rrsig_key_not_trusted")
                continue
            if not _serial_le(sig.inception, self.now):
                failures.append("rrsig_not_yet_valid")
                continue
            if not _serial_le(self.now, sig.expiration):
                failures.append("rrsig_expired")
                continue
            data = _signed_data(sig, owner, rtype, CLASS_IN, rdatas)
            if any(verify_signature(sig.algorithm, key, sig.signature, data) for _, _, key in matching):
                return Result(SECURE, "rrset_validated", sorted(set(rdatas)), [name_text(signer)])
            failures.append("signature_invalid")
        if failures:
            return Result(BOGUS, min(failures, key=_RANK.__getitem__))
        return Result(INDETERMINATE, "rrsig_missing")

    def validate(self, owner: tuple[bytes, ...], rtype: int, depth: int = 0) -> Result:
        """Validate the RRset ``owner``/``rtype`` from the trust anchor down."""
        if depth > MAX_DEPTH:
            return Result(INDETERMINATE, "chain_too_deep")
        if rtype not in VALIDATED_TYPES:
            return Result(INDETERMINATE, "rrtype_unsupported")
        rdatas = self.rrsets.get((owner, rtype))
        if not rdatas:
            return Result(INDETERMINATE, "rrset_missing")
        sigs = self.sigs.get((owner, rtype), [])
        if not sigs:
            return Result(INDETERMINATE, "rrsig_missing")
        if any(sig.labels < len(owner) for sig in sigs) and all(
                sig.labels != len(owner) for sig in sigs):
            return Result(INDETERMINATE, "wildcard_expansion_unsupported")
        if all(sig.algorithm not in ALGORITHMS for sig in sigs):
            return Result(INDETERMINATE, "algorithm_unsupported")
        results: list[Result] = []
        for signer in dict.fromkeys(sig.signer for sig in sigs):
            if not is_within(owner, signer) or (rtype == TYPES["DS"] and signer == owner) or (
                    rtype == TYPES["DNSKEY"] and signer != owner):
                results.append(Result(BOGUS, "signer_not_authoritative"))
                continue
            if rtype == TYPES["DNSKEY"]:
                keys = self.zone_keys(owner, depth + 1)
                if isinstance(keys, Result):
                    results.append(keys)
                    continue
                return Result(SECURE, "rrset_validated", sorted(set(rdatas)), [name_text(owner)])
            keys = self.zone_keys(signer, depth + 1)
            if isinstance(keys, Result):
                results.append(keys)
                continue
            result = self._check(owner, rtype, rdatas, keys, signer)
            if result.outcome == SECURE:
                return result
            results.append(result)
        bogus = [r for r in results if r.outcome == BOGUS]
        return bogus[0] if bogus else results[0]


def validate(chain: bytes, name: Any, rtype: int, anchor_zone: Any, anchor_ds: list[str],
             now: int) -> Result:
    """Validate one RRset of ``chain`` at POSIX second ``now``; malformed consumer input raises ValueError."""
    owner = name_labels(name)
    zone = name_labels(anchor_zone, "trust_anchor.zone")
    if not isinstance(anchor_ds, list) or not anchor_ds:
        raise ValueError("trust_anchor.ds: expected a non-empty list of DS records")
    ds = [parse_ds_text(text, f"trust_anchor.ds[{i}]") for i, text in enumerate(anchor_ds)]
    if not is_within(owner, zone):
        return Result(INDETERMINATE, "name_outside_trust_anchor")
    try:
        records = parse_chain(chain)
    except ChainError:
        return Result(BOGUS, "chain_malformed")
    return Validator(records, zone, ds, now).validate(owner, rtype)


def rrtype(value: Any, label: str = "type") -> int:
    """A type by mnemonic (``SVCB``) or ``TYPE<n>``; ValueError otherwise."""
    if isinstance(value, str) and value.upper() in TYPES:
        return TYPES[value.upper()]
    match = re.fullmatch(r"TYPE(\d{1,5})", value) if isinstance(value, str) else None
    if match and int(match.group(1)) <= 0xFFFF:
        return int(match.group(1))
    raise ValueError(f"{label}: expected a record type such as SVCB or TYPE64")


def txt_strings(rdata: bytes) -> str:
    """The character-strings of one TXT RDATA, concatenated (RFC 1035 section 3.3.14)."""
    out, offset = b"", 0
    while offset < len(rdata):
        length = rdata[offset]
        out += rdata[offset + 1:offset + 1 + length]
        offset += 1 + length
    return out.decode("utf-8", "replace")
