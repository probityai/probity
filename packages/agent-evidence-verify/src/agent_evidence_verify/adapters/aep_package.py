"""``aep_package/v1``: does an action evidence package verify, layer by layer, under keys the consumer trusts?

An action evidence package (``.aep``) is a ZIP archive: ``response.txt``, ``metadata.json``, ``canonical.bin``
(``response.txt || LF || RFC 8785 (metadata.json)``, or ``response.txt`` alone in the legacy form),
``hash.sha256``, an RSA PKCS#1 v1.5 signature over ``canonical.bin`` (``signature.sig``, base64) with the
signer's ``public_key.pem``, an optional receipt (``overt_receipt.json``, optionally signed in
``overt_receipt.sig``), an optional ML-DSA-65 signature (``signature_pqc.sig`` with ``pqc_public_key.pem``) and
an RFC 3161 time-stamp response (``timestamp.tsr``, base64).

Each layer is one check, run in this order; the first failure is the reason, and every check after it is
reported ``not_evaluated``, never skipped silently and never passed:

``package_shape``  the archive opens, its entries and central directory tile the file from byte 0 to the end
                   with nothing before, between or after them, no two entry names are equal or equal after case
                   folding, no name is a path, it holds the required entries, and ``metadata.json`` is strict
                   I-JSON;
``hash``           SHA-256 of ``canonical.bin`` equals ``hash.sha256`` (one trailing LF accepted);
``canonical_form`` ``canonical.bin`` is the current form; the legacy response-only form leaves ``metadata.json``
                   outside every signature, so it is ``not_established`` / ``metadata_unbound``;
``rsa_signature``  the recovered RSA block is exactly the RFC 8017 encoding (SHA-256 DigestInfo with NULL
                   parameters), or exactly the legacy encoding with absent parameters (reported): the whole
                   block is compared, so bytes between the padding and the digest, another hash OID, or a short
                   padding string are refused, and so is a modulus shorter than 2048 bits;
``signer_pinned``  the RSA key (its DER SubjectPublicKeyInfo) is admitted by the consumer's key authority: the key
                   the package carries proves nothing alone;
``receipt``        when present, the receipt's ``content_hash`` is ``sha256:`` + the package hash, every field it
                   shares with ``metadata.json`` is equal (a value of another type disagrees), and a receipt
                   signature verifies whenever ``overt_receipt.sig`` is present or ``metadata.json`` names it;
``pqc_signature``  when present, ML-DSA-65 over ``canonical.bin`` (RFC 9881 SPKI or a raw 1952-byte key, empty
                   context), and the key is admitted by the consumer's authority;
``timestamp``      the token is granted, it is SignedData whose encapsulated content type and signed
                   ``contentType`` attribute are both id-ct-TSTInfo, its SHA-256 imprint equals the package hash,
                   its ``messageDigest`` attribute equals SHA-256 of the TSTInfo, and the CMS signature (the
                   element after the signature algorithm, whatever unsigned attributes follow) verifies under the
                   certificate it embeds; the certificate key must be admitted by the consumer's
                   ``tsa_authority``.

A key with no authority to judge it is ``not_established`` (``signer_not_established`` or
``tsa_not_established``), never ``supported``.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import zipfile
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, mldsa, padding, rsa

from .. import key_authority
from ..ijson import IJSONError, describe, parse_ijson
from . import jcs_canonical
from .bound_records import assessment_for, bound, decision

CLAIM_TYPE = "aep_package/v1"
CHECKS = ("package_shape", "hash", "canonical_form", "rsa_signature", "signer_pinned", "receipt",
          "pqc_signature", "timestamp")
REQUIRED = ("response.txt", "metadata.json", "canonical.bin", "hash.sha256", "signature.sig", "public_key.pem",
            "timestamp.tsr")
MAX_ENTRIES = 64
MAX_ENTRY_BYTES = 8 * 1024 * 1024
SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")
SHA256_DIGEST_INFO_ABSENT_PARAMS = bytes.fromhex("302f300b0609608648016503040201" "0420")
SHA256_OID = "2.16.840.1.101.3.4.2.1"
MESSAGE_DIGEST_OID = "1.2.840.113549.1.9.4"
CONTENT_TYPE_OID = "1.2.840.113549.1.9.3"
SIGNED_DATA_OID = "1.2.840.113549.1.7.2"
TST_INFO_OID = "1.2.840.113549.1.9.16.1.4"
MIN_RSA_BITS = 2048
RECEIPT_FIELDS = ((("created_at",), ("event", "timestamp")), (("agent_id",), ("subject", "agent_id")),
                  (("tenant_id_hash",), ("subject", "tenant_hash")), (("action_type",), ("event", "action_type")),
                  (("policy_version",), ("policy", "version")), (("policy_decision",), ("policy", "decision")))
LIMIT = ("Checks each layer of one package under the keys the consumer's authorities admit. It shows the "
         "package is intact and signed and time-stamped by admitted keys; it does not show that the recorded "
         "action happened or that the response text is true.")


class Fail(Exception):
    """A layer failed: (check, detail)."""

    def __init__(self, check: str, detail: str) -> None:
        super().__init__(detail)
        self.check, self.detail = check, detail


class Unknown(Exception):
    """A layer could not be decided from the inputs: (check, reason, detail)."""

    def __init__(self, check: str, reason: str, detail: str) -> None:
        super().__init__(detail)
        self.check, self.reason, self.detail = check, reason, detail


# --- RSA: the whole block, exactly -------------------------------------------------------------------

def rsa_encoding(key: rsa.RSAPublicKey, signature: bytes, data: bytes) -> str | None:
    """``rfc8017`` or ``legacy-absent-params`` when the recovered block is exactly that encoding, else None."""
    numbers = key.public_numbers()
    k = (numbers.n.bit_length() + 7) // 8
    if len(signature) != k:
        return None
    s = int.from_bytes(signature, "big")
    if s >= numbers.n:
        return None
    block = pow(s, numbers.e, numbers.n).to_bytes(k, "big")
    digest = hashlib.sha256(data).digest()
    for name, prefix in (("rfc8017", SHA256_DIGEST_INFO), ("legacy-absent-params", SHA256_DIGEST_INFO_ABSENT_PARAMS)):
        t = prefix + digest
        if k < len(t) + 11:
            continue
        if block == b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t:
            return name
    return None


# --- DER, read strictly enough for a time-stamp token -------------------------------------------------

def _tlv(buf: bytes, pos: int) -> tuple[int, int, int, int]:
    """(tag, start of element, start of content, end) of the element at ``pos``; definite lengths only."""
    if pos + 2 > len(buf):
        raise ValueError("truncated element")
    tag, first = buf[pos], buf[pos + 1]
    head = pos + 2
    if first & 0x80:
        n = first & 0x7F
        if n == 0 or n > 4 or head + n > len(buf):
            raise ValueError("bad length")
        length = int.from_bytes(buf[head:head + n], "big")
        head += n
    else:
        length = first
    if head + length > len(buf):
        raise ValueError("element past the end")
    return tag, pos, head, head + length


def _kids(buf: bytes, start: int, end: int) -> list[tuple[int, int, int, int]]:
    out, pos = [], start
    while pos < end:
        element = _tlv(buf, pos)
        out.append(element)
        pos = element[3]
    if pos != end:
        raise ValueError("children overrun")
    return out


def _oid(buf: bytes, element: tuple[int, int, int, int]) -> str:
    tag, _, s, e = element
    if tag != 0x06 or s == e:
        raise ValueError("expected an OID")
    body = buf[s:e]
    parts, n = [str(body[0] // 40), str(body[0] % 40)], 0
    for byte in body[1:]:
        n = (n << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(n))
            n = 0
    return ".".join(parts)


def check_timestamp(raw: bytes, package_hash: str) -> tuple[bytes, str]:
    """(certificate public key DER, detail) for a valid token over ``package_hash``; raises :class:`Fail`."""
    try:
        der = base64.b64decode(raw.strip(), validate=True)
        tag, _, s, e = _tlv(der, 0)
        if tag != 0x30 or e != len(der):
            raise ValueError("TimeStampResp is not one SEQUENCE")
        top = _kids(der, s, e)
        status = _kids(der, top[0][2], top[0][3])
        if status[0][0] != 0x02 or int.from_bytes(der[status[0][2]:status[0][3]], "big") not in (0, 1):
            raise Fail("timestamp", "the time-stamp request was not granted")
        if len(top) < 2:
            raise ValueError("no token")
        content_info = _kids(der, top[1][2], top[1][3])
        if _oid(der, content_info[0]) != SIGNED_DATA_OID:
            raise Fail("timestamp", "the token is not CMS SignedData")
        signed_data = _kids(der, *_tlv(der, content_info[1][2])[2:])
        encap = _kids(der, signed_data[2][2], signed_data[2][3])
        if _oid(der, encap[0]) != TST_INFO_OID:
            raise Fail("timestamp", "the signed content is not a TSTInfo: the key signed something else")
        octet = _kids(der, encap[1][2], encap[1][3])[0]
        tst = der[octet[2]:octet[3]]
        tst_fields = _kids(tst, *_tlv(tst, 0)[2:])
        imprint = _kids(tst, tst_fields[2][2], tst_fields[2][3])
        algorithm = _oid(tst, _kids(tst, imprint[0][2], imprint[0][3])[0])
        if algorithm != SHA256_OID:
            raise Fail("timestamp", f"the imprint algorithm is {algorithm}, not SHA-256")
        if tst[imprint[1][2]:imprint[1][3]].hex() != package_hash:
            raise Fail("timestamp", "the imprint is not the package hash")
        certs = [c for c in signed_data if c[0] == 0xA0]
        signer_infos = _kids(der, signed_data[-1][2], signed_data[-1][3])
        if len(signer_infos) != 1 or not certs:
            raise ValueError("expected one signer and an embedded certificate")
        info = _kids(der, signer_infos[0][2], signer_infos[0][3])
        at = next(i for i, x in enumerate(info) if x[0] == 0xA0)
        attrs = info[at]
        if info[at + 2][0] != 0x04:
            raise ValueError("the signature does not follow the signature algorithm")
        signature = der[info[at + 2][2]:info[at + 2][3]]
        signed_input = b"\x31" + der[attrs[1] + 1:attrs[3]]
        found: dict[str, bytes] = {}
        for attribute in _kids(der, attrs[2], attrs[3]):
            kids = _kids(der, attribute[2], attribute[3])
            name = _oid(der, kids[0])
            if name in (MESSAGE_DIGEST_OID, CONTENT_TYPE_OID):
                values = _kids(der, kids[1][2], kids[1][3])
                if name in found or len(values) != 1:
                    raise Fail("timestamp", f"signed attribute {name} appears more than once")
                found[name] = der[values[0][1]:values[0][3]] if name == CONTENT_TYPE_OID \
                    else der[values[0][2]:values[0][3]]
        if CONTENT_TYPE_OID not in found or _oid(found[CONTENT_TYPE_OID], _tlv(found[CONTENT_TYPE_OID], 0)) \
                != TST_INFO_OID:
            raise Fail("timestamp", "the signed contentType attribute is not id-ct-TSTInfo")
        digest = found.get(MESSAGE_DIGEST_OID)
        if digest != hashlib.sha256(tst).digest():
            raise Fail("timestamp", "messageDigest is not SHA-256 of the TSTInfo")
        for cert_element in _kids(der, certs[0][2], certs[0][3]):
            cert = x509.load_der_x509_certificate(der[cert_element[1]:cert_element[3]])
            public = cert.public_key()
            try:
                if isinstance(public, rsa.RSAPublicKey):
                    public.verify(signature, signed_input, padding.PKCS1v15(), hashes.SHA256())
                elif isinstance(public, ec.EllipticCurvePublicKey):
                    public.verify(signature, signed_input, ec.ECDSA(hashes.SHA256()))
                else:
                    continue
            except InvalidSignature:
                continue
            spki = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            return spki, "imprint, messageDigest and the CMS signature under the embedded certificate"
        raise Fail("timestamp", "the CMS signature does not verify under an embedded certificate")
    except Fail:
        raise
    except (ValueError, IndexError, StopIteration, binascii.Error, TypeError) as exc:
        raise Fail("timestamp", f"the token does not parse ({type(exc).__name__})") from exc


# --- the package -------------------------------------------------------------------------------------

def _tiles(data: bytes, infos: list[zipfile.ZipInfo]) -> None:
    """Refuse any byte outside the entries, the central directory and an empty-comment end record.

    A reader that walks local headers from byte 0 and a reader that starts from the end record read the same
    entries only when nothing sits before, between or after them: a second archive prepended or hidden in a
    gap is read by one and not the other.
    """
    if len(data) < 22 or data[-22:-18] != b"PK\x05\x06" or data[-2:] != b"\x00\x00":
        raise Fail("package_shape", "the end record is not the last 22 bytes: bytes follow the archive")
    size_cd = int.from_bytes(data[-10:-6], "little")
    offset_cd = int.from_bytes(data[-6:-2], "little")
    if offset_cd + size_cd != len(data) - 22:
        raise Fail("package_shape", "bytes sit between the central directory and the end record")
    pos = 0
    for info in sorted(infos, key=lambda i: i.header_offset):
        if info.header_offset != pos or data[pos:pos + 4] != b"PK\x03\x04":
            raise Fail("package_shape", f"bytes sit before {info.filename!r}: the entries do not start at byte 0 "
                       "and follow one another")
        name_len = int.from_bytes(data[pos + 26:pos + 28], "little")
        extra_len = int.from_bytes(data[pos + 28:pos + 30], "little")
        pos += 30 + name_len + extra_len + info.compress_size
        if info.flag_bits & 0x08:
            pos += 16 if data[pos:pos + 4] == b"PK\x07\x08" else 12
    if pos != offset_cd:
        raise Fail("package_shape", "bytes sit between the last entry and the central directory")


def _entries(data: bytes) -> dict[str, bytes]:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            names = [i.filename for i in infos]
            if len(names) != len(set(names)):
                raise Fail("package_shape", "the archive names an entry twice: two readers would read different bytes")
            if len({n.casefold() for n in names}) != len(names):
                raise Fail("package_shape", "two entry names differ only in case: a case-folding reader reads one")
            if any("/" in n or "\\" in n for n in names):
                raise Fail("package_shape", "an entry name is a path: a package is one flat directory")
            if len(infos) > MAX_ENTRIES or any(i.file_size > MAX_ENTRY_BYTES for i in infos):
                raise Fail("package_shape", "the archive is larger than a package")
            _tiles(data, infos)
            return {i.filename: archive.read(i) for i in infos}
    except (zipfile.BadZipFile, OSError, ValueError, NotImplementedError) as exc:
        raise Fail("package_shape", f"the archive does not open ({type(exc).__name__})") from exc


def _dig(value: Any, path: tuple[str, ...]) -> Any:
    for member in path:
        if not isinstance(value, dict) or member not in value:
            return None
        value = value[member]
    return value


def _admit(authority: Any, key: bytes, label: str, reason: str) -> dict:
    answer = key_authority.authorize(authority, key)
    if answer.outcome == key_authority.UNAUTHORIZED:
        raise Fail(label, f"the key is not admitted ({answer.reason})")
    if answer.outcome == key_authority.UNKNOWN:
        raise Unknown(label, reason, answer.reason)
    return answer.check()


def _b64(raw: bytes, label: str, check: str) -> bytes:
    try:
        return base64.b64decode(bytes(c for c in raw if c not in b"\t\n\x0b\x0c\r "), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise Fail(check, f"{label} is not base64") from exc


def check_package(data: bytes, authority: Any, tsa_authority: Any) -> tuple[list[dict], str, str]:
    """(checks, decision, reason): every check is reported; after a failure the rest are not_evaluated."""
    results: dict[str, dict] = {}
    extra: list[dict] = []
    state = {"meta": None, "entries": None, "hash": None, "rsa_key": None}

    def shape() -> str:
        entries = state["entries"] = _entries(data)
        missing = [n for n in REQUIRED if n not in entries]
        if missing:
            raise Fail("package_shape", f"the package lacks {missing}")
        try:
            state["meta"] = parse_ijson(entries["metadata.json"])
        except IJSONError as exc:
            raise Fail("package_shape", f"metadata.json: {describe(exc)}") from exc
        if not isinstance(state["meta"], dict):
            raise Fail("package_shape", "metadata.json is not an object")
        return f"{len(entries)} entries, none named twice"

    def hash_layer() -> str:
        e = state["entries"]
        text = e["hash.sha256"].decode("ascii", "replace")
        text = text.removesuffix("\n")
        actual = hashlib.sha256(e["canonical.bin"]).hexdigest()
        if text != actual:
            raise Fail("hash", "SHA-256 of canonical.bin is not hash.sha256")
        state["hash"] = actual
        return "SHA-256 of canonical.bin equals hash.sha256"

    def form() -> str:
        e = state["entries"]
        if e["canonical.bin"] == e["response.txt"] + b"\n" + jcs_canonical._value(state["meta"]).encode("utf-8"):
            return "response.txt, LF, RFC 8785 of metadata.json"
        if e["canonical.bin"] == e["response.txt"]:
            raise Unknown("canonical_form", "metadata_unbound",
                          "legacy response-only form: metadata.json is outside every signature, so its action, "
                          "agent and policy decision can be rewritten without breaking any layer")
        raise Fail("canonical_form", "canonical.bin is neither the current nor the legacy form")

    def rsa_layer() -> str:
        e = state["entries"]
        try:
            key = serialization.load_pem_public_key(e["public_key.pem"])
        except (ValueError, UnsupportedAlgorithm) as exc:
            raise Fail("rsa_signature", "public_key.pem is not a public key") from exc
        if not isinstance(key, rsa.RSAPublicKey):
            raise Fail("rsa_signature", "public_key.pem is not an RSA key")
        if key.key_size < MIN_RSA_BITS:
            raise Fail("rsa_signature", f"the RSA modulus is {key.key_size} bits, under {MIN_RSA_BITS}")
        how = rsa_encoding(key, _b64(e["signature.sig"], "signature.sig", "rsa_signature"), e["canonical.bin"])
        if how is None:
            raise Fail("rsa_signature", "the recovered block is not an exact SHA-256 PKCS#1 v1.5 encoding")
        state["rsa_key"] = key
        return "RFC 8017 DigestInfo" if how == "rfc8017" else "legacy DigestInfo with absent parameters (exact block)"

    def signer() -> str:
        spki = state["rsa_key"].public_bytes(serialization.Encoding.DER,
                                             serialization.PublicFormat.SubjectPublicKeyInfo)
        extra.append(_admit(authority, spki, "signer_pinned", "signer_not_established"))
        return "the RSA key is admitted by the consumer's authority"

    def receipt() -> str:
        e, meta = state["entries"], state["meta"]
        if "overt_receipt.json" not in e:
            results["receipt"] = {"id": "receipt", "status": "absent", "detail": "no receipt in the package"}
            return ""
        try:
            body = parse_ijson(e["overt_receipt.json"])
        except IJSONError as exc:
            raise Fail("receipt", f"overt_receipt.json: {describe(exc)}") from exc
        if not isinstance(body, dict) or body.get("content_hash") != "sha256:" + state["hash"]:
            raise Fail("receipt", "the receipt's content_hash is not the package hash")
        for meta_path, receipt_path in RECEIPT_FIELDS:
            mine, theirs = _dig(meta, meta_path), _dig(body, receipt_path)
            if mine is not None and theirs is not None and mine != theirs:
                raise Fail("receipt", f"{'.'.join(receipt_path)} disagrees with metadata.{meta_path[0]}")
        if meta.get("overt_receipt_signature") == "overt_receipt.sig" or "overt_receipt.sig" in e:
            if "overt_receipt.sig" not in e:
                raise Fail("receipt", "metadata names a receipt signature the package lacks")
            sig = _b64(e["overt_receipt.sig"], "overt_receipt.sig", "receipt")
            if rsa_encoding(state["rsa_key"], sig, e["overt_receipt.json"]) is None:
                raise Fail("receipt", "the receipt signature does not verify")
            return "binding, shared fields and the receipt signature"
        return "binding and shared fields; the receipt is not signed on its own"

    def pqc() -> str:
        e = state["entries"]
        if "signature_pqc.sig" not in e and "pqc_public_key.pem" not in e:
            results["pqc_signature"] = {"id": "pqc_signature", "status": "absent", "detail": "no ML-DSA layer"}
            return ""
        if "signature_pqc.sig" not in e or "pqc_public_key.pem" not in e:
            raise Fail("pqc_signature", "the ML-DSA layer lacks its signature or its key")
        pem = e["pqc_public_key.pem"]
        try:
            key = serialization.load_pem_public_key(pem)
        except (ValueError, UnsupportedAlgorithm):
            lines = [ln for ln in pem.decode("ascii", "replace").splitlines() if ln and not ln.startswith("-----")]
            try:
                key = mldsa.MLDSA65PublicKey.from_public_bytes(base64.b64decode("".join(lines), validate=True))
            except (ValueError, binascii.Error) as exc:
                raise Fail("pqc_signature", "pqc_public_key.pem is not an ML-DSA-65 key") from exc
        if not isinstance(key, mldsa.MLDSA65PublicKey):
            raise Fail("pqc_signature", "pqc_public_key.pem is not an ML-DSA-65 key")
        try:
            key.verify(_b64(e["signature_pqc.sig"], "signature_pqc.sig", "pqc_signature"), e["canonical.bin"])
        except InvalidSignature as exc:
            raise Fail("pqc_signature", "the ML-DSA-65 signature does not verify") from exc
        extra.append(_admit(authority, key.public_bytes_raw(), "pqc_signature", "signer_not_established"))
        return "ML-DSA-65 over canonical.bin under an admitted key"

    def stamp() -> str:
        spki, detail = check_timestamp(state["entries"]["timestamp.tsr"], state["hash"])
        extra.append(_admit(tsa_authority, spki, "timestamp", "tsa_not_established"))
        return detail + "; the certificate key is admitted"

    order = {"package_shape": shape, "hash": hash_layer, "canonical_form": form, "rsa_signature": rsa_layer,
             "signer_pinned": signer, "receipt": receipt, "pqc_signature": pqc, "timestamp": stamp}
    outcome: tuple[str, str] | None = None
    pending: tuple[str, str] | None = None
    for check in CHECKS:
        if outcome is not None:
            results[check] = {"id": check, "status": "not_evaluated", "detail": f"after {outcome[1]} failed"}
            continue
        try:
            detail = order[check]()
            results.setdefault(check, {"id": check, "status": "pass", "detail": detail})
        except Fail as failed:
            results[failed.check] = {"id": failed.check, "status": "fail", "detail": failed.detail}
            outcome = ("contradicted", failed.check)
        except Unknown as unknown:
            results[unknown.check] = {"id": unknown.check, "status": "unavailable", "detail": unknown.detail}
            pending = pending or ("not_established", unknown.reason)
    checks = [results[c] for c in CHECKS] + extra
    result, reason = outcome or pending or ("supported", "package_verifies")
    return checks, result, reason


def adjudicate(case: Any, policy: Any, artifact_root: Path) -> dict:
    """Consumer claim adapter: one package and the consumer's signer and time-stamp authorities."""
    case_id, artifacts, assessment = assessment_for(case, policy, CLAIM_TYPE, {"package"},
                                                    {"authority", "tsa_authority"})
    data, binding = bound(artifacts, artifact_root, assessment["package"], "assessment.package")
    scope = {"package": binding, "limit": LIMIT}
    if data is None:
        return decision(case_id, CLAIM_TYPE, scope, "not_established", "package_unavailable")
    checks, result, reason = check_package(data, assessment.get("authority"), assessment.get("tsa_authority"))
    return {**decision(case_id, CLAIM_TYPE, scope, result, reason, checks), "vantage": "independent"}
