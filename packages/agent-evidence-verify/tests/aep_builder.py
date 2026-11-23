"""Build action evidence packages from keys generated for the test session.

Everything here is our own bytes: an RSA signer, an ML-DSA-65 signer from a fixed seed, and a time-stamp
authority with a self-signed EC certificate whose RFC 3161 responses are DER-encoded by hand.
"""

from __future__ import annotations

import base64
import datetime
import functools
import hashlib
import io
import json
import zipfile

from agent_evidence_verify.adapters import aep_package as ap
from agent_evidence_verify.adapters.jcs_canonical import canonical
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, mldsa, padding, rsa
from cryptography.x509.oid import NameOID


@functools.cache
def rsa_key(name: str = "signer") -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@functools.cache
def tsa() -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = ec.derive_private_key(int.from_bytes(hashlib.sha256(b"aep-test/tsa").digest(), "big") % (2**255), ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test time-stamp authority")])
    now = datetime.datetime(2026, 11, 1, tzinfo=datetime.UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(7).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=3650))
            .sign(key, hashes.SHA256()))
    return key, cert


def mldsa_key() -> mldsa.MLDSA65PrivateKey:
    return mldsa.MLDSA65PrivateKey.from_seed_bytes(hashlib.sha256(b"aep-test/mldsa").digest())


def spki(public) -> bytes:
    return public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def pin(*keys: bytes) -> dict:
    return {"kind": "pin", "keys": [{"public_key_sha256": hashlib.sha256(k).hexdigest()} for k in keys]}


# --- minimal DER -------------------------------------------------------------------------------------

def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _len(len(body)) + body


def seq(*parts: bytes) -> bytes:
    return tlv(0x30, b"".join(parts))


def integer(n: int) -> bytes:
    raw = n.to_bytes(max(1, (n.bit_length() + 8) // 8), "big")
    return tlv(0x02, raw)


def oid(text: str) -> bytes:
    nums = [int(x) for x in text.split(".")]
    body = bytes([nums[0] * 40 + nums[1]])
    for n in nums[2:]:
        chunk = [n & 0x7F]
        n >>= 7
        while n:
            chunk.append(0x80 | (n & 0x7F))
            n >>= 7
        body += bytes(reversed(chunk))
    return tlv(0x06, body)


def octets(raw: bytes) -> bytes:
    return tlv(0x04, raw)


def timestamp_response(imprint: bytes, *, algorithm: str = ap.SHA256_OID, status: int = 0,
                       tamper_digest: bool = False, signer: ec.EllipticCurvePrivateKey | None = None) -> bytes:
    """A base64 RFC 3161 TimeStampResp over ``imprint``, signed by the test authority."""
    key, cert = tsa()
    tst = seq(integer(1), oid("1.3.6.1.4.1.99999.1"), seq(seq(oid(algorithm), tlv(0x05, b"")), octets(imprint)),
              integer(42), tlv(0x18, b"20261115120000Z"))
    digest = hashlib.sha256(tst).digest()
    if tamper_digest:
        digest = bytes(32)
    attrs = (seq(oid("1.2.840.113549.1.9.3"), tlv(0x31, oid("1.2.840.113549.1.9.16.1.4")))
             + seq(oid(ap.MESSAGE_DIGEST_OID), tlv(0x31, octets(digest))))
    signature = (signer or key).sign(tlv(0x31, attrs), ec.ECDSA(hashes.SHA256()))
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    issuer_serial = seq(cert.issuer.public_bytes(), integer(cert.serial_number))
    signer_info = seq(integer(1), issuer_serial, seq(oid(ap.SHA256_OID)), tlv(0xA0, attrs),
                      seq(oid("1.2.840.10045.4.3.2")), octets(signature))
    signed_data = seq(integer(3), tlv(0x31, seq(oid(ap.SHA256_OID))),
                      seq(oid("1.2.840.113549.1.9.16.1.4"), tlv(0xA0, octets(tst))),
                      tlv(0xA0, cert_der), tlv(0x31, signer_info))
    token = seq(oid("1.2.840.113549.1.7.2"), tlv(0xA0, signed_data))
    return base64.b64encode(seq(seq(integer(status)), token))


def rsa_raw_sign(key: rsa.RSAPrivateKey, block: bytes) -> bytes:
    numbers = key.private_numbers()
    k = (key.key_size + 7) // 8
    return pow(int.from_bytes(block, "big"), numbers.d, numbers.public_numbers.n).to_bytes(k, "big")


def full_block(key: rsa.RSAPrivateKey, t: bytes) -> bytes:
    k = (key.key_size + 7) // 8
    return b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t


def entries(*, legacy: bool = False, receipt: bool = True, sign_receipt: bool = True,
            pqc: bool = False) -> dict[str, bytes]:
    key = rsa_key()
    response = b"tool call returned 3 rows"
    meta = {"agent_id": "agent-7", "action_type": "tools/call", "policy_decision": "allow",
            "policy_version": "p-1", "created_at": "2026-11-15T12:00:00Z"}
    if receipt and sign_receipt:
        meta["overt_receipt_signature"] = "overt_receipt.sig"
    canonical_bin = response if legacy else response + b"\n" + canonical("rfc8785", json.dumps(meta))
    digest = hashlib.sha256(canonical_bin).hexdigest()
    out = {"response.txt": response, "metadata.json": json.dumps(meta).encode(), "canonical.bin": canonical_bin,
           "hash.sha256": (digest + "\n").encode(),
           "signature.sig": base64.b64encode(key.sign(canonical_bin, padding.PKCS1v15(), hashes.SHA256())),
           "public_key.pem": key.public_key().public_bytes(serialization.Encoding.PEM,
                                                           serialization.PublicFormat.SubjectPublicKeyInfo),
           "timestamp.tsr": timestamp_response(bytes.fromhex(digest))}
    if receipt:
        body = json.dumps({"content_hash": "sha256:" + digest, "subject": {"agent_id": "agent-7"},
                           "event": {"action_type": "tools/call", "timestamp": "2026-11-15T12:00:00Z"},
                           "policy": {"decision": "allow", "version": "p-1"}}).encode()
        out["overt_receipt.json"] = body
        if sign_receipt:
            out["overt_receipt.sig"] = base64.b64encode(key.sign(body, padding.PKCS1v15(), hashes.SHA256()))
    if pqc:
        pq = mldsa_key()
        out["signature_pqc.sig"] = base64.b64encode(pq.sign(canonical_bin))
        out["pqc_public_key.pem"] = spki_pem(pq.public_key())
    return out


def spki_pem(public) -> bytes:
    return public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def zip_bytes(items: dict[str, bytes] | list[tuple[str, bytes]]) -> bytes:
    buf = io.BytesIO()
    pairs = items.items() if isinstance(items, dict) else items
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in pairs:
            z.writestr(name, data)
    return buf.getvalue()


def authorities(pqc: bool = False) -> dict:
    keys = [spki(rsa_key().public_key())]
    if pqc:
        keys.append(mldsa_key().public_key().public_bytes_raw())
    return {"authority": pin(*keys), "tsa_authority": pin(spki(tsa()[1].public_key()))}
