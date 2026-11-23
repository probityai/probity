"""Write the dns_aid_sig/v1 test fixtures from the DNS-AID binding cases.

usage: python3 -I scripts/import-dns-aid-sig-cases.py <cases dir with pinned/ and new/> <outdir>

The input cases were signed by the publisher's own signer (dns-aid-core 825ccea, ``sign_record``)
with the expected verdict derived from the stated rule: twelve originals (``pinned/``) and eight
counter-examples (``new/``). Each becomes ``<outdir>/<case>/record.json`` and ``jwks.json`` (the
bytes a consumer would hold) plus one row in ``<outdir>/cases.json``: the consumer's instant, its
key authority (a pin of the zone owner's key, as raw-key SHA-256), the expected decision, and the
rule. One case is derived here: ``r3-noncanonical-signature-b64`` re-encodes a valid signature with
non-zero trailing bits, which every base64url decoder that ignores them reads as the same bytes.
"""
import base64
import datetime
import hashlib
import json
import os
import sys

src, out = sys.argv[1], sys.argv[2]
os.makedirs(out, exist_ok=True)
VERDICT = {"agrees": "supported", "contradicted": "contradicted", "cannot-tell": "not_established"}


def raw_key(jwk):
    pad = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    return b"\x04" + pad(jwk["x"]) + pad(jwk["y"])


def dump(path, value):
    with open(path, "wb") as handle:
        handle.write(json.dumps(value, indent=1, sort_keys=True).encode() + b"\n")


rows = []


def emit(name, c, source, sig=None):
    record = dict(c["record"])
    record["sig"] = sig if sig is not None else c["sig"]
    if "jwks_url" in c:
        record["jwks_url"] = c["jwks_url"]
    os.makedirs(os.path.join(out, name), exist_ok=True)
    dump(os.path.join(out, name, "record.json"), record)
    dump(os.path.join(out, name, "jwks.json"), c["jwks"])
    authority = None
    if "key_authority" in c:
        owner = c.get("zone_jwks", c["jwks"])["keys"]
        authority = {"kind": "pin", "keys": [{"public_key_sha256": hashlib.sha256(raw_key(k)).hexdigest()}
                                             for k in owner]}
    at = datetime.datetime.fromtimestamp(c["now"], datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    rows.append({"case": name, "source": source, "at": at, "key_authority": authority,
                 "expected": VERDICT[c["expected"]], "rule": c["rule"]})


for sub in ("pinned", "new"):
    for fname in sorted(os.listdir(os.path.join(src, sub))):
        with open(os.path.join(src, sub, fname)) as handle:
            case = json.load(handle)
        emit(case["case"], case, sub)

with open(os.path.join(src, "pinned", "full-coverage-valid.json")) as handle:
    base = json.load(handle)
head, body, sig = base["sig"].split(".")
raw = base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4))
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
odd = sig[:-1] + alphabet[alphabet.index(sig[-1]) ^ 1]
assert base64.urlsafe_b64decode(odd + "=" * (-len(odd) % 4)) == raw and odd != sig
base["expected"] = "contradicted"
base["rule"] = ("RFC 4648 section 3.5 and RFC 7515 section 2: the signature part is base64url with non-zero "
                "trailing bits; a lenient decoder reads the same 64 bytes and the signature verifies, so only "
                "canonical-form checking refuses it")
emit("r3-noncanonical-signature-b64", base, "derived", f"{head}.{body}.{odd}")
dump(os.path.join(out, "cases.json"), rows)
print(len(rows), "cases")
