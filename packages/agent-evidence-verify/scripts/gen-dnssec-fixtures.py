# /// script
# requires-python = ">=3.11"
# dependencies = ["dnspython==2.8.0", "cryptography>=50.0.0"]
# ///
"""Write the DNSSEC chain fixtures for dnssec_rrset/v1 and the dnssec-chain key authority.

usage: uv run scripts/gen-dnssec-fixtures.py <dns-aid-sig fixtures dir> <outdir>

The chains are signed by dnspython (``dns.dnssec.sign``), a second implementation that shares no
code with ``agent_evidence_verify.dnssec``, under a test root zone ``.`` whose DS the cases pin as
their trust anchor, then ``com.`` and ``example.com.``. Keys are Ed25519 from fixed seeds and the
signature windows are fixed, so the bytes are the same on every run. ``example.com.`` publishes the
SVCB RRset of the DNS-AID record and a TXT record ``key-sha256=<hex>`` at ``dns-aid.example.com.``
naming the zone owner's ES256 key from the dns-aid-sig fixtures. Each chain file is the records in
DNS wire format, uncompressed, one after another (RFC 9102 section 3).

Two chains hold attacks. ``tenant-delegated``: ``tenant.example.com.`` is a delegated child zone with
its own key, and its TXT at ``dns-aid.tenant.example.com.`` names the same ES256 key, so a check that
compares names alone would let the child vouch for the parent's records. ``revoked-key``: the
DNSKEY RRset of ``example.com.`` lists a second key with the REVOKE bit (RFC 5011), and the TXT is
signed by that key alone, as whoever kept the revoked key's private half would sign it.
"""
import base64
import hashlib
import json
import os
import sys

import dns.dnssec
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sig_dir, out = sys.argv[1], sys.argv[2]
os.makedirs(out, exist_ok=True)
INCEPTION, EXPIRATION = 1793318400, 1796083200  # 2026-10-30T00:00:00Z .. 2026-12-01T00:00:00Z
INSIDE, AFTER = "2026-11-15T12:00:00Z", "2026-12-02T00:00:00Z"
TTL = 3600


def key(label):
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"dnssec-fixture/" + label.encode()).digest())


def owner_key_sha256():
    with open(os.path.join(sig_dir, "ce1-owner-key-pinned-control", "jwks.json")) as handle:
        jwks = json.load(handle)
    k = jwks["keys"][0]
    raw = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    return hashlib.sha256(b"\x04" + raw(k["x"]) + raw(k["y"])).hexdigest()


ZONES = [".", "com.", "example.com."]
keys, dnskeys = {}, {}
for zone in ZONES:
    priv = key(zone)
    rd = dns.dnssec.make_dnskey(priv.public_key(), dns.dnssec.Algorithm.ED25519, flags=257)
    keys[zone] = (priv, rd)
    dnskeys[zone] = dns.rrset.from_rdata(zone, TTL, rd)


def sign(rrset, zone):
    priv, rd = keys[zone]
    sig = dns.dnssec.sign(rrset, priv, dns.name.from_text(zone), rd, inception=INCEPTION,
                          expiration=EXPIRATION, lifetime=None)
    return dns.rrset.from_rdata(rrset.name, rrset.ttl, sig)


def rr(name, rtype, *texts):
    return dns.rrset.from_text(name, TTL, "IN", rtype, *texts)


def wire(rrsets):
    data = b""
    for rs in rrsets:
        for rd in rs:
            body = rd.to_digestable()
            data += rs.name.to_wire() + int(rs.rdtype).to_bytes(2, "big") + int(rs.rdclass).to_bytes(2, "big") \
                + rs.ttl.to_bytes(4, "big") + len(body).to_bytes(2, "big") + body
    return data


ds = {z: dns.rrset.from_rdata(z, TTL, dns.dnssec.make_ds(z, keys[z][1], "SHA256")) for z in ZONES[1:]}
svcb = rr("_chat._a2a._agents.example.com.", "SVCB", '1 chat.example.com. alpn="a2a" port=443')
txt = rr("dns-aid.example.com.", "TXT", f'"key-sha256={owner_key_sha256()}"')
base = []
for zone in ZONES:
    base += [dnskeys[zone], sign(dnskeys[zone], zone)]
    if zone != ".":
        parent = "." if zone == "com." else "com."
        base += [ds[zone], sign(ds[zone], parent)]
data = [svcb, sign(svcb, "example.com."), txt, sign(txt, "example.com.")]
root_ds = dns.dnssec.make_ds(".", keys["."][1], "SHA256").to_text()
wrong_ds = root_ds[:-4] + ("0000" if not root_ds.endswith("0000") else "1111")

chains = {"valid": base + data}
tenant_priv = key("tenant.example.com.")
tenant_rd = dns.dnssec.make_dnskey(tenant_priv.public_key(), dns.dnssec.Algorithm.ED25519, flags=257)
keys["tenant.example.com."] = (tenant_priv, tenant_rd)
tenant_dnskey = dns.rrset.from_rdata("tenant.example.com.", TTL, tenant_rd)
tenant_ds = dns.rrset.from_rdata("tenant.example.com.", TTL,
                                 dns.dnssec.make_ds("tenant.example.com.", tenant_rd, "SHA256"))
tenant_txt = rr("dns-aid.tenant.example.com.", "TXT", f'"key-sha256={owner_key_sha256()}"')
chains["tenant-delegated"] = base + data + [tenant_ds, sign(tenant_ds, "example.com."), tenant_dnskey,
                                            sign(tenant_dnskey, "tenant.example.com."), tenant_txt,
                                            sign(tenant_txt, "tenant.example.com.")]
revoked_priv = key("example.com./revoked")
revoked_rd = dns.dnssec.make_dnskey(revoked_priv.public_key(), dns.dnssec.Algorithm.ED25519,
                                    flags=257 | 0x80)
two_keys = dns.rrset.from_rdata("example.com.", TTL, keys["example.com."][1], revoked_rd)
revoked_sig = dns.rrset.from_rdata(txt.name, txt.ttl, dns.dnssec.sign(
    txt, revoked_priv, dns.name.from_text("example.com."), revoked_rd, inception=INCEPTION,
    expiration=EXPIRATION, lifetime=None))
chains["revoked-key"] = [r for r in base if r.name != dns.name.from_text("example.com.")
                         or r.rdtype not in (dns.rdatatype.DNSKEY, dns.rdatatype.RRSIG)
                         or (r.rdtype == dns.rdatatype.RRSIG and r[0].type_covered != dns.rdatatype.DNSKEY)] + [
    two_keys, sign(two_keys, "example.com."), txt, revoked_sig]
flipped = bytearray(wire([sign(svcb, "example.com.")]))
flipped[-3] ^= 0x01
chains["svcb-rrsig-bitflip"] = None  # written from bytes below
chains["missing-ds"] = [r for r in base if not (r.name == dns.name.from_text("example.com.")
                                                 and r.rdtype in (dns.rdatatype.DS, dns.rdatatype.RRSIG)
                                                 and (r.rdtype == dns.rdatatype.DS or r[0].type_covered == dns.rdatatype.DS))] + data
chains["missing-rrsig"] = base + [svcb, txt, sign(txt, "example.com.")]
blobs = {name: wire(value) for name, value in chains.items() if value is not None}
blobs["svcb-rrsig-bitflip"] = wire(base + [svcb]) + bytes(flipped) + wire([txt, sign(txt, "example.com.")])
for name, blob in blobs.items():
    with open(os.path.join(out, name + ".chain"), "wb") as handle:
        handle.write(blob)

S, T = "_chat._a2a._agents.example.com.", "dns-aid.example.com."
anchor = {"zone": ".", "ds": [root_ds]}
cases = [
    ("svcb-validated", "valid", S, "SVCB", anchor, INSIDE, "supported", "rrset_validated"),
    ("txt-validated", "valid", T, "TXT", anchor, INSIDE, "supported", "rrset_validated"),
    ("svcb-expired", "valid", S, "SVCB", anchor, AFTER, "contradicted", "rrsig_expired"),
    ("svcb-before-inception", "valid", S, "SVCB", anchor, "2026-10-29T00:00:00Z", "contradicted",
     "rrsig_not_yet_valid"),
    ("svcb-wrong-anchor-ds", "valid", S, "SVCB", {"zone": ".", "ds": [wrong_ds]}, INSIDE, "contradicted",
     "ds_mismatch"),
    ("svcb-rrsig-bitflip", "svcb-rrsig-bitflip", S, "SVCB", anchor, INSIDE, "contradicted", "signature_invalid"),
    ("svcb-missing-ds", "missing-ds", S, "SVCB", anchor, INSIDE, "not_established", "ds_missing"),
    ("svcb-missing-rrsig", "missing-rrsig", S, "SVCB", anchor, INSIDE, "not_established", "rrsig_missing"),
    ("svcb-not-in-chain", "valid", "_mcp._mcp._agents.example.com.", "SVCB", anchor, INSIDE, "not_established",
     "rrset_missing"),
    ("tenant-txt-validated", "tenant-delegated", "dns-aid.tenant.example.com.", "TXT", anchor, INSIDE,
     "supported", "rrset_validated"),
    ("txt-signed-by-revoked-key", "revoked-key", T, "TXT", anchor, INSIDE, "contradicted",
     "rrsig_key_not_trusted"),
]
rows = [{"case": c, "chain": f + ".chain", "name": n, "type": t, "trust_anchor": a, "at": at,
         "expected": e, "reason": r} for c, f, n, t, a, at, e, r in cases]
with open(os.path.join(out, "cases.json"), "w") as handle:
    json.dump({"generator": "scripts/gen-dnssec-fixtures.py (dnspython 2.8.0)", "cases": rows,
               "chains": {n + ".chain": hashlib.sha256(b).hexdigest() for n, b in sorted(blobs.items())}},
              handle, indent=1, sort_keys=True)
    handle.write("\n")
print(len(rows), "cases,", len(blobs), "chains")
