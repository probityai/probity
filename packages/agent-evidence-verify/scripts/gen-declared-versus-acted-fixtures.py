# /// script
# requires-python = ">=3.11"
# dependencies = ["cryptography>=50.0.0", "rfc8785==0.1.4"]
# ///
"""Write the declared_versus_acted/v1 fixtures with agent-evidence-observer's own recorder.

usage: uv run scripts/gen-declared-versus-acted-fixtures.py <observer src dir> <tests/data dir>

The trajectories are written by ``probity_observer.resolution.ResolutionObserver`` (the recorder the
adapter joins, a second implementation of the trajectory format) and closed with a witness key from a
fixed seed, so the bytes are the same on every run. The discovery answers are the DNS-AID records of
the dns-aid-sig fixtures (signed by the publisher's own signer), served as SVCB presentation records;
the JWKS and DNSSEC chain are those fixtures' bytes, bound by digest in each resolution event.
"""
import hashlib
import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[1])
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from probity_observer.crypto import SigningKey
from probity_observer.resolution import ResolutionObserver

data = Path(sys.argv[2])
out = data / "declared-versus-acted"
shutil.rmtree(out, ignore_errors=True)
out.mkdir(parents=True)
witness = SigningKey(Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"dva-fixture/witness").digest()))
JWKS_URL = "https://dns-aid.example.com/.well-known/dns-aid-jwks.json"
NAMES = {"cap": 65400, "cap-sha256": 65401, "bap": 65402, "policy": 65403, "realm": 65404,
         "connect-class": 65406, "connect-meta": 65407, "enroll-uri": 65408, "well-known": 65409}


def svcb(source):
    record = json.loads((data / "dns-aid-sig" / source / "record.json").read_text())
    params = "".join(f' key{NAMES[k]}="{v}"' for k, v in sorted(record["params"].items()) if v is not None)
    return (f'1 {record["target"]}. alpn="{record["alpn"]}" port={record["port"]}{params} '
            f'key65405="{record["sig"]}"'), record["fqdn"], record["sig"]


def jwks(source):
    return (data / "dns-aid-sig" / source / "jwks.json").read_bytes()


CHAIN = (data / "dnssec" / "valid.chain").read_bytes()
OWNER = "ce1-owner-key-pinned-control"
cases = []


def scenario(name, source, calls, expected, reason, authority="pin", chain=False, drop_tail=False):
    folder = out / name
    folder.mkdir()
    observer = ResolutionObserver(folder / "trajectory.jsonl", trajectory_id=f"dva-{name}")
    record, fqdn, sig = svcb(source)
    seq = observer.resolved(name=fqdn, svcb=[record], at="2026-11-15T20:59:00Z", sig=sig, jwks_url=JWKS_URL,
                            jwks_bytes=jwks(source), dnssec_chain=CHAIN if chain else None)
    for endpoint, at, relies in calls:
        observer.called(endpoint=endpoint, at=at, resolution=seq if relies else None)
    head = observer.trajectory.close(witness)
    (folder / "head.json").write_text(json.dumps(head, indent=1, sort_keys=True) + "\n")
    if drop_tail:
        lines = (folder / "trajectory.jsonl").read_bytes().splitlines(keepends=True)
        (folder / "trajectory.jsonl").write_bytes(b"".join(lines[:-1]))
    shutil.copy(data / "dns-aid-sig" / source / "jwks.json", folder / "jwks.json")
    evidence = ["jwks.json"]
    if chain:
        shutil.copy(data / "dnssec" / "valid.chain", folder / "dnssec.chain")
        evidence.append("dnssec.chain")
    pins = json.loads((data / "dns-aid-sig" / "cases.json").read_text())
    pin = next(r["key_authority"] for r in pins if r["case"] == source and r["key_authority"])
    dnssec_cases = json.loads((data / "dnssec" / "cases.json").read_text())["cases"]
    anchor = dnssec_cases[0]["trust_anchor"]
    key_authority = {"pin": pin, "none": None,
                     "dnssec-chain": {"kind": "dnssec-chain", "trust_anchor": anchor,
                                      "name": "dns-aid.example.com."}}[authority]
    cases.append({"case": name, "trajectory_id": f"dva-{name}", "witness_key": witness.public_hex,
                  "zone": "example.com", "key_authority": key_authority, "evidence": evidence,
                  "expected": expected, "reason": reason})


IN, LATE = "2026-11-15T21:00:00Z", "2026-11-17T00:00:00Z"
scenario("all-calls-bound", OWNER, [("https://chat.example.com/a2a", IN, True),
                                    ("chat.example.com:443", IN, False)], "supported", "every_call_declared_and_bound")
scenario("planted-undeclared-call", OWNER, [("https://chat.example.com/a2a", IN, True),
                                            ("https://collector.example.net/a2a", IN, False)],
         "contradicted", "call_not_declared")
scenario("call-to-another-port", OWNER, [("https://chat.example.com:8443/a2a", IN, True)],
         "contradicted", "call_not_declared")
scenario("call-after-exp", OWNER, [("https://chat.example.com/a2a", LATE, True)], "contradicted",
         "binding_expired")
scenario("no-calls", OWNER, [], "not_established", "no_calls_recorded")
scenario("endpoint-only-binding", "endpoint-only", [("https://chat.example.com/a2a", "2026-11-15T20:20:00Z", True)],
         "not_established", "endpoint_only")
scenario("no-key-authority", OWNER, [("https://chat.example.com/a2a", IN, True)], "not_established",
         "no_key_authority_in_policy", authority="none")
scenario("tail-dropped", OWNER, [("https://chat.example.com/a2a", IN, True),
                                 ("https://collector.example.net/a2a", IN, False)],
         "contradicted", "trajectory_tail_missing", drop_tail=True)
scenario("dnssec-key-authority", OWNER, [("https://chat.example.com/a2a", IN, True)], "supported",
         "every_call_declared_and_bound", authority="dnssec-chain", chain=True)
scenario("foreign-key-dnssec-authority", "ce1-foreign-key-pinned-owner",
         [("https://chat.example.com/a2a", IN, True)], "contradicted", "key_not_in_dnssec_record",
         authority="dnssec-chain", chain=True)
(out / "cases.json").write_text(json.dumps(cases, indent=1, sort_keys=True) + "\n")
print(len(cases), "scenarios")
