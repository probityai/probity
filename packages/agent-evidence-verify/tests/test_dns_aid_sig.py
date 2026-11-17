"""``dns_aid_sig/v1`` on the DNS-AID binding cases, signed by the publisher's own signer.

tests/data/dns-aid-sig holds twelve original cases and eight counter-examples signed by dns-aid-core
825ccea (``sign_record``), plus one derived non-canonical base64url case, imported by
scripts/import-dns-aid-sig-cases.py. Each case pins the expected decision; the policy pins the zone
owner's key (or no authority, where the case says the key is unattested).
"""

import hashlib
import json
from pathlib import Path

import pytest
from agent_evidence_verify import adjudicate
from agent_evidence_verify.adapters import dns_aid_sig
from agent_evidence_verify.common import CaseError

DATA = Path(__file__).parent / "data" / "dns-aid-sig"
CASES = json.loads((DATA / "cases.json").read_text(encoding="utf-8"))
OWNER = "ce1-owner-key-pinned-control"
DNSSEC = Path(__file__).parent / "data" / "dnssec"


def _meta(body: bytes, name: str) -> dict:
    return {"path": name, "sha256": hashlib.sha256(body).hexdigest(), "length": len(body)}


def run(tmp_path: Path, record: bytes, jwks: bytes, at: str, authority=None, extra=None) -> dict:
    files = {"record.json": record, "jwks.json": jwks, **(extra or {})}
    for name, body in files.items():
        (tmp_path / name).write_bytes(body)
    assessment = {"claim_type": "dns_aid_sig/v1", "record": "record.json", "jwks": "jwks.json", "at": at}
    if authority is not None:
        assessment["key_authority"] = authority
    case = {"schema_version": "probity-case/v1", "case_id": "c",
            "artifacts": {name: _meta(body, name) for name, body in files.items()}}
    policy = {"schema_version": "probity-policy/v1", "assessments": {"c": assessment}}
    return adjudicate(case, policy, tmp_path)


def files(name: str) -> tuple[bytes, bytes]:
    return (DATA / name / "record.json").read_bytes(), (DATA / name / "jwks.json").read_bytes()


@pytest.mark.parametrize("row", CASES, ids=lambda r: r["case"])
def test_every_case_reaches_its_expected_decision(tmp_path, row):
    record, jwks = files(row["case"])
    result = run(tmp_path, record, jwks, row["at"], row["key_authority"])
    assert result["decision"] == row["expected"], (row["rule"], result["reason"])
    assert result["scope"]["profile"] == dns_aid_sig.PROFILE
    assert len(result["scope"]["jwks_key_set_sha256"]) == 64


def test_the_counts_the_row_10_break_names():
    originals = [r for r in CASES if r["source"] == "pinned"]
    new = [r for r in CASES if r["source"] == "new"]
    assert (len(originals), len(new)) == (12, 8)


def test_a_verdict_names_the_key_set_it_read_and_the_authority_its_keys(tmp_path):
    row = next(r for r in CASES if r["case"] == OWNER)
    result = run(tmp_path, *files(OWNER), row["at"], row["key_authority"])
    assert result["decision"] == "supported" and result["reason"] == "binding_verified"
    authority = next(c for c in result["checks"] if c["id"] == "key_authority")
    pinned = row["key_authority"]["keys"][0]["public_key_sha256"]
    assert authority["key_set_sha256"] == hashlib.sha256((pinned + "\n").encode()).hexdigest()
    assert result["scope"]["signature_coverage"]["value"] == "full"
    assert result["scope"]["signing_key_sha256"] == pinned


def _with_sig(record: bytes, sig: str) -> bytes:
    value = json.loads(record)
    value["sig"] = sig
    return json.dumps(value).encode()


def _b64(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


@pytest.mark.parametrize("sig", ["", "..", "a.b.c", "a..", "e30.e30.", "e30.e30." + "A" * 86,
                                 _b64(b'{"alg":"ES256","crit":["x"],"x":1}') + ".e30." + "A" * 86,
                                 _b64(b"[1]") + ".e30.AAAA", _b64(b'{"alg":"ES256"}') + ".bm90IGpzb24." + "A" * 86])
def test_malformed_signatures_get_a_verdict_never_an_exception(tmp_path, sig):
    record, jwks = files(OWNER)
    result = run(tmp_path, _with_sig(record, sig), jwks, "2026-11-15T20:47:35Z")
    assert result["decision"] == "contradicted"


@pytest.mark.parametrize("jwks", [b"", b"{}", b'{"keys":[]}', b'{"keys":[{"kty":"OKP","crv":"Ed25519","x":"AA"}]}',
                                  b'{"keys":[{"kty":"EC","crv":"P-256","x":"!","y":"?"}]}', b'{"keys":[1,2]}',
                                  b'{"keys":[{"kty":["EC"]}]}', b"[" * 200 + b"]" * 200])
def test_unusable_jwks_is_not_established_never_an_exception(tmp_path, jwks):
    record, _ = files(OWNER)
    result = run(tmp_path, record, jwks, "2026-11-15T20:47:35Z")
    assert result["decision"] == "not_established"
    assert len(result["scope"]["jwks_key_set_sha256"]) == 64


@pytest.mark.parametrize("record", [b"", b"[]", b'{"a":1,"a":2}', b'{"fqdn":"x"}', b"\xff"])
def test_malformed_records_are_contradicted(tmp_path, record):
    _, jwks = files(OWNER)
    assert run(tmp_path, record, jwks, "2026-11-15T20:47:35Z")["decision"] == "contradicted"


def test_the_consumer_policy_is_still_a_case_error(tmp_path):
    record, jwks = files(OWNER)
    with pytest.raises(CaseError):
        run(tmp_path, record, jwks, "2026-11-15T20:47:35Z", {"kind": "trust-me"})
    with pytest.raises(CaseError):
        run(tmp_path, record, jwks, "yesterday")


def test_the_dnssec_chain_authority_reads_the_zone_owner_key(tmp_path):
    chain = (DNSSEC / "valid.chain").read_bytes()
    anchor = json.loads((DNSSEC / "cases.json").read_text())["cases"][0]["trust_anchor"]
    authority = {"kind": "dnssec-chain", "trust_anchor": anchor, "name": "dns-aid.example.com.",
                 "chain": "dnssec.chain"}
    at = next(r["at"] for r in CASES if r["case"] == OWNER)
    owner = run(tmp_path, *files(OWNER), at, authority, {"dnssec.chain": chain})
    assert (owner["decision"], owner["reason"]) == ("supported", "binding_verified")
    assert owner["scope"]["key_authority_chain"]["status"] == "bound"
    foreign = run(tmp_path, *files("ce1-foreign-key-pinned-owner"), at, authority, {"dnssec.chain": chain})
    assert (foreign["decision"], foreign["reason"]) == ("contradicted", "key_not_in_dnssec_record")
    outside = dict(authority, name="dns-aid.example.net.")
    assert run(tmp_path, *files(OWNER), at, outside, {"dnssec.chain": chain})["reason"] == \
        "key_record_outside_subject"


def test_a_delegated_child_zone_never_vouches_for_its_parent(tmp_path):
    # tenant.example.com. is a delegated zone with its own key; its TXT names the same ES256 key.
    # Comparing names alone, the TXT owner is inside example.com, so the child's key spoke for a
    # record of example.com and of com; the zone that signed the TXT must contain the record's zone.
    from agent_evidence_verify.key_authority import authorize, jwk_key_bytes
    chain = (DNSSEC / "tenant-delegated.chain").read_bytes()
    anchor = json.loads((DNSSEC / "cases.json").read_text())["cases"][0]["trust_anchor"]
    authority = {"kind": "dnssec-chain", "trust_anchor": anchor, "name": "dns-aid.tenant.example.com.",
                 "chain": "dnssec.chain"}
    at = next(r["at"] for r in CASES if r["case"] == OWNER)
    parent = run(tmp_path, *files(OWNER), at, authority, {"dnssec.chain": chain})
    assert (parent["decision"], parent["reason"]) == ("contradicted", "key_record_signed_by_another_zone")
    assert parent["scope"]["zone"] == "example.com"
    key = jwk_key_bytes(json.loads(files(OWNER)[1])["keys"][0], "jwks")
    instant = dns_aid_sig.instant(at, "at")
    config = {k: v for k, v in authority.items() if k != "chain"}
    assert authorize(config, key, subject="tenant.example.com", at=instant, dnssec_chain=chain).outcome == "authorized"
    for subject in ("example.com", "com"):
        answer = authorize(config, key, subject=subject, at=instant, dnssec_chain=chain)
        assert (answer.outcome, answer.reason) == ("unauthorized", "key_record_signed_by_another_zone")


def test_a_revoked_dnskey_never_authorises_a_key(tmp_path):
    chain = (DNSSEC / "revoked-key.chain").read_bytes()
    anchor = json.loads((DNSSEC / "cases.json").read_text())["cases"][0]["trust_anchor"]
    authority = {"kind": "dnssec-chain", "trust_anchor": anchor, "name": "dns-aid.example.com.",
                 "chain": "dnssec.chain"}
    at = next(r["at"] for r in CASES if r["case"] == OWNER)
    result = run(tmp_path, *files(OWNER), at, authority, {"dnssec.chain": chain})
    assert (result["decision"], result["reason"]) == ("contradicted", "dnssec_rrsig_key_not_trusted")


@pytest.mark.parametrize("url,reason", [
    ("https://[", "jwks_url_malformed"),  # urlsplit raised ValueError out of judge
    ("https://evil.example.net\\@dns-aid.example.com/k", "jwks_url_malformed"),  # urllib3 fetches evil
    ("https://user@dns-aid.example.com/k", "jwks_url_malformed"),
    ("https://dns-aid.example.com:99999/k", "jwks_url_malformed"),
    ("https://dns-aid.example%2Ecom/k", "jwks_url_malformed"),
    ("https://evil.example.net/k", "jwks_host_not_zone"),
    ("http://dns-aid.example.com/k", "jwks_host_not_zone"),
])
def test_a_jwks_url_is_read_as_every_client_reads_it(tmp_path, url, reason):
    record, jwks = files(OWNER)
    served = dict(json.loads(record), jwks_url=url)
    at = next(r["at"] for r in CASES if r["case"] == OWNER)
    pin = next(r["key_authority"] for r in CASES if r["case"] == OWNER)
    result = run(tmp_path, json.dumps(served).encode(), jwks, at, pin)
    assert (result["decision"], result["reason"]) == ("contradicted", reason)
    ok = run(tmp_path, json.dumps(dict(served, jwks_url="https://dns-aid.example.com/k")).encode(), jwks, at, pin)
    assert ok["decision"] == "supported"


def _own_record(port=443, iat=1794775595, exp=1794862055, record_port=None):
    from cryptography.hazmat.primitives.asymmetric import ec
    key = ec.derive_private_key(11, ec.SECP256R1())
    numbers = key.public_key().public_numbers()
    point = b"\x04" + numbers.x.to_bytes(32, "big") + numbers.y.to_bytes(32, "big")
    jwks = json.dumps({"keys": [{"kty": "EC", "crv": "P-256", "kid": "k", "x": _b64(point[1:33]),
                                 "y": _b64(point[33:])}]}).encode()
    params = {"cap": "https://a.example.com/cap.json"}
    payload = {"fqdn": "a.example.com", "target": "a.example.com", "port": port, "alpn": "a2a",
               "iat": iat, "exp": exp, "svcb": dns_aid_sig.svcb1(params)}
    record = json.dumps({"fqdn": "a.example.com", "target": "a.example.com",
                         "port": port if record_port is None else record_port, "alpn": "a2a",
                         "zone": "example.com", "params": params,
                         "sig": _signed({"alg": "ES256", "kid": "k"}, payload, key)}).encode()
    return record, jwks, {"kind": "pin", "keys": [{"public_key_sha256": hashlib.sha256(point).hexdigest()}]}


@pytest.mark.parametrize("changes,reason", [({"port": 70000}, "record_malformed"), ({"port": -1}, "record_malformed"),
                                            ({"iat": 1794775595, "exp": 1794775595}, "payload_window_inverted"),
                                            ({"iat": 1794775900, "exp": 1794775800}, "payload_window_inverted")])
def test_a_signed_impossible_port_or_inverted_window_is_refused(tmp_path, changes, reason):
    record, jwks, pin = _own_record(**changes)
    result = run(tmp_path, record, jwks, "2026-11-15T21:00:00Z", pin)
    assert (result["decision"], result["reason"]) == ("contradicted", reason)
    control = run(tmp_path, *_own_record()[:2], "2026-11-15T21:00:00Z", _own_record()[2])
    assert (control["decision"], control["scope"]["fqdn"], control["scope"]["zone"]) == \
        ("supported", "a.example.com", "example.com")


def test_the_reader_imports_no_dns_aid_or_dns_library():
    source = Path(dns_aid_sig.__file__).read_text(encoding="utf-8")
    for module in ("dns_aid", "dns."):
        assert f"import {module}" not in source and f"from {module}" not in source


def test_svcb1_is_the_publisher_digest_over_rfc8785():
    params = {"cap": "u", "realm": "t", "policy": None}
    import base64
    expected = base64.urlsafe_b64encode(hashlib.sha256(
        b'svcb1:{"cap":"u","realm":"t"}').digest()).rstrip(b"=").decode()
    assert dns_aid_sig.svcb1(params) == expected
    assert dns_aid_sig.svcb1({"cap": "u\nrealm=t"}) != expected


def _signed(header: dict, payload: dict, key) -> str:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    signing_input = f"{_b64(json.dumps(header).encode())}.{_b64(json.dumps(payload).encode())}"
    r, s = decode_dss_signature(key.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256())))
    return f"{signing_input}.{_b64(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


@pytest.mark.parametrize("alg,expected", [("ES256", "supported"), ("ES512", "contradicted"),
                                          ("HS256", "contradicted")])
def test_only_es256_is_read_even_when_an_es256_signature_verifies(tmp_path, alg, expected):
    from cryptography.hazmat.primitives.asymmetric import ec
    key = ec.derive_private_key(7, ec.SECP256R1())
    numbers = key.public_key().public_numbers()
    point = b"\x04" + numbers.x.to_bytes(32, "big") + numbers.y.to_bytes(32, "big")
    jwks = json.dumps({"keys": [{"kty": "EC", "crv": "P-256", "kid": "k", "x": _b64(point[1:33]),
                                 "y": _b64(point[33:])}]}).encode()
    params = {"cap": "https://a.example.com/cap.json"}
    payload = {"fqdn": "a.example.com", "target": "a.example.com", "port": 443, "alpn": "a2a",
               "iat": 1794775595, "exp": 1794862055, "svcb": dns_aid_sig.svcb1(params)}
    record = json.dumps({"fqdn": "a.example.com", "target": "a.example.com", "port": 443, "alpn": "a2a",
                         "zone": "example.com", "params": params,
                         "sig": _signed({"alg": alg, "kid": "k"}, payload, key)}).encode()
    pin = {"kind": "pin", "keys": [{"public_key_sha256": hashlib.sha256(point).hexdigest()}]}
    result = run(tmp_path, record, jwks, "2026-11-15T21:00:00Z", pin)
    assert result["decision"] == expected
    if expected == "contradicted":
        assert result["reason"] == "jws_alg_not_es256"
