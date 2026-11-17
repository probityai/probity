"""``dnssec_rrset/v1`` and the DNSSEC validator, on chains a second implementation signed.

tests/data/dnssec: a test root, ``com.`` and ``example.com.`` signed by dnspython 2.8.0
(scripts/gen-dnssec-fixtures.py), with mutations. tests/data/dnssec-real: the HTTPS RRset of
cloudflare.com and its chain from the IANA root, captured 2026-11-17 and validated by delv then.
"""

import hashlib
import json
from pathlib import Path

import pytest
from agent_evidence_verify import adjudicate, dnssec
from agent_evidence_verify.common import CaseError

DATA = Path(__file__).parent / "data"


def rows():
    out = []
    for folder in ("dnssec", "dnssec-real"):
        meta = json.loads((DATA / folder / "cases.json").read_text(encoding="utf-8"))
        for chain, digest in meta["chains"].items():
            assert hashlib.sha256((DATA / folder / chain).read_bytes()).hexdigest() == digest
        for case in meta["cases"]:
            out.append((folder, case.get("trust_anchor") or meta["trust_anchor"], case))
    return out


def run(tmp_path, chain: bytes | None, name, rtype, anchor, at):
    artifacts = {}
    if chain is not None:
        (tmp_path / "chain.bin").write_bytes(chain)
    artifacts["chain.bin"] = {"path": "chain.bin", "sha256": hashlib.sha256(chain or b"").hexdigest(),
                              "length": len(chain or b"")}
    case = {"schema_version": "probity-case/v1", "case_id": "c", "artifacts": artifacts}
    policy = {"schema_version": "probity-policy/v1", "assessments": {"c": {
        "claim_type": "dnssec_rrset/v1", "chain": "chain.bin", "name": name, "type": rtype,
        "trust_anchor": anchor, "at": at}}}
    return adjudicate(case, policy, tmp_path)


@pytest.mark.parametrize("folder,anchor,case", [pytest.param(*r, id=r[2]["case"]) for r in rows()])
def test_every_chain_case_reaches_its_decision_and_reason(tmp_path, folder, anchor, case):
    chain = (DATA / folder / case["chain"]).read_bytes()
    result = run(tmp_path, chain, case["name"], case["type"], anchor, case["at"])
    assert (result["decision"], result["reason"]) == (case["expected"], case["reason"])


def test_a_missing_chain_is_never_validated(tmp_path):
    meta = json.loads((DATA / "dnssec" / "cases.json").read_text())
    case = meta["cases"][0]
    result = run(tmp_path, None, case["name"], case["type"], case["trust_anchor"], case["at"])
    assert (result["decision"], result["reason"]) == ("not_established", "chain_unavailable")


@pytest.mark.parametrize("chain", [b"\x00", b"\xc0\x0c" + b"\x00" * 10, b"\x03com\x00\x00\x40", b"\x40" + b"a" * 64])
def test_malformed_chain_bytes_are_contradicted(tmp_path, chain):
    meta = json.loads((DATA / "dnssec" / "cases.json").read_text())
    case = meta["cases"][0]
    result = run(tmp_path, chain, case["name"], case["type"], case["trust_anchor"], case["at"])
    assert result["decision"] in ("contradicted", "not_established")


@pytest.mark.parametrize("anchor", [{"zone": "."}, {"zone": ".", "ds": []}, {"zone": ".", "ds": ["1 2 3"]},
                                    {"zone": "..", "ds": ["1 8 2 00"]}])
def test_a_malformed_trust_anchor_is_a_case_error(tmp_path, anchor):
    with pytest.raises(CaseError):
        run(tmp_path, b"", "example.com.", "SVCB", anchor, "2026-11-15T12:00:00Z")


def test_key_tag_matches_rfc4034_appendix_b_on_the_root_ksk():
    chain = (DATA / "dnssec-real" / "cloudflare.com-HTTPS.chain").read_bytes()
    tags = {dnssec.key_tag(r.rdata) for r in dnssec.parse_chain(chain)
            if r.rtype == dnssec.TYPES["DNSKEY"] and r.owner == ()}
    assert 20326 in tags


def test_serial_arithmetic_crosses_the_32_bit_wrap():
    assert dnssec._serial_le(2**32 - 10, 5) and not dnssec._serial_le(5, 2**32 - 10)
