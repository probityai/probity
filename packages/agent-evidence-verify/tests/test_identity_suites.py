"""The payment-mandate and status-receipt-binding suites in corpus mode.

Every member is answered with the decision and the reason the corpus declares, so the Action's
reference stage reads 36 of 36 and 24 of 24 for the two suites.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from agent_evidence_verify import corpus
from agent_evidence_verify.cli import main

DATA = Path(__file__).resolve().parent / "data"
VERDICT = {"accepted": "accept", "rejected": "reject", "accept": "accept", "reject": "reject"}
SUITES = {"payment-mandate": ("agent-payment-mandate/v1", 36),
          "status-receipt-binding": ("status-receipt-binding/v1", 24)}


def _printed(capsys) -> list[dict]:
    return [json.loads(text) for text in capsys.readouterr().out.splitlines()]


@pytest.mark.parametrize("name", sorted(SUITES))
def test_every_member_answered_as_the_corpus_declares(name: str, capsys) -> None:
    suite, count = SUITES[name]
    root = DATA / name
    manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    assert manifest["suite"] == suite and len(manifest["vectors"]) == count
    assert main(["corpus", str(root)]) == 0
    printed = _printed(capsys)
    assert [line["vector"] for line in printed] == [e["id"] for e in manifest["vectors"]]
    wrong = [(e["id"], line["verdict"], line["reason"], e["expected"])
             for line, e in zip(printed, manifest["vectors"], strict=True)
             if (line["verdict"], line["reason"])
             != (VERDICT[e["expected"]["decision"]], e["expected"]["reason"])]
    assert wrong == []
    assert all(line["corpusDigest"] == manifest["corpusDigest"] for line in printed)
    assert all(line["schema"] == corpus.SCHEMA_ID for line in printed)


# Adversarial cases: each edits an accepted member and must fail closed with the named reason.

PM = DATA / "payment-mandate" / "cases" / "x402-exact-evm-settled-once" / "case.json"
SR = DATA / "status-receipt-binding" / "cases" / "accept-bound"


def _edited(src: Path, tmp_path: Path, edit) -> Path:
    record = json.loads(src.read_text(encoding="utf-8"))
    edit(record)
    out = tmp_path / "case.json"
    out.write_text(json.dumps(record), encoding="utf-8")
    return out


def _x(record: dict) -> dict:
    return record["credential"]["facilitator_request"]


def _flip_signature(record: dict) -> None:
    signature = _x(record)["paymentPayload"]["payload"]["signature"]
    _x(record)["paymentPayload"]["payload"]["signature"] = signature[:10] + (
        "0" if signature[10] != "0" else "1") + signature[11:]


def _payment_edits():
    def other_domain(r: dict) -> None:
        _x(r)["paymentRequirements"]["extra"]["version"] = "3"

    def scheme_dropped(r: dict) -> None:
        r["scheme"] = "unknown-scheme"

    def short_signature(r: dict) -> None:
        _x(r)["paymentPayload"]["payload"]["signature"] = "0x" + "11" * 64

    def amount_raised(r: dict) -> None:
        _x(r)["paymentPayload"]["payload"]["authorization"]["value"] = "10001"

    return [("a flipped signature byte recovers another signer", _flip_signature,
             "payer_not_authorization_signer"),
            ("a token domain the payer did not sign under", other_domain,
             "payer_not_authorization_signer"),
            ("a signature of the wrong length", short_signature, "signature_not_canonical"),
            ("an authorization value raised after signing", amount_raised,
             "amount_not_offer_amount")]


@pytest.mark.parametrize(("label", "edit", "reason"), _payment_edits(),
                         ids=[e[0] for e in _payment_edits()])
def test_payment_edits_fail_closed(label: str, edit, reason: str, tmp_path: Path) -> None:
    from agent_evidence_verify.adapters import payment_mandate
    record = json.loads(PM.read_text(encoding="utf-8"))
    assert payment_mandate.decide(record) == ("accepted", "mandate_chain_holds")
    edit(record)
    assert payment_mandate.decide(record) == ("rejected", reason), label


def test_an_unknown_scheme_is_never_accepted(tmp_path: Path) -> None:
    from agent_evidence_verify.adapters import payment_mandate
    path = _edited(PM, tmp_path, lambda r: r.update(scheme="unknown-scheme"))
    decision, _ = payment_mandate.judge(path)
    assert decision == "rejected"


def test_a_repeated_member_is_refused_not_read_as_the_last_copy(tmp_path: Path, capsys) -> None:
    text = PM.read_text(encoding="utf-8")
    twin = tmp_path / "dup"
    (twin / "cases" / "dup").mkdir(parents=True)
    (twin / "cases" / "dup" / "case.json").write_text(
        text.replace("{", '{"scheme": "x", "scheme": "x402-exact-evm-eip3009",', 1),
        encoding="utf-8")
    manifest = {"suite": "agent-payment-mandate/v1", "corpusDigest": "a" * 64,
                "vectors": [{"id": "dup", "path": "cases/dup"}]}
    (twin / "MANIFEST.json").write_text(json.dumps(manifest), encoding="utf-8")
    assert main(["corpus", str(twin)]) == 0
    (line,) = _printed(capsys)
    assert line["verdict"] == "error" and line["verdict"] != "accept"


def _receipt_case(tmp_path: Path, edit) -> Path:
    base = tmp_path / "case"
    base.mkdir()
    for name in ("case.json", "credential.json", "receipt.json"):
        (base / name).write_bytes((SR / name).read_bytes())
    edit(base)
    return base / "case.json"


def _rewrite(base: Path, name: str, change) -> None:
    doc = json.loads((base / name).read_text(encoding="utf-8"))
    change(doc)
    (base / name).write_text(json.dumps(doc), encoding="utf-8")


def _flip_sig(doc: dict) -> None:
    sig = doc["signatures"][0]["sig"]
    doc["signatures"][0]["sig"] = ("B" if sig[0] != "B" else "C") + sig[1:]


def _wrong_authority(base: Path) -> None:
    _rewrite(base, "case.json", lambda d: d.update(authorityKey="A" * 43 + "="))


def _unpadded_sig(base: Path) -> None:
    _rewrite(base, "receipt.json",
             lambda d: d["signatures"][0].update(sig=d["signatures"][0]["sig"].rstrip("=")))


def _receipt_edits():
    return [
        ("a flipped receipt signature", lambda b: _rewrite(b, "receipt.json", _flip_sig),
         "receipt_signature_invalid"),
        ("an authority key that is not the signer", _wrong_authority, "receipt_signature_invalid"),
        ("a signature spelled non-canonically", _unpadded_sig, "receipt_malformed"),
        ("a flipped credential signature",
         lambda b: _rewrite(b, "credential.json", _flip_sig), "credential_signature_invalid"),
        ("a check time before the window opens",
         lambda b: _rewrite(b, "case.json", lambda d: d.update(now="2026-10-01T00:00:00Z")),
         "receipt_not_yet_valid"),
        ("a check time at the window end",
         lambda b: _rewrite(b, "case.json", lambda d: d.update(now="2026-12-01T00:00:00Z")),
         "receipt_expired"),
        ("a missing check time", lambda b: _rewrite(b, "case.json", lambda d: d.pop("now")),
         "receipt_not_yet_valid"),
    ]


@pytest.mark.parametrize(("label", "edit", "reason"), _receipt_edits(),
                         ids=[e[0] for e in _receipt_edits()])
def test_receipt_edits_fail_closed(label: str, edit, reason: str, tmp_path: Path) -> None:
    from agent_evidence_verify.adapters import status_receipt_binding as srb
    assert srb.judge(SR / "case.json") == ("accept", "credential_bound")
    assert srb.judge(_receipt_case(tmp_path, edit)) == ("reject", reason), label


def test_a_case_with_no_receipt_file_is_not_accepted(tmp_path: Path) -> None:
    from agent_evidence_verify.adapters import status_receipt_binding as srb
    case = _receipt_case(tmp_path, lambda b: (b / "receipt.json").unlink())
    assert srb.judge(case) == ("reject", "receipt_malformed")
