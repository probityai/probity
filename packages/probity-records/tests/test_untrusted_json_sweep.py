"""Every reader of bytes a stranger can hand the package reads them through ``core.admitted_loads``.

Each test hands one reader a document json.loads would take apart: nesting past the interpreter's recursion limit,
a repeated member (json.loads keeps the last), a lone surrogate, bytes that are not UTF-8, or more bytes than the
caller allows. The reader must answer with its own refusal, never raise, and never see a value other than the one
signed. The CPython recursion limit is about 1,000 levels, so 20,000 nested containers is past it on every version.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from probity_records import Journal, Signer, authority, governance
from probity_records import erasure as ev
from probity_records import journal as journal_mod
from probity_records.__main__ import main
from probity_records.clock import SystemClock
from probity_records.core import admitted_loads
from probity_records.erasure import (
    KEPT,
    PAYLOAD,
    PSEUDONYM,
    EnvelopeError,
    Rule,
    Schema,
)
from probity_records.exports import (
    MAX_EXPORT_BYTES,
    compare_seals,
    parse_export,
    seal_export,
    verify_export_seal,
)
from probity_records.identity import b64url
from probity_records.verified_identities import (
    VerifiedIdentitiesRefused,
    verified_identities,
)
from probity_records.verified_identities_vectors import AT, bundle, token

DEEP = b"[" * 20_000 + b"]" * 20_000
HOSTILE = {
    "deep": DEEP,
    "repeated member": b'{"a":1,"a":2}',
    "lone surrogate": b'{"a":"\\ud800"}',
    "invalid utf-8": b'{"a":"\xff"}',
    "nan": b'{"a":NaN}',
}


@pytest.mark.parametrize("name", sorted(HOSTILE))
def test_the_reader_itself_refuses_each_hostile_document(name: str) -> None:
    with pytest.raises(ValueError, match="jcs_refused"):
        admitted_loads(HOSTILE[name])


# ---------- verified_identities: a token segment ----------

@pytest.mark.parametrize("name", sorted(HOSTILE))
@pytest.mark.parametrize("segment", [0, 1])
def test_a_hostile_token_segment_is_token_malformed(name: str, segment: int) -> None:
    parts = token("agent").split(".")
    parts[segment] = b64url(HOSTILE[name])
    with pytest.raises(VerifiedIdentitiesRefused) as err:
        verified_identities({"user": token("user"), "agent": ".".join(parts)}, bundle(), AT)
    assert err.value.code == "token_malformed"


# ---------- exports ----------

SEALED_AT = "2026-11-08T00:00:00Z"


def _sealed(signer: Signer, data: bytes) -> dict:
    return seal_export(signer, data, source="t", kind="entities", captured_at=SEALED_AT, sealed_at=SEALED_AT)


@pytest.mark.parametrize("name", sorted(HOSTILE))
def test_an_export_the_strict_reader_refuses_is_a_value_error_not_a_crash(name: str) -> None:
    with pytest.raises(ValueError):
        parse_export(b'{"content":' + HOSTILE[name] + b"}")


def test_an_export_past_the_size_bound_is_refused_and_the_bound_is_the_callers_to_move() -> None:
    data = json.dumps({"content": [{"id": "a"}]}).encode()
    assert parse_export(data) == [{"id": "a"}]
    with pytest.raises(ValueError, match="jcs_refused"):
        parse_export(data, max_bytes=len(data) - 1)
    assert parse_export(data, max_bytes=len(data)) == [{"id": "a"}]
    assert MAX_EXPORT_BYTES == 128 * 1024 * 1024


def test_a_hostile_export_fails_its_seal_check_and_a_hostile_seal_payload_is_a_failure() -> None:
    signer = Signer.generate()
    data = json.dumps({"content": [{"id": "a"}]}).encode()
    seal = _sealed(signer, data)
    assert verify_export_seal(seal, DEEP, [signer.public_pem()])["verdict"] == "FAIL"
    # a payload the key signed that no strict reader accepts: a repeated member, then nesting past the limit
    for payload in (b'{"predicate":{},"predicate":{}}', DEEP):
        forged = _signed(signer, payload)
        report = verify_export_seal(forged, data, [signer.public_pem()])
        assert report["verdict"] == "FAIL" and report["failures"], payload[:20]


def _signed(signer: Signer, payload: bytes) -> dict:
    from probity_records.core import sign_envelope

    return sign_envelope(signer, payload)


def test_compare_seals_refuses_a_payload_the_strict_reader_refuses() -> None:
    signer = Signer.generate()
    good = _sealed(signer, json.dumps({"content": [{"id": "a"}]}).encode())
    with pytest.raises(ValueError, match="jcs_refused"):
        compare_seals(good, _signed(signer, b'{"predicate":{"census":{}},"predicate":{}}'))
    with pytest.raises(ValueError, match="jcs_refused"):
        compare_seals(_signed(signer, DEEP), good)


def test_the_command_line_reports_a_hostile_seal_and_a_hostile_pair_without_a_traceback(tmp_path: Path,
                                                                                         capsys) -> None:
    signer = Signer.generate()
    (tmp_path / "pub.pem").write_bytes(signer.public_pem())
    (tmp_path / "export.json").write_bytes(b'{"content":[]}')
    (tmp_path / "seal.json").write_bytes(DEEP)
    assert main(["verify-export", str(tmp_path / "export.json"), str(tmp_path / "seal.json"),
                 "--pub", str(tmp_path / "pub.pem")]) == 1
    assert '"verdict": "FAIL"' in capsys.readouterr().out
    assert main(["compare-seals", str(tmp_path / "seal.json"), str(tmp_path / "seal.json")]) == 1
    assert "seals_unreadable" in capsys.readouterr().out


# ---------- governance and authority: the call arguments a record carries ----------

def test_arguments_the_strict_reader_refuses_are_not_the_call_arguments() -> None:
    body = governance.exception_body(
        exception_id="EX-1", owner="human:risk", rationale="goodwill", tool="refund_payment", args={},
        not_before="2026-01-01T00:00:00Z", expires_at="2099-01-01T00:00:00Z", policy_id="p", requested_by="a")
    for raw in (DEEP, b'{"a":1,"a":2}', b"\xff"):
        evidence = {"argsB64": base64.b64encode(raw).decode(), "exception": body,
                    "exceptionDigest": governance.exception_digest(body), "quorum": {}}
        pred = {"tool": "refund_payment", "exceptionDigest": governance.exception_digest(body)}
        problems = governance.verify_exception_evidence(pred, evidence, {}, "2026-06-01T00:00:00Z")
        assert "authority_args_are_not_the_call_arguments" in problems, raw[:20]
    problems: list[str] = []
    for raw in (DEEP, b'{"a":1,"a":2}'):
        assert authority._args({"argsB64": base64.b64encode(raw).decode()}, {}, problems, "line_1") is None
    assert problems.count("line_1:authority_args_are_not_the_call_arguments") >= 1
    problems = []
    assert authority._args({"argsB64": "not base64!"}, {}, problems, "line_2") is None
    assert problems == ["line_2:authority_args_are_not_the_call_arguments"]


# ---------- the journal ----------

def test_a_hostile_key_certificate_line_is_a_failure_not_a_crash(tmp_path: Path) -> None:
    (tmp_path / journal_mod.KEYS_FILE).write_bytes(DEEP + b"\n" + b'{"body":{},"body":{}}\n')
    failures: list[str] = []
    assert journal_mod._delegations(tmp_path, [], failures) == {}
    assert [f.split(":")[0] for f in failures] == ["keys_line_1", "keys_line_2"]


def test_a_hostile_checkpoint_provenance_is_left_to_the_checkpoint_check(tmp_path: Path) -> None:
    for payload in (DEEP, b'{"predicate":{},"predicate":{}}'):
        env = {"payload": base64.b64encode(payload).decode()}
        failures: list[str] = []
        journal_mod._check_custody(env, set(), {}, authority.Trust(), failures)
        assert failures == []


def test_the_journal_reads_its_own_hostile_line_as_a_refusal_not_a_recursion_error(tmp_path: Path) -> None:
    journal = Journal(tmp_path, Signer.generate(), clock=SystemClock())
    journal.append("https://example.test/t", "s0", "0" * 64, {"phase": "note"})
    with (tmp_path / journal_mod.JOURNAL_FILE).open("ab") as fh:
        fh.write(DEEP + b"\n")
    with pytest.raises(ValueError, match="jcs_refused"):
        journal.statements()


# ---------- erasure: bytes a sealer encrypted ----------

SCHEMA = Schema("sweep@2", (Rule("sequence", KEPT), Rule("session_sha256", PSEUDONYM, "user", personal=True),
                            Rule("intent", PAYLOAD, "user", personal=True)), frozenset())


@pytest.mark.parametrize("plain", [DEEP, b'{"intent":1,"intent":2}', b'["not","an","object"]'])
def test_a_ciphertext_whose_plaintext_the_strict_reader_refuses_is_ciphertext_refused(
        monkeypatch: pytest.MonkeyPatch, plain: bytes) -> None:
    keys = {"user": b"k" * 32}
    record = {"sequence": 1, "session_sha256": "s" * 64, "intent": {"tool": "pay"}}
    monkeypatch.setattr(ev, "_pad", lambda data, size=None: plain)
    sealed = ev.seal(SCHEMA, record, keys, "call", "user")
    monkeypatch.undo()
    with pytest.raises(EnvelopeError) as err:
        ev.open_sealed(sealed.kept, sealed.erasure, sealed.blobs, keys)
    assert err.value.code == "ciphertext_refused"
