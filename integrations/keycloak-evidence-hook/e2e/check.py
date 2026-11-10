"""Verify every receipt the hook wrote, offline, with the released verifier's claim type.

Usage: check.py <work dir> <out dir> <verifier command...>

Reads ``<work>/sink/receipts.jsonl``, ``<work>/keys/recorder.pub.pem`` and ``<work>/observed.json``.
For each grant the driver observed it finds the one receipt whose subject digest is the SHA-256 of
the ``jti`` the client received, writes a case and a policy pinning the recorder key and the
observed values, and runs the verifier. Then it runs the controls that must not be supported: a
receipt with one payload byte changed, a scope the consumer did not allow, and a log with a line
removed. Exits 0 only when every expectation holds.
"""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

CLAIM = "token_grant_receipt/v1"


def raw_public_key(pem: str) -> str:
    body = "".join(line for line in pem.splitlines() if not line.startswith("-----"))
    spki = base64.b64decode(body)
    if len(spki) != 44:
        raise SystemExit("recorder.pub.pem is not an Ed25519 SubjectPublicKeyInfo")
    return spki[-32:].hex()


def artifact(root: Path, name: str, data: bytes) -> dict:
    (root / name).write_bytes(data)
    return {"path": name, "length": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def run_case(verifier: list[str], root: Path, case_id: str, envelope: bytes, log: bytes | None,
             key: str, expected: dict) -> dict:
    root.mkdir(parents=True, exist_ok=True)
    artifacts = {"envelope": artifact(root, "envelope.json", envelope)}
    assessment = {"claim_type": CLAIM, "envelope": "envelope", "recorder_public_key": key,
                  "expected": expected}
    if log is not None:
        artifacts["log"] = artifact(root, "receipts.jsonl", log)
        assessment["log"] = "log"
    case = {"schema_version": "probity-case/v1", "case_id": case_id, "artifacts": artifacts}
    policy = {"schema_version": "probity-policy/v1", "assessments": {case_id: assessment}}
    (root / "case.json").write_text(json.dumps(case, indent=2) + "\n", encoding="utf-8")
    (root / "policy.json").write_text(json.dumps(policy, indent=2) + "\n", encoding="utf-8")
    done = subprocess.run([*verifier, str(root / "case.json"), "--policy", str(root / "policy.json"),
                           "--json"], capture_output=True, text=True, check=False)
    (root / "decision.json").write_text(done.stdout, encoding="utf-8")
    if done.returncode != 0:
        print(f"VERIFIER_EXIT {case_id} rc={done.returncode} {done.stderr.strip()}")
        return {"decision": "invalid_input", "reason": done.stderr.strip()}
    return json.loads(done.stdout)


def subject_digest(line: bytes) -> str:
    statement = json.loads(base64.b64decode(json.loads(line)["payload"]))
    return statement["subject"][0]["digest"]["sha256"]


def main() -> int:
    work, out, verifier = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3:]
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    log = (work / "sink" / "receipts.jsonl").read_bytes()
    lines = [line for line in log.split(b"\n") if line]
    key = raw_public_key((work / "keys" / "recorder.pub.pem").read_text(encoding="ascii"))
    grants = json.loads((work / "observed.json").read_text(encoding="utf-8"))["grants"]
    shutil.copy(work / "observed.json", out / "observed.json")
    (out / "receipts.jsonl").write_bytes(log)
    (out / "recorder-public-key.hex").write_text(key + "\n", encoding="ascii")
    results: list[tuple[str, str, str, bool]] = []

    def expect(case_id: str, decision: dict, wanted: str, reason: str | None = None) -> None:
        ok = decision["decision"] == wanted and (reason is None or decision["reason"] == reason)
        results.append((case_id, decision["decision"], decision["reason"], ok))

    for grant in grants:
        matches = [line for line in lines if subject_digest(line) == grant["access_token_id_sha256"]]
        if len(matches) != 1:
            results.append((grant["name"], "no_receipt", f"{len(matches)} receipts match the jti", False))
            continue
        envelope = matches[0] + b"\n"
        expected = {k: grant[k] for k in ("issuer", "grant_type", "actor_client_id",
                                          "access_token_id_sha256", "subject_user_id")}
        expected["scope_allowed"] = grant["scope"]
        if grant["subject_token_sha256"]:
            expected["subject_token_sha256"] = grant["subject_token_sha256"]
        name = grant["name"]
        expect(name, run_case(verifier, out / name, name, envelope, log, key, expected), "supported",
               "grant_recorded_as_expected")
        if name != "token-exchange":
            continue
        envelope_json = json.loads(envelope)
        payload = bytearray(base64.b64decode(envelope_json["payload"]))
        payload[payload.index(b'"tools:read"') + 2] ^= 0x01
        envelope_json["payload"] = base64.b64encode(bytes(payload)).decode("ascii")
        tampered = (json.dumps(envelope_json, separators=(",", ":"), sort_keys=True) + "\n").encode("ascii")
        expect("tampered-payload", run_case(verifier, out / "tampered-payload", "tampered-payload",
                                            tampered, None, key, expected),
               "not_established", "receipt_signature_unverified")
        narrow = {**expected, "scope_allowed": ["tools:read"]}
        expect("scope-not-allowed", run_case(verifier, out / "scope-not-allowed", "scope-not-allowed",
                                             envelope, None, key, narrow),
               "contradicted", "grant_scope_exceeds_expected")
        # Remove a line from the middle of the log, never the receipt itself. A removed first
        # line is a truncated prefix, which the chain alone cannot show; see docs/design.md.
        victim = 1 if lines.index(matches[0]) != 1 else len(lines) - 2
        cut = b"\n".join(line for i, line in enumerate(lines) if i != victim) + b"\n"
        expect("log-line-removed", run_case(verifier, out / "log-line-removed", "log-line-removed",
                                            envelope, cut, key, expected),
               "not_established", "receipt_log_unestablished")
    report = [{"case": c, "decision": d, "reason": r, "as_expected": ok} for c, d, r, ok in results]
    (out / "summary.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    for row in report:
        print(("PASS " if row["as_expected"] else "FAIL ") + f"{row['case']}: {row['decision']} {row['reason']}")
    failed = sum(not ok for *_, ok in results)
    print(f"CHECKS total={len(results)} failed={failed} receipts={len(lines)}")
    return 1 if failed or len(results) != 6 else 0


if __name__ == "__main__":
    raise SystemExit(main())
