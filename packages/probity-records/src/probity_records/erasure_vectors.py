"""Conformance vectors for record envelope v2 (``erasure``).

Each vector is ``{"id", "description", "op", "input", "expected"}``. Byte strings (keys, leaf ids, nonces,
ciphertexts) are lowercase hex. ``op`` is one of:

- ``seal``: ``input`` is ``{"schema", "record", "keys", "subjectValue", "subjectRole", "leaf", "nonces"}`` (``keys``
  maps a role to a 32-byte key, ``nonces`` maps ``"<role>/<class>"`` to a 12-byte nonce); ``expected`` is
  ``{"kept", "erasure", "blobs", "subjectDigest"}`` or ``{"refused"}``.
- ``open``: ``input`` is ``{"kept", "erasure", "blobs", "keys"}``; ``expected`` is ``{"fields", "erased",
  "missing"}`` or ``{"refused"}``.
- ``disclose``: ``input`` is ``{"key", "erasure", "path", "value"}``; ``expected`` is the disclosure or
  ``{"refused"}``.
- ``verify-disclosure``: ``input`` is ``{"erasure", "disclosure"}``; ``expected`` is ``{"valid"}``.
- ``lint``: ``input`` is ``{"schema"}``; ``expected`` is ``{"problems"}``.
- ``erasability``: ``input`` is ``{"predicates"}``; ``expected`` is ``{"label", "records", "v1", "v2", "kept"}``.

``refused`` is the ``EnvelopeError`` code. Keys, leaf ids and nonces are fixed, so the file is byte-identical on
every run.
"""

from __future__ import annotations

import hashlib
from typing import Any

from . import erasure as ev
from .erasure import KEPT, PAYLOAD, PSEUDONYM, EnvelopeError, Rule, Schema

SCHEMA = Schema("example-decision@2", (
    Rule("record_kind", KEPT), Rule("sequence", KEPT), Rule("previous_record_sha256", KEPT), Rule("verdict", KEPT),
    Rule("session_sha256", PSEUDONYM, "user", personal=True, digest_of_personal=True),
    Rule("intent", PAYLOAD, "user", personal=True, commit=True),
    Rule("reasons", PAYLOAD, "user", personal=True),
    Rule("approver", PAYLOAD, "approver", personal=True),
    Rule("principals.user", PSEUDONYM, "user", personal=True),
    Rule("principals.approver", PSEUDONYM, "approver", personal=True),
), frozenset({"previous_record_sha256"}))  # fmt: skip
STRUCTURAL_ONLY = Schema("example-summary@2", (Rule("record_kind", KEPT), Rule("count", KEPT)))
CALL = {"name": "act.1", "sha256": "f" * 64}


def _bytes(label: str, n: int) -> bytes:
    return hashlib.sha256(("erasure-vectors/" + label).encode()).digest()[:n]


KEYS = {"user": _bytes("key/user", 32), "approver": _bytes("key/approver", 32)}
LEAF = _bytes("leaf/1", 16)
NONCES = {(role, cls): _bytes(f"nonce/{role}/{cls}", 12) for role in ev.ROLES for cls in (PSEUDONYM, PAYLOAD)}


def record(**over: Any) -> dict[str, Any]:
    body = {"record_kind": "decision", "sequence": 3, "previous_record_sha256": "a" * 64, "verdict": "allow",
            "session_sha256": "5" * 64, "intent": {"tool": "pay", "args": {"to": "bob", "amount": 10}},
            "reasons": ["within limit"], "approver": "carol@example.com",
            "principals": {"user": {"issuer": "https://idp.example", "subject": "alice"},
                           "approver": {"issuer": "https://idp.example", "subject": "carol"}}}  # fmt: skip
    return {**body, **over}


def _hex(keys: dict[str, bytes]) -> dict[str, str]:
    return {k: v.hex() for k, v in sorted(keys.items())}


def _seal_input(schema: Schema, rec: Any, keys: dict[str, bytes], role: str | None) -> dict[str, Any]:
    return {"schema": schema.to_json(), "record": rec, "keys": _hex(keys), "subjectValue": CALL if role else None,
            "subjectRole": role, "leaf": LEAF.hex(),
            "nonces": {f"{r}/{c}": n.hex() for (r, c), n in sorted(NONCES.items())}}  # fmt: skip


def run(op: str, data: dict[str, Any]) -> dict[str, Any]:
    """The expected block for one vector's ``op`` and ``input``, computed by this package."""
    try:
        return _run(op, data)
    except EnvelopeError as exc:
        return {"refused": exc.code}


def _keys(data: dict[str, Any]) -> dict[str, bytes]:
    return {role: bytes.fromhex(k) for role, k in data["keys"].items()}


def _run(op: str, data: dict[str, Any]) -> dict[str, Any]:
    if op == "seal":
        nonces: dict[tuple[str, str], bytes] = {}
        for name, value in data["nonces"].items():
            role, _, cls = name.partition("/")
            nonces[(role, cls)] = bytes.fromhex(value)
        sealed = ev.seal(Schema.from_json(data["schema"]), data["record"], _keys(data), data["subjectValue"],
                         data["subjectRole"], leaf=bytes.fromhex(data["leaf"]), nonce=nonces)
        return {"kept": sealed.kept, "erasure": sealed.erasure, "subjectDigest": sealed.subject_digest,
                "blobs": {d: b.hex() for d, b in sorted(sealed.blobs.items())}}  # fmt: skip
    if op == "open":
        blobs = {d: bytes.fromhex(b) for d, b in data["blobs"].items()}
        opened = ev.open_sealed(data["kept"], data["erasure"], blobs, _keys(data))
        return {"fields": opened.fields, "erased": list(opened.erased), "missing": list(opened.missing)}
    if op == "disclose":
        return ev.disclose(bytes.fromhex(data["key"]), data["erasure"], data["path"], data["value"])
    if op == "verify-disclosure":
        return {"valid": ev.verify_disclosure(data["erasure"], data["disclosure"])}
    if op == "lint":
        return {"problems": ev.lint_schema(Schema.from_json(data["schema"]))}
    if op == "erasability":
        report = ev.erasability(data["predicates"])
        return {"label": report.label, "records": report.records, "v1": report.v1, "v2": report.v2,
                "kept": list(report.kept)}  # fmt: skip
    raise ValueError(op)


def vectors() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    def add(vid: str, description: str, op: str, data: dict[str, Any]) -> dict[str, Any]:
        expected = run(op, data)
        rows.append({"id": vid, "description": description, "op": op, "input": data, "expected": expected})
        return expected

    base = add("S1", "a decision sealed: structural fields kept, the rest pseudonymized or encrypted per subject",
               "seal", _seal_input(SCHEMA, record(), KEYS, "user"))
    add("S2", "a null field whose subject has no key is kept as null; no approver key is needed", "seal",
        _seal_input(SCHEMA, record(approver=None, principals={"user": record()["principals"]["user"]}),
                    {"user": KEYS["user"]}, "user"))
    add("S3", "a record with no data subject: every field kept, no statement subject", "seal",
        _seal_input(STRUCTURAL_ONLY, {"record_kind": "summary", "count": 7}, {}, None))
    add("S4", "a field the schema does not declare is refused", "seal",
        _seal_input(SCHEMA, record(extra=1), KEYS, "user"))
    add("S5", "a plain digest in a kept field not declared structural is refused", "seal",
        _seal_input(SCHEMA, record(verdict="sha256:" + "b" * 64), KEYS, "user"))
    add("S6", "a personal field with no key for its subject is refused", "seal",
        _seal_input(SCHEMA, record(), {"user": KEYS["user"]}, "user"))
    bad = Schema("bad@2", (Rule("email", KEPT, personal=True),))
    add("S7", "a schema that keeps a personal field cannot seal", "seal", _seal_input(bad, {"email": "x"}, {}, None))

    kept, erasure = base["kept"], base["erasure"]
    blobs = base["blobs"]
    add("O1", "every key present: the record opens to its clear fields", "open",
        {"kept": kept, "erasure": erasure, "blobs": blobs, "keys": _hex(KEYS)})
    add("O2", "the user key is destroyed: the user's fields read as erased, the approver's still open", "open",
        {"kept": kept, "erasure": erasure, "blobs": blobs, "keys": _hex({"approver": KEYS["approver"]})})
    first = sorted(blobs)[0]
    add("O3", "a ciphertext the payload store no longer holds reads as missing", "open",
        {"kept": kept, "erasure": erasure, "blobs": {d: b for d, b in blobs.items() if d != first},
         "keys": _hex(KEYS)})
    add("O4", "a blob whose bytes do not hash to the committed digest is refused", "open",
        {"kept": kept, "erasure": erasure, "blobs": {**blobs, first: "00" + blobs[first][2:]}, "keys": _hex(KEYS)})
    add("O5", "the leaf id changed: the AEAD binding refuses the ciphertext", "open",
        {"kept": kept, "erasure": {**erasure, "leaf": "0" * 32}, "blobs": blobs, "keys": _hex(KEYS)})
    add("O6", "a tampered commitment is refused", "open",
        {"kept": kept, "erasure": {**erasure, "commitments": {"intent": "0" * 64}}, "blobs": blobs,
         "keys": _hex(KEYS)})
    add("O7", "a tampered pseudonym is refused", "open",
        {"kept": kept, "erasure": {**erasure, "pseudonyms": {**erasure["pseudonyms"], "session_sha256": "0" * 64}},
         "blobs": blobs, "keys": _hex(KEYS)})
    add("O8", "a wrong key for a present subject is refused, never read as erased", "open",
        {"kept": kept, "erasure": erasure, "blobs": blobs, "keys": _hex({**KEYS, "user": _bytes("key/other", 32)})})
    add("O9", "a block that is not envelope v2 is refused", "open",
        {"kept": kept, "erasure": {**erasure, "format": "probity-record-envelope/v1"}, "blobs": blobs,
         "keys": _hex(KEYS)})
    add("O10", "ciphertexts that do not cover every non-kept field are refused", "open",
        {"kept": kept, "erasure": {**erasure, "ciphertexts": erasure["ciphertexts"][:1]}, "blobs": blobs,
         "keys": _hex(KEYS)})
    add("O11", "a class outside kept, pseudonym and payload is refused", "open",
        {"kept": kept, "erasure": {**erasure, "classes": {**erasure["classes"], "verdict": "secret"}},
         "blobs": blobs, "keys": _hex(KEYS)})

    shown = add("D1", "one committed field disclosed: its value and k_field, never the subject key", "disclose",
                {"key": KEYS["user"].hex(), "erasure": erasure, "path": "intent", "value": record()["intent"]})
    add("D2", "a field without a commitment cannot be disclosed", "disclose",
        {"key": KEYS["user"].hex(), "erasure": erasure, "path": "reasons", "value": record()["reasons"]})
    add("V1", "the disclosure verifies against the commitment", "verify-disclosure",
        {"erasure": erasure, "disclosure": shown})
    add("V2", "another value under the same field key does not verify", "verify-disclosure",
        {"erasure": erasure, "disclosure": {**shown, "value": {"tool": "pay", "args": {"to": "eve", "amount": 10}}}})
    add("V3", "a disclosure naming another leaf does not verify", "verify-disclosure",
        {"erasure": erasure, "disclosure": {**shown, "leaf": "1" * 32}})

    add("L1", "a schema that may seal: no problems", "lint", {"schema": SCHEMA.to_json()})
    add("L2", "personal or digest-of-personal fields kept, and digest-named kept fields not declared structural",
        "lint", {"schema": Schema("bad@2", (Rule("email", KEPT, personal=True),
                                            Rule("token_digest", KEPT, digest_of_personal=True),
                                            Rule("response_sha256", KEPT))).to_json()})  # fmt: skip
    add("L3", "a non-kept field with no subject role, a pseudonym with a commitment, a kept field naming a key",
        "lint", {"schema": Schema("bad@2", (Rule("a", PAYLOAD, None), Rule("b", PSEUDONYM, "user", commit=True),
                                            Rule("c", KEPT, "user"))).to_json()})  # fmt: skip

    v2 = {**kept, "erasure": erasure}
    add("E1", "every record in envelope v2: erasable, and the kept class is printed", "erasability",
        {"predicates": [v2, v2]})
    add("E2", "one v1 record makes the journal not erasable", "erasability", {"predicates": [v2, record()]})
    return rows


def check(rows: list[dict[str, Any]]) -> list[str]:
    """The ids whose recomputed outcome differs from the vector's expected outcome."""
    return [v["id"] for v in rows if run(v["op"], v["input"]) != v["expected"]]
