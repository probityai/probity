"""Differential cases for the Python and TypeScript verified-identities readers.

Every shared vector row is copied with one token segment or one DPoP segment replaced by hostile bytes or a hostile
spelling, or with one bundle key member respelled (key_spellings.py), or with a token or proof edited and signed again
(signed_edits.py), or generated from the grammar files (grammar_cases.py: every production of grammar/*.json at every
place it is read), and judged by probity_records.verified_identities_vectors.judge. Cases of kind possession, record and
spent judge the possession checks a request does not reach alone (check_possession, possession_record_problem,
duplicate_proofs). The TypeScript twin judges the same cases (judge_ts.ts); compare.py prints every case where the two
disagree and every registered refusal code of verified_identities.py and possession.py that no case reaches in either
language. Each case is judged after a JSON round trip, so both readers see the same values. A raise is RAISED:<type>.
Usage: gen_cases.py <shared verified_identities.json> <out cases.json>
"""

from __future__ import annotations

import base64
import copy
import json
import sys
from pathlib import Path
from typing import Any

from agent_evidence_verify import structured_fields as sf
from probity_records.certificate import CertificateRefused, certificate_facts, spki_key
from probity_records.grants import micros
from probity_records.possession import (
    check_possession,
    duplicate_proofs,
    http_uri_parts,
    possession_record_problem,
)
from probity_records.verified_identities_vectors import judge, proof_document

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # tests/: the shared key respellings
from grammar_cases import grammar_cases
from key_spellings import key_edits
from signed_edits import possession_cases, record_cases, request_edits, spent_cases


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def unb64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


BYTE_EDITS: dict[str, Any] = {
    "deep33": lambda raw: b"[" * 33 + b"]" * 33,
    "obj-depth32": lambda raw: b'{"a":' + b"[" * 31 + b"]" * 31 + b"}",
    "obj-depth33": lambda raw: b'{"a":' + b"[" * 32 + b"]" * 32 + b"}",
    "deep-in-member": lambda raw: raw[:-1] + b',"zz":' + b"[" * 40 + b"]" * 40 + b"}",
    "bracket-in-string": lambda raw: raw[:-1] + b',"zz":"' + b"[" * 40 + b'\\"' + b"[" * 40 + b'"}',
    "escaped-backslash-then-quote": lambda raw: raw[:-1] + b',"zz":"\\\\","yy":' + b"[" * 33 + b"]" * 33 + b"}",
    "repeated-top": lambda raw: raw[:-1] + b',"alg":"none"}',
    "repeated-nested": lambda raw: raw[:-1] + b',"zz":{"q":1,"q":2}}',
    "repeated-by-escape": lambda raw: raw[:-1] + b',"\\u0061lg":"none"}',
    "lone-surrogate": lambda raw: raw[:-1] + b',"zz":"\\ud800"}',
    "low-surrogate": lambda raw: raw[:-1] + b',"zz":"\\udc00x"}',
    "pair-ok": lambda raw: raw[:-1] + b',"zz":"\\ud83d\\ude00"}',
    "raw-surrogate-bytes": lambda raw: raw[:-1] + b',"zz":"\xed\xa0\x80"}',
    "invalid-utf8": lambda raw: raw[:-1] + b',"zz":"\xff"}',
    "overlong-utf8": lambda raw: raw[:-1] + b',"zz":"\xc0\xaf"}',
    "bom": lambda raw: b"\xef\xbb\xbf" + raw,
    "nan": lambda raw: raw[:-1] + b',"zz":NaN}',
    "overflow": lambda raw: raw[:-1] + b',"zz":1e400}',
    "big-int": lambda raw: raw[:-1] + b',"zz":9007199254740993}',
    "huge-int": lambda raw: raw[:-1] + b',"zz":' + b"9" * 400 + b"}",
    "neg-zero": lambda raw: raw[:-1] + b',"zz":-0}',
    "padded": lambda raw: b"  " + raw + b"\n",
    "not-object-array": lambda raw: b"[1]",
    "not-object-string": lambda raw: b'"x"',
    "null": lambda raw: b"null",
    "empty": lambda raw: b"",
    "crit": lambda raw: raw[:-1] + b',"crit":["exp"]}',
    "crit-escaped": lambda raw: raw[:-1] + b',"\\u0063rit":["exp"]}',
    "crit-empty": lambda raw: raw[:-1] + b',"crit":[]}',
    "jwk-ref": lambda raw: raw[:-1] + b',"jku":"https://x.example/k"}',
    "trailing-garbage": lambda raw: raw + b"x",
    "two-values": lambda raw: raw + b"{}",
}

TEXT_EDITS: dict[str, Any] = {
    "pad-eq": lambda seg: seg + "=",
    "std-alphabet": lambda seg: seg.replace("-", "+").replace("_", "/"),
    "non-ascii": lambda seg: seg + "é",
    "len-mod4-1": lambda seg: seg + "A",
    "space": lambda seg: seg[:4] + " " + seg[4:],
    "noncanonical-tail": lambda seg: seg[:-1] + ("B" if seg[-1] == "A" else "A") if len(seg) % 4 in (2, 3) else seg,
    "empty-seg": lambda seg: "",
}


def mutate(seg: str, kind: str, name: str) -> str:
    if kind == "bytes":
        return b64u(BYTE_EDITS[name](unb64u(seg)))
    return TEXT_EDITS[name](seg)


def _possession(c: dict[str, Any]) -> Any:
    r = c["request"]
    content = None if r["contentB64"] is None else base64.b64decode(r["contentB64"])
    cert = None if r["clientCertificateB64"] is None else base64.b64decode(r["clientCertificateB64"])
    proof, reason = check_possession(c["cnf"], method=r["method"], url=r["url"], at=c["at"], access_token=c["accessToken"],
                                     dpop=r["dpop"], client_certificate=cert, content=content or b"")  # fmt: skip
    return {"refused": reason} if proof is None else {"proof": proof_document(proof)}


def _record(c: dict[str, Any]) -> Any:
    problem = possession_record_problem(c["record"], c["cnf"])
    return {"ok": True} if problem is None else {"refused": problem}


def _spent(c: dict[str, Any]) -> Any:
    found = [[n, code] for n, code in duplicate_proofs([(n, body) for n, body in c["records"]])]
    return {"found": found, **({"refused": found[0][1].split(":")[0]} if found else {})}


def _timestamp(c: dict[str, Any]) -> Any:
    try:
        return {"micros": f"{micros(c['text']):d}"}
    except ValueError as exc:
        return {"refused": exc.args[0]}


def _uri(c: dict[str, Any]) -> Any:
    try:
        return list(http_uri_parts(c["text"]))
    except ValueError as exc:
        return {"refused": exc.args[0]}


def _certificate(c: dict[str, Any]) -> Any:
    try:
        facts = certificate_facts(base64.b64decode(c["derB64"]))
    except CertificateRefused as exc:
        return {"refused": exc.args[0]}
    key = spki_key(facts.spki)
    shown = None if key is None else {m: (x.hex() if isinstance(x, bytes) else x) for m, x in key.items()}
    return {"notBefore": f"{facts.not_before:d}", "notAfter": f"{facts.not_after:d}", "key": shown}


def _sf_bytes(c: dict[str, Any]) -> Any:
    try:
        member = sf.parse_dictionary(f"a=:{c['text']}:").get("a")
    except sf.SFError:
        return {"refused": "sf"}
    value = getattr(member, "value", None)
    return {"hex": value.hex()} if isinstance(value, bytes) and len(getattr(member, "params", {})) == 0 else {"other": True}


JUDGES = {"request": judge, "possession": _possession, "record": _record, "spent": _spent, "timestamp": _timestamp,
          "uri": _uri, "certificate": _certificate, "sf-bytes": _sf_bytes}


def verdict(kind: str, row: dict[str, Any]) -> Any:
    try:
        return JUDGES[kind](json.loads(json.dumps(row)))  # the values the TypeScript reader parses
    except Exception as exc:  # noqa: BLE001 - a raise is itself the finding
        return f"RAISED:{type(exc).__name__}"


def main() -> None:
    with open(sys.argv[1]) as f:
        rows = json.load(f)
    cases: list[dict[str, Any]] = []
    skipped: list[str] = []  # a segment a byte edit cannot decode; counted and printed, never dropped silently
    for row in rows:
        cases.append({"case": f"{row['id']}/unchanged", "row": row})
        for role, token in row["tokens"].items():
            if not isinstance(token, str) or token.count(".") != 2:
                continue
            for seg_i in (0, 1):
                for kind, table in (("bytes", BYTE_EDITS), ("text", TEXT_EDITS)):
                    for name in table:
                        r = copy.deepcopy(row)
                        parts = token.split(".")
                        try:
                            parts[seg_i] = mutate(parts[seg_i], kind, name)
                        except ValueError:  # binascii.Error: the vector's own segment is not base64url
                            skipped.append(f"{row['id']}/token/{role}/{seg_i}/{name}")
                            continue
                        r["tokens"][role] = ".".join(parts)
                        cases.append({"case": f"{row['id']}/token/{role}/{seg_i}/{name}", "row": r})
        dpop = (row.get("request") or {}).get("dpop")
        if isinstance(dpop, str) and dpop.count(".") == 2:
            for seg_i in (0, 1):
                for kind, table in (("bytes", BYTE_EDITS), ("text", TEXT_EDITS)):
                    for name in table:
                        r = copy.deepcopy(row)
                        parts = dpop.split(".")
                        try:
                            parts[seg_i] = mutate(parts[seg_i], kind, name)
                        except ValueError:  # binascii.Error: the vector's own segment is not base64url
                            skipped.append(f"{row['id']}/dpop/{seg_i}/{name}")
                            continue
                        r["request"]["dpop"] = ".".join(parts)
                        cases.append({"case": f"{row['id']}/dpop/{seg_i}/{name}", "row": r})
        cases.extend({"case": name, "row": r} for name, r in key_edits(row))  # one bundle key respelled
        cases.extend({"case": name, "row": r} for name, r in request_edits(row))  # edited and signed again
    for kind, family in (("possession", possession_cases), ("record", record_cases), ("spent", spent_cases)):
        cases.extend({"case": name, "kind": kind, "row": c} for name, c in family(rows))
    cases.extend(grammar_cases(rows))  # every production of grammar/*.json, at every place it is read
    for c in cases:
        c.setdefault("kind", "request")
        c["python"] = verdict(c["kind"], c["row"])
    with open(sys.argv[2], "w") as f:
        json.dump(cases, f, ensure_ascii=True)
    print(f"PARITY_CASES {len(cases)} PARITY_SKIPPED {len(skipped)}")
    for case in skipped:
        print(f"  SKIPPED {case}")


if __name__ == "__main__":
    main()
