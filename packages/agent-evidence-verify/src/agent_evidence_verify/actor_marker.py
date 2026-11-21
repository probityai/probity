"""``actor-marker-survival/v1``: did the acting-agent marker survive every hop?

A record is a chain of signed statements: the origin issuer's statement of the token it
sent, then one statement per hop of the token it received and the token it sent, in the
native form of each side's protocol. ``rfc8693`` tokens carry nested ``act`` claims
(RFC 8693 section 4.1: the outermost is the current actor, the least recent is the most
deeply nested); ``a2a-actor-chain`` tokens carry the ``actorChain`` member proposed in
a2aproject/A2A issue 2028, actors in delegation order. Each statement is Ed25519-signed
over its RFC 8785 bytes. The key and the writer's role come from the trust bundle the
caller holds, never from the record: an ``agent`` appends itself, a ``relay`` forwards
unchanged.

The checks, in order, first failure wins, are those of the corpus at
probityai/agent-evidence-vectors ``corpora/vectors-actor-marker-survival``: contract,
shape, writer, signature, link, audience, transit, critical header parameter
(RFC 7515 section 4.1.11), expiry at use, unsigned marker, deferred dispatch, subject,
the six actor-list classes, and user-alone without user-presence evidence. A record
passing all of them is ``accept`` / ``marker_survives``. This module shares no code
with that corpus's readers.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections import Counter
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .adapters.jcs_canonical import Refusal, canonical

SUITE = "actor-marker-survival/v1"
CONTRACT_ID = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/actor-marker-survival"
ACCEPTED = "marker_survives"
ACTOR_CLASSES = ("downgraded_to_user_alone", "chain_truncated", "marker_stripped",
                 "agent_replaced", "actor_order_changed", "actor_inserted")
_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class _Bad(ValueError):
    pass


def _ok(condition: bool) -> None:
    if not condition:
        raise _Bad("record_malformed")


def _jcs(value: Any) -> bytes:
    return canonical("rfc8785", json.dumps(value, ensure_ascii=False))


def _when(text: str) -> int:
    return int(datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC).timestamp())


def _time(value: Any) -> bool:
    return isinstance(value, str) and bool(_TIME.match(value))


def _sub(holder: Any) -> str:
    _ok(isinstance(holder, dict) and isinstance(holder.get("sub"), str) and holder["sub"] != "")
    return str(holder["sub"])


def principals(side: Any) -> tuple[str, list[str]]:
    _ok(isinstance(side, dict) and isinstance(side.get("token"), dict))
    token = side["token"]
    if side.get("protocol") == "rfc8693":
        header, claims = token.get("header"), token.get("claims")
        _ok(isinstance(header, dict) and isinstance(claims, dict))
        crit = header.get("crit", [])
        _ok(isinstance(crit, list) and all(isinstance(c, str) for c in crit))
        exp = claims.get("exp")
        _ok(exp is None or (type(exp) is int))
        chain: list[str] = []
        node = claims.get("act")
        while node is not None:
            chain.insert(0, _sub(node))
            node = node.get("act")
        return _sub(claims), chain
    if side.get("protocol") == "a2a-actor-chain":
        body = token.get("actorChain")
        _ok(isinstance(body, dict) and isinstance(body.get("actors"), list))
        return _sub(body.get("origin")), [_sub(a) for a in body["actors"]]
    raise _Bad("record_malformed")


def _check_side(side: Any, needs_to: bool) -> None:
    _ok(isinstance(side, dict) and _time(side.get("at")))
    _ok(not needs_to or (isinstance(side.get("to"), str) and side["to"] != ""))
    principals(side)


def _check_shape(record: dict[str, Any]) -> list[dict[str, Any]]:
    entries = record.get("statements")
    _ok(isinstance(entries, list) and len(entries) >= 2)
    for n, entry in enumerate(entries):
        _ok(isinstance(entry, dict) and isinstance(entry.get("signature"), str))
        st = entry.get("statement")
        _ok(isinstance(st, dict) and isinstance(st.get("writer"), str))
        headers = entry.get("transport", {"headers": {}})
        _ok(isinstance(headers, dict) and isinstance(headers.get("headers"), dict))
        _ok(all(isinstance(h, str) for h in headers["headers"].values()))
        _ok(st.get("kind") == ("origin" if n == 0 else "hop"))
        _check_side(st.get("sent"), True)
        if n == 0:
            ev = st.get("humanEvidence")
            _ok(ev is None or (isinstance(ev, dict) and isinstance(ev.get("method"), str)
                               and _time(ev.get("at"))))
            continue
        _ok(isinstance(st.get("prev"), str) and bool(_HEX64.match(st["prev"])))
        _check_side(st.get("received"), False)
        d = st.get("deferred")
        if d is not None:
            _ok(isinstance(d, dict) and _time(d.get("enqueuedAt")) and _time(d.get("dispatchedAt")))
            _ok(d["dispatchedAt"] == st["sent"]["at"] and _when(d["enqueuedAt"]) <= _when(d["dispatchedAt"]))
    return entries


def _raw(text: Any, size: int) -> bytes | None:
    if not isinstance(text, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", text):
        return None
    try:
        data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except ValueError:
        return None
    same = base64.urlsafe_b64encode(data).decode().rstrip("=") == text
    return data if len(data) == size and same else None


def _classify(owed: list[str], sent: list[str]) -> str | None:
    if sent == owed:
        return None
    if not sent:
        return "downgraded_to_user_alone"
    if Counter(sent) == Counter(owed):
        return "actor_order_changed"
    if len(sent) < len(owed) and _in_order(sent, owed):
        return "chain_truncated" if owed[-len(sent):] == sent else "marker_stripped"
    if len(sent) > len(owed) and _in_order(owed, sent):
        return "actor_inserted"
    return "agent_replaced"


def _in_order(short: list[str], long: list[str]) -> bool:
    it = iter(long)
    return all(x in it for x in short)


def _rules(entries: list[dict[str, Any]], writers: dict[str, Any]) -> list[tuple[str, Callable[[], bool]]]:
    sts = [e["statement"] for e in entries]
    hops = list(enumerate(sts))[1:]

    def role(st: dict[str, Any]) -> Any:
        w = writers.get(st["writer"])
        return w.get("role") if isinstance(w, dict) else None

    def owed(st: dict[str, Any]) -> tuple[str, list[str]]:
        subject, actors = principals(st["received"])
        return subject, actors + ([st["writer"]] if role(st) == "agent" else [])

    def any_hop(test: Callable[[int, dict[str, Any]], bool]) -> bool:
        return any(test(i, st) for i, st in hops)

    def writer_unknown() -> bool:
        return any(role(st) not in (("origin",) if i == 0 else ("agent", "relay")) for i, st in enumerate(sts))

    def signature_invalid() -> bool:
        for e in entries:
            key = _raw(writers[e["statement"]["writer"]].get("key"), 32)
            sig = _raw(e["signature"], 64)
            if key is None or sig is None:
                return True
            try:
                Ed25519PublicKey.from_public_bytes(key).verify(sig, _jcs(e["statement"]))
            except InvalidSignature:
                return True
        return False

    def token(side: dict[str, Any]) -> bytes:
        return _jcs({"protocol": side["protocol"], "token": side["token"]})

    def expired(st: dict[str, Any]) -> bool:
        rec = st["received"]
        exp = rec["token"]["claims"].get("exp") if rec["protocol"] == "rfc8693" else None
        return exp is not None and _when(st["sent"]["at"]) > exp

    def unsigned(i: int, st: dict[str, Any]) -> bool:
        if role(st) != "agent" or st["writer"] in principals(st["sent"])[1]:
            return False
        return st["writer"] in entries[i].get("transport", {"headers": {}})["headers"].values()

    def crit(st: dict[str, Any]) -> bool:
        rec = st["received"]
        return rec["protocol"] == "rfc8693" and bool(rec["token"]["header"].get("crit"))

    def alone() -> bool:
        if principals(sts[-1]["sent"])[1]:
            return False
        ev = sts[0].get("humanEvidence")
        return not (isinstance(ev, dict) and ev.get("method") == "user-presence")

    rules: list[tuple[str, Callable[[], bool]]] = [
        ("statement_writer_unknown", writer_unknown),
        ("statement_signature_invalid", signature_invalid),
        ("hop_link_broken", lambda: any_hop(lambda i, st: st["prev"] != hashlib.sha256(_jcs(sts[i - 1])).hexdigest())),
        ("audience_mismatch", lambda: any_hop(lambda i, st: st["writer"] != sts[i - 1]["sent"]["to"])),
        ("received_not_sent", lambda: any_hop(lambda i, st: token(st["received"]) != token(sts[i - 1]["sent"]))),
        ("unknown_critical_attribute_ignored", lambda: any_hop(lambda _i, st: crit(st))),
        ("principals_expired_at_use", lambda: any_hop(lambda _i, st: expired(st))),
        ("marker_unsigned", lambda: any_hop(unsigned)),
        ("deferred_dispatch_without_stored_principals",
         lambda: any_hop(lambda _i, st: "deferred" in st and principals(st["sent"]) != owed(st))),
        ("subject_replaced",
         lambda: any_hop(lambda _i, st: principals(st["sent"])[0] != principals(st["received"])[0])),
    ]
    for name in ACTOR_CLASSES:
        rules.append((name, lambda n=name: any_hop(
            lambda _i, st: _classify(owed(st)[1], principals(st["sent"])[1]) == n)))
    rules.append(("user_alone_without_human_evidence", alone))
    return rules


def judge(record_bytes: bytes, trust: dict[str, Any]) -> tuple[str, str]:
    """(``accept`` or ``reject``, reason) for one record under one trust bundle."""
    try:
        record = json.loads(record_bytes)
    except ValueError:
        return "reject", "record_malformed"
    if not isinstance(record, dict):
        return "reject", "record_malformed"
    if "contractId" not in record:
        return "reject", "contract_id_missing"
    if record["contractId"] != CONTRACT_ID:
        return "reject", "contract_id_unknown"
    try:
        entries = _check_shape(record)
    except (_Bad, Refusal, KeyError, TypeError, AttributeError):
        return "reject", "record_malformed"
    for name, fails in _rules(entries, trust.get("writers", {})):
        if fails():
            return "reject", name
    return "accept", ACCEPTED
