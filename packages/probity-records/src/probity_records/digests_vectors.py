"""Conformance vectors for the identity digests (``digests``).

Each vector is ``{"id", "description", "function", "input", "expected"}``. ``input`` is the JSON text of the argument
array, so a float written ``1.0``, an integer beyond 2**53 and an escaped lone surrogate reach every reader as written;
a reader parses it keeping integers and floats apart (Python ``json``, the TypeScript twin's ``parsePy``, Go
``json.Number``) and calls ``function`` with the items. ``expected`` is ``{"digest"}`` or ``{"refused", "reason"}``,
``reason`` null for every code but ``identity_out_of_domain``. Keys and times are fixed, so the file is byte-identical
on every run.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .core import Signer
from .digests import MAX_ACTORS, MAX_DEPTH, MAX_SAFE_INT, judge
from .grants import grant_digest, issue_grant, raw_public
from .identity_vectors import base
from .possession import cnf_for_signer

NOT_BEFORE, EXPIRES = "2026-11-21T00:00:00Z", "2026-11-22T00:00:00Z"


def _signer(seed: str) -> Signer:
    return Signer(Ed25519PrivateKey.from_private_bytes(hashlib.sha256(seed.encode()).digest()))


def block() -> dict[str, Any]:
    """The four-principal block of the identity vectors (user credential names the agent in ``act``)."""
    return base()["principals"]


def links(spend_max: float = 100) -> list[dict[str, Any]]:
    """A root grant from the principal to agent A and A's narrower link to agent B."""
    root_key, a, b = _signer("b30/root"), _signer("b30/agent-a"), _signer("b30/agent-b")
    tools = {"refund": {"args": {"amount": {"type": "range", "min": 0, "max": 500}}}}
    root = issue_grant(root_key, grant_id="g-root", holder_key=raw_public(a), cnf=cnf_for_signer(a), tools=tools, not_before=NOT_BEFORE,
                       expires_at=EXPIRES, max_depth=1, budget={"uses": 10, "spend": {"arg": "amount", "max": 1000}})
    child = issue_grant(a, grant_id="g-a-b", holder_key=raw_public(b), cnf=cnf_for_signer(b), parent=root, not_before=NOT_BEFORE,
                        expires_at=EXPIRES, tools={"refund": {"args": {"amount": {"type": "range", "min": 0, "max": 50}}}},
                        budget={"uses": 2, "spend": {"arg": "amount", "max": spend_max}})
    return [root, child]


def _reversed(value: Any) -> str:
    """JSON text with every object's members in reverse order: the same value, other bytes."""
    if isinstance(value, dict):
        return "{" + ",".join(json.dumps(k) + ":" + _reversed(v) for k, v in reversed(list(value.items()))) + "}"
    if isinstance(value, list):
        return "[" + ",".join(_reversed(v) for v in value) + "]"
    return json.dumps(value, ensure_ascii=False)


def _nested(depth: int, leaf: Any) -> Any:
    value = leaf
    for _ in range(depth):
        value = {"n": value}
    return value


def _actors(n: int) -> dict[str, Any]:
    act: dict[str, Any] = {"sub": f"agent-{n}"}
    for i in range(n - 1, 0, -1):
        act = {"sub": f"agent-{i}", "act": act}
    return act


def _with(path: list[str], value: Any) -> dict[str, Any]:
    doc = block()
    target = doc
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    return doc


def _args(*items: Any) -> str:
    return json.dumps(list(items), ensure_ascii=False, separators=(",", ":"))


def _cases() -> list[tuple[str, str, str, str]]:
    b, chain = block(), links()
    act = b["user"]["act"]
    digests = [grant_digest(link["body"]) for link in chain]
    no_act = block()
    del no_act["user"]["act"]
    p = "sha256:" + "a1" * 32
    a = "sha256:" + "b2" * 32
    g = "sha256:" + "c3" * 32
    deep_ok = _with(["user", "extra"], _nested(MAX_DEPTH - 2, True))
    deep_bad = _with(["user", "extra"], _nested(MAX_DEPTH - 1, True))
    return [
        ("PD1", "four principals, the user credential names the agent in act", "principals_digest", _args(b)),
        ("PD2", "the same block with every object's members reversed: the same digest", "principals_digest",
         "[" + _reversed(b) + "]"),
        ("PD3", "an astral character in a value is in the domain", "principals_digest",
         _args(_with(["user", "subject"], "alice-\U0001f600@example.com"))),
        ("PD4", "an astral character in a member name", "principals_digest", _args(_with(["user", "\U0001f600"], 1))),
        ("PD5", "a non-ASCII member name in the Basic Multilingual Plane", "principals_digest",
         _args(_with(["user", "ténant"], "x"))),
        ("PD6", "a control character in a member name", "principals_digest", _args(_with(["user", "a\tb"], "x"))),
        ("PD7", "an integer one beyond 2**53 - 1", "principals_digest", _args(_with(["user", "extra"], MAX_SAFE_INT + 1))),
        ("PD8", "the largest and smallest safe integers are in the domain", "principals_digest",
         _args(_with(["user", "extra"], [MAX_SAFE_INT, -MAX_SAFE_INT]))),
        ("PD9", "a negative integer one beyond the safe range", "principals_digest",
         _args(_with(["user", "extra"], -MAX_SAFE_INT - 1))),
        ("PD10", "a fractional number", "principals_digest", _args(_with(["user", "extra"], 1.5))),
        ("PD11", "an integral number written as a float", "principals_digest",
         _args(_with(["user", "extra"], 7)).replace('"extra":7', '"extra":7.0')),
        ("PD12", "an integral number written with an exponent", "principals_digest",
         _args(_with(["user", "extra"], 7)).replace('"extra":7', '"extra":7e0')),
        ("PD13", "an escaped lone surrogate in a value", "principals_digest",
         _args(_with(["user", "extra"], "x")).replace('"extra":"x"', '"extra":"\\ud800"')),
        ("PD14", f"nesting {MAX_DEPTH} containers deep is in the domain", "principals_digest", _args(deep_ok)),
        ("PD15", f"nesting {MAX_DEPTH + 1} containers deep", "principals_digest", _args(deep_bad)),
        ("PD16", "an empty block", "principals_digest", _args({})),
        ("PD17", "a member that is not a role", "principals_digest", _args({**b, "operator": b["user"]})),
        ("PD18", "a role that is not an object", "principals_digest", _args({**b, "agent": "agent-refunds"})),
        ("PD19", "an array, not a block", "principals_digest", _args([b["user"]])),
        ("PD20", "the out-of-domain value is reported before the malformed block", "principals_digest",
         _args({"operator": 1.5})),
        ("AC1", "the act claim of the user credential", "act_chain_digest", _args(act)),
        ("AC2", "a nested act claim, current actor first", "act_chain_digest", _args(_actors(3))),
        ("AC3", "the nested claim with members reversed: the same digest", "act_chain_digest",
         "[" + _reversed(_actors(3)) + "]"),
        ("AC4", "a missing act claim has no digest", "act_chain_digest", _args(None)),
        ("AC5", "an actor without sub", "act_chain_digest", _args({"client_id": "agent-refunds"})),
        ("AC6", "an actor with an empty sub", "act_chain_digest", _args({"sub": ""})),
        ("AC7", "a prior actor that is not an object", "act_chain_digest", _args({"sub": "a", "act": "b"})),
        ("AC8", "a null prior actor", "act_chain_digest", _args({"sub": "a", "act": None})),
        ("AC9", f"{MAX_ACTORS} actors", "act_chain_digest", _args(_actors(MAX_ACTORS))),
        ("AC10", f"{MAX_ACTORS + 1} actors", "act_chain_digest", _args(_actors(MAX_ACTORS + 1))),
        ("AC11", "a float inside the act claim", "act_chain_digest", _args({"sub": "a", "iat": 1.5})),
        ("AC12", "a principals block is not an act claim", "act_chain_digest", _args(b)),
        ("GC1", "a root grant and one narrower link, root first", "grant_chain_digest", _args(chain)),
        ("GC2", "the same chain from its grant digests alone", "grant_chain_digest_of", _args(digests)),
        ("GC3", "a float in a grant body is the body's own matter: the chain still has a digest", "grant_chain_digest",
         _args(links(9.5))),
        ("GC4", "the links in the other order are another chain", "grant_chain_digest", _args(chain[::-1])),
        ("GC5", "an empty chain", "grant_chain_digest", _args([])),
        ("GC6", "a link without a body", "grant_chain_digest", _args([{"sig": chain[0]["sig"]}])),
        ("GC7", "a chain that is not an array", "grant_chain_digest", _args(chain[0])),
        ("GC8", "a body with an integer beyond the exact JSON range", "grant_chain_digest",
         _args([{"body": {"maxDepth": MAX_SAFE_INT + 1}, "sig": ""}])),
        ("GC9", "an empty list of grant digests", "grant_chain_digest_of", _args([])),
        ("GC10", "a grant digest in upper case", "grant_chain_digest_of", _args([d.upper() for d in digests])),
        ("GC11", "a grant digest with the sha256: prefix", "grant_chain_digest_of", _args(["sha256:" + digests[0]])),
        ("SD1", "principals, act chain and grant chain", "stamp_digest", _args(p, a, g)),
        ("SD2", "no act claim and no grants: both null", "stamp_digest", _args(p, None, None)),
        ("SD3", "an act claim and no grants", "stamp_digest", _args(p, a, None)),
        ("SD4", "a principals digest in upper case", "stamp_digest", _args(p.upper(), a, g)),
        ("SD5", "a bare hex digest without the prefix", "stamp_digest", _args(p[7:], a, g)),
        ("SD6", "no principals digest", "stamp_digest", _args(None, a, g)),
        ("SD7", "a grant chain digest that is a number", "stamp_digest", _args(p, a, 7)),
        ("SS1", "a block and its grant links", "stamp_digest_of", _args(b, chain)),
        ("SS2", "a block with no act claim and no grants", "stamp_digest_of", _args(no_act, None)),
        ("SS3", "a user principal whose act member is null", "stamp_digest_of",
         _args(_with(["user", "act"], None), None)),
    ]


def vectors() -> list[dict[str, Any]]:
    return [{"id": vid, "description": description, "function": function, "input": text,
             "expected": judge(function, json.loads(text))} for vid, description, function, text in _cases()]


def check(rows: list[dict[str, Any]]) -> list[str]:
    """The ids whose recomputed outcome differs from the vector's expected outcome, or that no longer exist."""
    fresh = {v["id"]: v for v in vectors()}
    return [v["id"] for v in rows if v["id"] not in fresh or fresh[v["id"]]["expected"] != v["expected"]
            or fresh[v["id"]]["input"] != v["input"]]
