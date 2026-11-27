"""Deterministic conformance vectors for the four-principal block and ID-JAG credentials.

Every key comes from a fixed seed and every time is fixed, so the vectors are byte-identical on every
run and any verifier (this package, the TypeScript verifier) can be checked against them. Each vector
is ``{"id", "description", "at", "principals", "pins", "approvers", "tokens", "jwks", "expected"}``
where ``expected`` is ``{"problems": [...], "grade": "strict" | "basic" | "autonomous" | None, "act": ...}`` and
``tokens`` maps a role to its escrowed token for ``verify_token``. An autonomous vector (``ID17`` on) also carries
``sponsors`` (agent client id to the registered [issuer, subject] pairs, or null when none is pinned) and
``standingGrants`` (grant digest to the grant body the verifier resolved); its ``approvers`` is null when no approval
admitted the call. ``pins`` maps an issuer to its pinned thumbprints exactly as an auditor wrote them (``ID35`` writes
one as a string, which pins nothing); ``tokens`` are checked at the vector's ``at``. A vector that carries
``counted`` (``ID52`` on) gives the people the approval counted apart from ``approvers``, the people the block may
name: a deny counts nobody, so its ``counted`` is ``[]``; with no ``counted`` the two are one set.

``python -m probity_records identity-vectors`` prints them as JSON; ``check`` re-runs them.
"""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .core import Signer, sha256_hex
from .grants import grant_digest, issue_grant, raw_public
from .identity import (
    b64url,
    check_principals,
    jwk_thumbprint,
    jwks_digest,
    possession_grade,
    verify_token,
)

AT = "2026-11-08T12:00:00Z"
_AT_EPOCH = 1794139200  # AT as seconds since the epoch
IAT, EXP = _AT_EPOCH - 2400, _AT_EPOCH + 1200  # 11:20 .. 12:20 on the vectors' day
ISSUER = "https://idp.example.com/realms/agents"
# The agent's access token is DPoP-bound (RFC 9449 section 6.1) to this key's thumbprint.
AGENT_CNF = {"jkt": "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"}  # the RFC 8037 appendix A.3 key


def _iso_at(seconds: int) -> str:
    from .identity import _iso

    return _iso(seconds)


def _key(seed: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(seed.encode()).digest())


def _jwk(priv: Ed25519PrivateKey, kid: str) -> dict[str, str]:
    raw = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {"crv": "Ed25519", "kid": kid, "kty": "OKP", "x": b64url(raw)}


def _token(priv: Ed25519PrivateKey, kid: str, claims: dict[str, Any], typ: str = "JWT") -> str:
    head = b64url(json.dumps({"alg": "EdDSA", "kid": kid, "typ": typ}, separators=(",", ":")).encode())
    body = b64url(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
    return f"{head}.{body}.{b64url(priv.sign(f'{head}.{body}'.encode()))}"


def _principal(token: str, jwk: dict, jwks: dict, source: str, claims: dict) -> dict[str, Any]:
    from .identity import _iso

    p = {"audience": [claims["aud"]], "authMethod": "private_key_jwt", "clientId": claims["client_id"],
         "expiresAt": _iso(claims["exp"]), "issuedAt": _iso(claims["iat"]), "issuer": claims["iss"],
         "jwksDigest": jwks_digest(jwks), "key": jwk, "keyThumbprint": jwk_thumbprint(jwk), "kid": jwk["kid"],
         "source": source, "subject": claims["sub"], "tokenDigest": sha256_hex(token.encode())}
    for member in ("act", "cnf"):
        if member in claims:
            p[member] = copy.deepcopy(claims[member])
    return p


def base() -> dict[str, Any]:
    priv = _key("probity-identity-vectors/issuer-key-1")
    jwk = _jwk(priv, "k1")
    jwks = {"keys": [jwk]}
    specs = {
        "user": ("id-jag", "oauth-id-jag+jwt", {"sub": "alice@example.com", "client_id": "agent-refunds",
                                                "aud": "https://api.example.com", "act": {"sub": "agent-refunds"}}),
        "agent": ("jwt-access-token", "at+jwt", {"sub": "agent-refunds", "client_id": "agent-refunds",
                                                 "aud": "https://api.example.com", "cnf": dict(AGENT_CNF)}),
        "sponsor": ("id-token", "JWT", {"sub": "owner@example.com", "client_id": "console",
                                        "aud": "console"}),
        "approver": ("id-token", "JWT", {"sub": "bob@example.com", "client_id": "console", "aud": "console"}),
    }
    principals, tokens = {}, {}
    for role, (source, typ, extra) in specs.items():
        claims = {"iss": ISSUER, "iat": IAT, "exp": EXP, "jti": f"jti-{role}", **extra}
        tokens[role] = _token(priv, "k1", claims, typ)
        principals[role] = _principal(tokens[role], dict(jwk), jwks, source, claims)
    return {"at": AT, "principals": principals, "pins": {ISSUER: [jwk_thumbprint(jwk)]},
            "approvers": ["bob@example.com"], "tokens": tokens, "jwks": jwks}


def second_approver() -> tuple[dict[str, Any], str]:
    """A second approver, ``carol@example.com``, signed in at the same issuer as ``bob@example.com``: her principal
    and her escrowed ID token. ``base`` keeps one approver, so every vector before ``ID41`` keeps its bytes."""
    priv = _key("probity-identity-vectors/issuer-key-1")
    jwk = _jwk(priv, "k1")
    claims = {"iss": ISSUER, "iat": IAT, "exp": EXP, "jti": "jti-approver-2", "sub": "carol@example.com",
              "client_id": "console", "aud": "console"}
    token = _token(priv, "k1", claims, "JWT")
    return _principal(token, dict(jwk), {"keys": [jwk]}, "id-token", claims), token


def _approvers(v: dict[str, Any], *who: str, counted: tuple[str, ...] | None = ("bob@example.com", "carol@example.com"),
               ) -> None:  # fmt: skip
    """Name the approvers ``who`` (``bob`` or ``carol``) as a list, with their tokens in the same order, and set the
    approvals counted (None when no approval admitted the call)."""
    carol, carol_token = second_approver()
    own = {"bob": (v["principals"]["approver"], v["tokens"]["approver"]), "carol": (carol, carol_token)}
    v["principals"]["approver"] = [copy.deepcopy(own[w][0]) for w in who]
    v["tokens"]["approver"] = [own[w][1] for w in who]
    v["approvers"] = None if counted is None else list(counted)


def _mut(vid: str, description: str, fn) -> dict[str, Any]:
    v = base()
    fn(v)
    return {"id": vid, "description": description, **v}


SPONSOR_REF = [ISSUER, "owner@example.com"]
GRANT_NB = _AT_EPOCH - 1800  # 11:30: the sponsor's credential (11:20 .. 12:20) was live when the grant was issued


def _standing(*, review: int = _AT_EPOCH + 43200, expires: int = _AT_EPOCH + 129600, cnf: dict | None = None,
              sponsor: list[str] = SPONSOR_REF) -> dict[str, Any]:
    """A standing grant for the agent, signed by a fixed grant root: deterministic bytes (Ed25519 is)."""
    root = Signer(_key("probity-identity-vectors/grant-root"))
    holder = raw_public(Signer(_key("probity-identity-vectors/agent-holder")))
    return issue_grant(root, grant_id="standing-refunds-nightly", holder_key=holder, cnf=cnf or dict(AGENT_CNF),
                       tools={"refund": {"args": {"amount_cents": {"type": "range", "min": 1, "max": 5000}}}},
                       not_before=_iso_at(GRANT_NB), expires_at=_iso_at(expires),
                       sponsor={"issuer": sponsor[0], "subject": sponsor[1]}, review_by=_iso_at(review))["body"]


def autonomous_record_parts() -> dict[str, Any]:
    """What a journal of autonomous records needs, deterministic: the autonomous block (``_auto``'s), the signed
    standing grant it names, a broad plain grant the same agent key holds (no sponsor, no review date), the grant
    root's key id, the identity pins and the sponsor registry. The shared journal vectors are built from these."""
    v = _auto("parts", "parts")
    root = Signer(_key("probity-identity-vectors/grant-root"))
    holder = raw_public(Signer(_key("probity-identity-vectors/agent-holder")))
    common = {"holder_key": holder, "cnf": dict(AGENT_CNF), "not_before": _iso_at(GRANT_NB),
              "expires_at": _iso_at(_AT_EPOCH + 129600)}
    standing = issue_grant(root, grant_id="standing-refunds-nightly",
                           tools={"refund": {"args": {"amount_cents": {"type": "range", "min": 1, "max": 5000}}}},
                           sponsor={"issuer": SPONSOR_REF[0], "subject": SPONSOR_REF[1]},
                           review_by=_iso_at(_AT_EPOCH + 43200), **common)  # fmt: skip
    if grant_digest(standing["body"]) != v["principals"]["standingGrant"]:
        raise AssertionError("the signed standing grant is not the one the autonomous block names")
    plain = issue_grant(root, grant_id="broad-refunds", tools={"refund": {"args": {"amount_cents": {"type": "wildcard"}}},
                                                               "wire": {"args": {"to": {"type": "wildcard"}}}},
                        **common)  # fmt: skip
    return {"at": AT, "principals": v["principals"], "pins": v["pins"], "sponsors": v["sponsors"],
            "standing": standing, "plain": plain, "root": root.key_id}


def _auto(vid: str, description: str, fn=None, **grant: Any) -> dict[str, Any]:
    """An autonomous block: the agent, the sponsor (as presented at the grant's issue), the session, the grant."""
    v = base()
    body = _standing(**grant)
    p = v["principals"]
    v["principals"] = {"agent": p["agent"], "sponsor": p["sponsor"],
                       "session": {"id": "run-2026-11-08-nightly", "startedAt": _iso_at(_AT_EPOCH - 600)},
                       "standingGrant": grant_digest(body)}
    v["tokens"] = {r: v["tokens"][r] for r in ("agent", "sponsor")}
    v["approvers"] = None
    v["sponsors"] = {"agent-refunds": [list(SPONSOR_REF)]}
    v["standingGrants"] = {grant_digest(body): body}
    if fn is not None:
        fn(v)
    return {"id": vid, "description": description, **v}


def _resign_sponsor(v: dict[str, Any], iat: int) -> None:
    """Re-mint the sponsor's ID token with another iat: valid at the record's time, not at the grant's issue."""
    priv, jwk = _key("probity-identity-vectors/issuer-key-1"), v["jwks"]["keys"][0]
    claims = {"iss": ISSUER, "iat": iat, "exp": EXP, "jti": "jti-sponsor", "sub": "owner@example.com",
              "client_id": "console", "aud": "console"}
    v["tokens"]["sponsor"] = _token(priv, "k1", claims, "JWT")
    v["principals"]["sponsor"] = _principal(v["tokens"]["sponsor"], dict(jwk), v["jwks"], "id-token", claims)


def _autonomous_vectors() -> list[dict[str, Any]]:
    approver = base()["principals"]["approver"]
    return [
        _auto("ID17", "autonomous: agent, registered sponsor, standing grant held by the agent, session; no approval"),
        _auto("ID18", "autonomous with the approver whose approval admitted the call",
              lambda v: (v["principals"].__setitem__("approver", approver),
                         v.__setitem__("approvers", ["bob@example.com"]))),
        _auto("ID19", "autonomous with no sponsor", lambda v: v["principals"].pop("sponsor")),
        _auto("ID20", "autonomous sponsor not registered for this agent",
              lambda v: v.__setitem__("sponsors", {"agent-refunds": [[ISSUER, "carol@example.com"]]})),
        _auto("ID21", "standing grant expired at the record time",
              review=_AT_EPOCH - 1200, expires=_AT_EPOCH - 600),
        _auto("ID22", "standing grant past its review date", review=_AT_EPOCH - 900),
        _auto("ID23", "a user credential smuggled into an autonomous block",
              lambda v: v["principals"].__setitem__("user", base()["principals"]["user"])),
        _auto("ID24", "autonomous with no session", lambda v: v["principals"].pop("session")),
        _auto("ID25", "standing grant confirms a key other than the agent's",
              cnf={"jkt": "A" * 42 + "E"}),
        _auto("ID26", "standing grant names another sponsor", sponsor=[ISSUER, "carol@example.com"]),
        _auto("ID27", "standing grant the verifier never resolved",
              lambda v: v.__setitem__("standingGrants", {})),
        _auto("ID28", "no sponsor registry pinned", lambda v: v.__setitem__("sponsors", None)),
        _auto("ID29", "session starts after the record",
              lambda v: v["principals"]["session"].__setitem__("startedAt", _iso_at(_AT_EPOCH + 1))),
        _auto("ID30", "approver present when no approval admitted the call",
              lambda v: v["principals"].__setitem__("approver", approver)),
        _auto("ID31", "sponsor credential live at the record time but not when the grant was issued",
              lambda v: _resign_sponsor(v, GRANT_NB + 60)),
        _auto("ID32", "no approver when an approval admitted the call",
              lambda v: v.__setitem__("approvers", ["bob@example.com"])),
        _auto("ID33", "session id with a space", lambda v: v["principals"]["session"].__setitem__("id", "run 1")),
        _auto("ID34", "agent credential is a bearer token (no cnf)", lambda v: _bearer_agent(v)),
    ]


def _many_approver_vectors() -> list[dict[str, Any]]:
    """``approver`` as a list of at least two principals: an approval two people gave, each a counted signer."""
    def bad_thumbprint(v: dict[str, Any]) -> None:
        _approvers(v, "bob", "carol")
        v["principals"]["approver"][1]["keyThumbprint"] = "A" * 43

    def not_an_object(v: dict[str, Any]) -> None:
        _approvers(v, "bob", "carol")
        v["principals"]["approver"][1] = "carol@example.com"

    def autonomous(*who: str) -> Any:
        """An autonomous block whose approval two people gave, naming ``who`` (one name: the single form)."""
        def fn(v: dict[str, Any]) -> None:
            b = base()
            v["principals"]["approver"], v["tokens"]["approver"] = b["principals"]["approver"], b["tokens"]["approver"]
            if len(who) > 1:
                _approvers(v, *who)
            else:
                v["approvers"] = ["bob@example.com", "carol@example.com"]
        return fn

    def deny_names_both(v: dict[str, Any]) -> None:
        _approvers(v, "bob", "carol")
        v["counted"] = []

    return [
        _mut("ID41", "two approvers, both counted signers of the approval, named as a list: strict",
             lambda v: _approvers(v, "bob", "carol")),
        _mut("ID42", "two approvals counted, the block names one approver: basic, approvers-partial",
             lambda v: v.__setitem__("approvers", ["bob@example.com", "carol@example.com"])),
        _mut("ID43", "an approver list names the same person twice", lambda v: _approvers(v, "bob", "bob")),
        _mut("ID44", "an approver list of one: one approval takes the single form", lambda v: _approvers(v, "bob")),
        _mut("ID45", "an approver list names a person whose approval was not counted",
             lambda v: _approvers(v, "bob", "carol", counted=("bob@example.com",))),
        _mut("ID46", "an approver list member whose thumbprint does not recompute from its key", bad_thumbprint),
        _mut("ID47", "an approver list member that is not a principal object", not_an_object),
        _mut("ID48", "an approver list when no approval admitted the call",
             lambda v: _approvers(v, "bob", "carol", counted=None)),
        _auto("ID49", "autonomous with both approvers its approval counted, named as a list",
              autonomous("bob", "carol")),
        _auto("ID50", "autonomous names one of the two approvers its approval counted", autonomous("bob")),
        _mut("ID51", "an empty approver list", lambda v: _approvers(v)),
        _mut("ID52", "a deny resting on two people's bindings names one of them: a deny counts nobody, strict",
             lambda v: (v.__setitem__("approvers", ["bob@example.com", "carol@example.com"]),
                        v.__setitem__("counted", []))),
        _mut("ID53", "a deny resting on two people's bindings names both as a list: strict", deny_names_both),
        _auto("ID54", "autonomous deny resting on two people's bindings names one of them: autonomous",
              lambda v: (autonomous("bob")(v), v.__setitem__("counted", []))),
        _mut("ID55", "the approver list written in the other order: the verdict is the same, strict",
             lambda v: _approvers(v, "carol", "bob")),
    ]


def _bearer_agent(v: dict[str, Any]) -> None:
    priv, jwk = _key("probity-identity-vectors/issuer-key-1"), v["jwks"]["keys"][0]
    claims = {"iss": ISSUER, "iat": IAT, "exp": EXP, "jti": "jti-agent", "sub": "agent-refunds",
              "client_id": "agent-refunds", "aud": "https://api.example.com"}
    v["tokens"]["agent"] = _token(priv, "k1", claims, "at+jwt")
    v["principals"]["agent"] = _principal(v["tokens"]["agent"], dict(jwk), v["jwks"], "jwt-access-token", claims)


def _agent_not_before(v: dict[str, Any]) -> None:
    """The agent's access token carries ``nbf`` one minute after the record's time."""
    priv, jwk = _key("probity-identity-vectors/issuer-key-1"), v["jwks"]["keys"][0]
    claims = {"iss": ISSUER, "iat": IAT, "exp": EXP, "nbf": _AT_EPOCH + 60, "jti": "jti-agent", "sub": "agent-refunds",
              "client_id": "agent-refunds", "aud": "https://api.example.com", "cnf": dict(AGENT_CNF)}
    v["tokens"]["agent"] = _token(priv, "k1", claims, "at+jwt")
    v["principals"]["agent"] = _principal(v["tokens"]["agent"], dict(jwk), v["jwks"], "jwt-access-token", claims)


def _pin_as_string(v: dict[str, Any]) -> None:
    """The issuer's pin written as one string that holds the real thumbprint between other characters."""
    v["pins"] = {ISSUER: "x" + v["pins"][ISSUER][0] + "x"}


def vectors() -> list[dict[str, Any]]:
    out = [
        _mut("ID1", "four principals, user credential names the agent in act: strict", lambda v: None),
        _mut("ID2", "no act on the user credential: accepted, graded basic, act-absent",
             lambda v: v["principals"]["user"].pop("act")),
        _mut("ID3", "no sponsor: accepted, basic", lambda v: v["principals"].pop("sponsor")),
        _mut("ID4", "thumbprint does not recompute from the key",
             lambda v: v["principals"]["agent"].__setitem__("keyThumbprint", "A" * 43)),
        _mut("ID5", "credential expired at the record time",
             lambda v: v.__setitem__("at", _iso_at(EXP))),
        _mut("ID6", "issuer missing", lambda v: v["principals"]["user"].pop("issuer")),
        _mut("ID7", "issuer not pinned by the auditor", lambda v: v.__setitem__("pins", {})),
        _mut("ID8", "key not pinned for the issuer", lambda v: v.__setitem__("pins", {ISSUER: ["B" * 43]})),
        _mut("ID9", "act names an agent other than the agent principal",
             lambda v: v["principals"]["user"].__setitem__("act", {"sub": "agent-payroll"})),
        _mut("ID10", "approver principal did not sign an approval",
             lambda v: v.__setitem__("approvers", ["carol@example.com"])),
        _mut("ID11", "kid differs from the key", lambda v: v["principals"]["agent"].__setitem__("kid", "k2")),
        _mut("ID12", "private member in the key",
             lambda v: v["principals"]["agent"]["key"].__setitem__("d", "AA")),
        _mut("ID13", "credential not yet valid", lambda v: v.__setitem__("at", _iso_at(IAT - 1))),
        _mut("ID14", "agent principal missing", lambda v: v["principals"].pop("agent")),
        _mut("ID15", "agent cnf names two confirmation methods",
             lambda v: v["principals"]["agent"]["cnf"].__setitem__("x5t#S256", "A" * 43)),
        _mut("ID16", "agent cnf thumbprint is not a SHA-256 digest",
             lambda v: v["principals"]["agent"].__setitem__("cnf", {"jkt": "short"})),
    ]
    out += _autonomous_vectors()
    out += [
        _mut("ID35", "the issuer's pin is written as a string that contains the thumbprint", _pin_as_string),
        _mut("ID36", "the user principal states an access token, its token is an identity assertion grant",
             lambda v: v["principals"]["user"].__setitem__("source", "jwt-access-token")),
        _mut("ID37", "the agent's token is not valid before a time after the record", _agent_not_before),
        _mut("ID38", "no approval admitted the call and the block names no approver: strict",
             lambda v: (v["principals"].pop("approver"), v.__setitem__("approvers", None))),
        _mut("ID39", "the block names an approver but no approval admitted the call",
             lambda v: v.__setitem__("approvers", None)),
        _mut("ID40", "an approval admitted the call and the block does not name the approver: basic",
             lambda v: v["principals"].pop("approver")),
    ]
    out += _many_approver_vectors()
    for v in out:
        approvers = None if v["approvers"] is None else set(v["approvers"])
        counted = None if v.get("counted") is None else set(v["counted"])
        sponsors = v.get("sponsors")
        problems, grade = check_principals(v["principals"], v["at"], v["pins"],
                                           approvers, counted=counted,
                                           sponsors=None if sponsors is None else
                                           {a: frozenset(map(tuple, s)) for a, s in sponsors.items()},
                                           standing_grants=v.get("standingGrants"))  # fmt: skip
        token_checks = {role: _token_check(p, v["tokens"][role], v["jwks"], v["at"])
                        for role, p in v["principals"].items() if role in v["tokens"]}
        v["expected"] = {"problems": problems, "grade": grade,  # an autonomous block has no user: act-absent
                         "act": "act-chain" if "act" in v["principals"].get("user", {}) else "act-absent",
                         "possession": possession_grade(v["principals"]),
                         "tokens": token_checks}
    return copy.deepcopy(out)


def _token_check(p: Any, token: Any, jwks: dict[str, Any], at: str) -> Any:
    """``verify_token`` for one principal, or a list of its outcomes for an approver list (a member that is not an
    object has no token to check: None)."""
    if isinstance(p, list):
        return [verify_token(m, t, jwks, at=at) if isinstance(m, dict) else None for m, t in zip(p, token, strict=True)]
    return verify_token(p, token, jwks, at=at)


def check(vs: list[dict[str, Any]]) -> list[str]:
    """The ids whose recomputed outcome differs from the vector's expected outcome."""
    fresh = {v["id"]: v["expected"] for v in vectors()}
    return [v["id"] for v in vs if fresh.get(v["id"]) != v["expected"]]


# --- standing grants: chains every verifier must judge alike ----------------------------------------------------

_STANDING_TOOLS = {"refund": {"args": {"amount_cents": {"type": "range", "min": 1, "max": 5000},
                                       "note": {"type": "pattern", "pattern": "ticket-*"}}}}


def _signed(issuer: Signer, body: dict[str, Any]) -> dict[str, Any]:
    """A grant signed over any body, the narrowing proof skipped: what a forger who holds the parent's key sends."""
    from .core import _b64, canonical
    from .grants import GRANT_DOMAIN

    return {"body": body, "sig": _b64(issuer.sign(GRANT_DOMAIN + canonical(body)))}


def standing_grant_vectors() -> list[dict[str, Any]]:
    """``{"id", "description", "chain", "roots", "at", "tool", "args", "expected": {"decision", "reason",
    "grantDigest", "digests"}}``: ``expected`` is ``grants.verify_grant_allow`` (decision, reason, grantDigest) and
    the digests ``grants.chain_digests`` resolves (empty when the chain does not verify)."""
    from .grants import chain_digests, verify_grant_allow

    root = Signer(_key("probity-identity-vectors/grant-root"))
    holder = Signer(_key("probity-identity-vectors/agent-holder"))
    child_holder = Signer(_key("probity-identity-vectors/child-holder"))
    sponsor = {"issuer": ISSUER, "subject": "owner@example.com"}
    nb, review, exp = _iso_at(GRANT_NB), _iso_at(_AT_EPOCH + 3600), _iso_at(_AT_EPOCH + 86400)
    parent = issue_grant(root, grant_id="standing", holder_key=raw_public(holder), cnf=dict(AGENT_CNF),
                         tools=_STANDING_TOOLS, not_before=nb, expires_at=exp, max_depth=1, sponsor=sponsor,
                         review_by=review)
    child_body = {**parent["body"], "grantId": "child", "issuerKey": raw_public(holder),
                  "holderKey": raw_public(child_holder), "parent": grant_digest(parent["body"]), "maxDepth": 0,
                  "reviewBy": _iso_at(_AT_EPOCH + 1800)}
    child = _signed(holder, child_body)
    args = {"amount_cents": 40, "note": "ticket-7"}
    plain = {k: v for k, v in parent["body"].items() if k not in ("sponsor", "reviewBy")}
    rows = [
        ("SG1", "standing grant inside its window and before review", [parent], AT),
        ("SG2", "standing grant at its review date", [parent], _iso_at(_AT_EPOCH + 3600)),
        ("SG3", "child reviews earlier: refused from the child's review date", [parent, child],
         _iso_at(_AT_EPOCH + 1800)),
        ("SG4", "child keeps sponsor, earlier review: allowed before it", [parent, child], AT),
        ("SG5", "forged child that swaps the sponsor",
         [parent, _signed(holder, {**child_body, "sponsor": {**sponsor, "subject": "mallory@example.com"}})], AT),
        ("SG6", "forged child that reviews later than its parent",
         [parent, _signed(holder, {**child_body, "reviewBy": _iso_at(_AT_EPOCH + 7200)})], AT),
        ("SG7", "forged child that drops the sponsor and review date",
         [parent, _signed(holder, {k: v for k, v in child_body.items() if k not in ("sponsor", "reviewBy")})], AT),
        ("SG8", "a sponsor without a review date", [_signed(root, {**plain, "sponsor": sponsor})], AT),
        ("SG9", "a review date after the grant expires",
         [_signed(root, {**plain, "sponsor": sponsor, "reviewBy": _iso_at(_AT_EPOCH + 90000)})], AT),
        ("SG10", "a sponsor whose issuer carries a fragment",
         [_signed(root, {**plain, "sponsor": {**sponsor, "issuer": ISSUER + "#x"}, "reviewBy": review})], AT),
        ("SG11", "forged child that drops an argument its parent constrains (a call without it is unbounded)",
         [parent, _signed(holder, {**child_body, "tools": {"refund": {"args": {
             "amount_cents": {"type": "range", "min": 1, "max": 5000}}}}})], AT),
        ("SG12", "a delegate of a plain grant names a sponsor: only the pinned root says who answers",
         [_signed(root, plain), _signed(holder, {**child_body, "parent": grant_digest(plain)})], AT),
    ]
    out = []
    for vid, description, chain, at in rows:
        verdict = verify_grant_allow(copy.deepcopy(chain), "refund", args if vid != "SG11" else {"amount_cents": 40},
                                     at, {root.key_id})  # fmt: skip
        out.append({"id": vid, "description": description, "chain": copy.deepcopy(chain), "roots": [root.key_id],
                    "at": at, "tool": "refund", "args": args if vid != "SG11" else {"amount_cents": 40},
                    "expected": {"decision": verdict["decision"], "reason": verdict["reason"],
                                 "grantDigest": verdict["grantDigest"],
                                 "digests": sorted(chain_digests(copy.deepcopy(chain), {root.key_id}))}})
    return out
