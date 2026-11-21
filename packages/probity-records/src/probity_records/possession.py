"""Proof of possession: a grant is usable only by the party that holds the key its ``cnf`` names.

Every grant names a confirmation key (RFC 7800 section 3.1) in ``cnf``, by exactly one method:

- ``jkt``: the RFC 7638 SHA-256 thumbprint of the holder's public JWK (RFC 9449 section 6.1). The holder proves
  possession on each request with a DPoP proof (RFC 9449 section 4) signed by that key.
- ``x5t#S256``: the SHA-256 thumbprint of the holder's client certificate (RFC 8705 section 3.1). The holder
  proves possession by completing mutual TLS with that certificate at the endpoint that checks the grant.

``verify_held_grant`` joins three things before it lets a call through: the grant chain is valid, the agent's
own access token is valid and is bound to the same ``cnf`` (so the grant's holder is the authenticated agent),
and the request carries a fresh proof by that key. Without all three a grant is a bearer token, so this module
refuses rather than degrades.

The DPoP checks follow RFC 9449 section 4.3 and the ANS SDK ``pop`` verifier (ans-sdk-go ``pop/``, Apache-2.0,
commit a36e0195b2dc): strict header, pinned algorithms, the content digest claim ``ans_content_digest`` so a hop
that terminates TLS cannot rewrite the body, ``ath`` if and only if a token is presented, and the ``jti``
recorded last so that only fully verified proofs spend replay-cache capacity. Two choices differ from ANS: the
accepted key is the one the issuer-signed ``cnf`` names (the header's ``jwk`` is trusted only after its
thumbprint matches), and both ES256 and EdDSA (Ed25519) are accepted.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .core import Signer
from .grants import ts, verify_call_under_grant, verify_chain
from .identity import b64url, check_principal, jwk_thumbprint, unb64url, verify_token

CNF_METHODS = ("jkt", "x5t#S256")
DPOP_TYP = "dpop+jwt"
DPOP_ALGS = ("ES256", "EdDSA")
CONTENT_DIGEST_CLAIM = "ans_content_digest"
MAX_PROOF_BYTES = 8 << 10
MAX_JTI_BYTES = 128
DEFAULT_SKEW = 120
REPLAY_GRACE = 5
_HEADER_MEMBERS = {"typ", "alg", "jwk", "x5c"}
_JWK_MEMBERS = {"ES256": ("crv", "kty", "x", "y"), "EdDSA": ("crv", "kty", "x")}
_JWK_CURVE = {"ES256": ("EC", "P-256"), "EdDSA": ("OKP", "Ed25519")}


# ---------- confirmation (cnf) ----------

def _is_digest(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 43:
        return False
    try:
        return len(unb64url(value)) == 32 and b64url(unb64url(value)) == value
    except (ValueError, TypeError):
        return False


def cnf_problem(cnf: Any) -> str | None:
    """None when ``cnf`` names exactly one confirmation method with a well-formed SHA-256 thumbprint."""
    if cnf is None:
        return "cnf_missing"
    if not isinstance(cnf, dict) or len(cnf) != 1:
        return "cnf_invalid"
    (method, value), = cnf.items()
    if method not in CNF_METHODS or not _is_digest(value):
        return "cnf_invalid"
    return None


def public_jwk(key: Any) -> dict[str, str]:
    """The public JWK of an EC P-256 or Ed25519 key (private or public), with only the RFC 7638 members."""
    if isinstance(key, Signer):
        key = key.key
    if isinstance(key, Ed25519PrivateKey | ec.EllipticCurvePrivateKey):
        key = key.public_key()
    if isinstance(key, Ed25519PublicKey):
        return {"crv": "Ed25519", "kty": "OKP", "x": b64url(key.public_bytes(Encoding.Raw, PublicFormat.Raw))}
    if isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1):
        nums = key.public_numbers()
        return {"crv": "P-256", "kty": "EC", "x": b64url(nums.x.to_bytes(32, "big")),
                "y": b64url(nums.y.to_bytes(32, "big"))}
    raise ValueError("key_unsupported")


def cnf_for_jwk(jwk: Mapping[str, Any]) -> dict[str, str]:
    return {"jkt": jwk_thumbprint(jwk)}


def cnf_for_signer(signer: Signer) -> dict[str, str]:
    """The ``cnf`` that lets the grant's Ed25519 holder key also present the grant."""
    return cnf_for_jwk(public_jwk(signer))


def cnf_for_certificate(der: bytes) -> dict[str, str]:
    return {"x5t#S256": b64url(hashlib.sha256(der).digest())}


# ---------- replay ----------

class ReplayCacheFull(Exception):
    """The cache holds only live entries and cannot record another; the proof is refused."""


class ReplayCache:
    """Single-use record of DPoP proof ids, bounded, with the clock passed in.

    ``check_and_store`` is atomic. Entries live until their proof could no longer pass the freshness check.
    The clock is an argument so an offline walker replays a journal with the records' own times.
    In-process only: several verifier instances need one shared store with the same contract.
    """

    def __init__(self, max_entries: int = 100_000) -> None:
        self._max = max_entries
        self._seen: dict[str, int] = {}
        self._lock = threading.Lock()

    def __len__(self) -> int:
        return len(self._seen)

    def check_and_store(self, key: str, *, exp: int, now: int) -> bool:
        """True when ``key`` is already recorded and live (a replay); otherwise record it until ``exp``."""
        with self._lock:
            held = self._seen.get(key)
            if held is not None and held >= now:
                return True
            if len(self._seen) >= self._max:
                self._seen = {k: e for k, e in self._seen.items() if e >= now}
                if len(self._seen) >= self._max:
                    raise ReplayCacheFull
            self._seen[key] = exp
            return False


# ---------- DPoP ----------

@dataclass(frozen=True)
class DpopProof:
    """A DPoP proof that passed every check except the single-use commit."""

    jkt: str
    jti: str
    iat: int
    replay_exp: int


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise ValueError("duplicate")
        out[k] = v
    return out


def _segment_json(segment: str) -> Any:
    raw = unb64url(segment)
    if b64url(raw) != segment:
        raise ValueError("not canonical base64url")
    return json.loads(raw, object_pairs_hook=_no_duplicates)


def normalize_htu(url: str) -> str:
    """RFC 9449 section 4.3 target URI: scheme and host lower case, default port dropped, no query or fragment,
    an empty path as ``/``. The path is otherwise compared exactly."""
    parts = urlsplit(url)
    scheme, host = parts.scheme.lower(), (parts.hostname or "").lower()
    if scheme not in ("https", "http") or not host:
        raise ValueError("htu_not_absolute")
    port = parts.port
    if port is None or (scheme, port) in (("https", 443), ("http", 80)):
        authority = host
    else:
        authority = f"{host}:{port}"
    return f"{scheme}://{authority}{parts.path or '/'}"


def _load_jwk(alg: str, jwk: Any) -> Any:
    """The public key of a JWK of exactly the shape ``alg`` takes, or ValueError naming the defect."""
    if not isinstance(jwk, dict):
        raise ValueError("dpop_jwk_invalid")
    if any(m in jwk for m in ("d", "p", "q", "dp", "dq", "qi", "k")):
        raise ValueError("dpop_jwk_private")
    kty, crv = _JWK_CURVE[alg]
    if set(jwk) != set(_JWK_MEMBERS[alg]) or jwk.get("kty") != kty or jwk.get("crv") != crv:
        raise ValueError("dpop_jwk_invalid")
    try:
        x = unb64url(jwk["x"])
        if alg == "EdDSA":
            if len(x) != 32:
                raise ValueError
            return Ed25519PublicKey.from_public_bytes(x)
        y = unb64url(jwk["y"])
        if len(x) != 32 or len(y) != 32:
            raise ValueError
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + x + y)
    except (ValueError, TypeError, KeyError) as exc:
        raise ValueError("dpop_jwk_invalid") from exc


def _verify_sig(alg: str, key: Any, signing_input: bytes, sig: bytes) -> bool:
    try:
        if alg == "EdDSA":
            key.verify(sig, signing_input)
        else:
            if len(sig) != 64:
                return False
            der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
            key.verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError):
        return False
    return True


def _x5c_problem(x5c: Any, jwk: Mapping[str, Any]) -> str | None:
    """An ``x5c`` is tolerated only as one certificate presenting the very key in ``jwk``."""
    if not isinstance(x5c, list) or len(x5c) != 1 or not isinstance(x5c[0], str):
        return "dpop_x5c_invalid"
    try:
        cert = x509.load_der_x509_certificate(base64.b64decode(x5c[0], validate=True))
        presented = public_jwk(cert.public_key())
    except (ValueError, TypeError, UnsupportedAlgorithm):
        return "dpop_x5c_invalid"
    return None if presented == dict(jwk) else "dpop_x5c_key_mismatch"


def _header(segment: str, expected_jkt: str) -> tuple[str, Any, str | None]:
    """(alg, public key, None) for a header that passes, or ("", None, refusal)."""
    try:
        h = _segment_json(segment)
    except ValueError as exc:
        return "", None, "dpop_duplicate_member" if str(exc) == "duplicate" else "dpop_malformed"
    if not isinstance(h, dict):
        return "", None, "dpop_malformed"
    if set(h) - _HEADER_MEMBERS:
        return "", None, "dpop_header_member_unknown"
    if h.get("typ") != DPOP_TYP:
        return "", None, "dpop_typ_invalid"
    alg = h.get("alg")
    if alg not in DPOP_ALGS:
        return "", None, "dpop_alg_not_allowed"
    try:
        key = _load_jwk(alg, h.get("jwk"))
    except ValueError as exc:
        return "", None, str(exc)
    if "x5c" in h:
        problem = _x5c_problem(h["x5c"], h["jwk"])
        if problem:
            return "", None, problem
    if not hmac.compare_digest(jwk_thumbprint(h["jwk"]), expected_jkt):
        return "", None, "dpop_key_not_confirmed"
    return alg, key, None


def _int_claim(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _claims_problem(p: Any, method: str, url: str, now: int, skew: int, access_token: str | None,
                    content: bytes, require_content_binding: bool) -> str | None:
    if not isinstance(p, dict):
        return "dpop_malformed"
    if p.get("htm") != method:
        return "dpop_htm_mismatch"
    try:
        if not isinstance(p.get("htu"), str) or normalize_htu(p["htu"]) != normalize_htu(url):
            return "dpop_htu_mismatch"
    except ValueError:
        return "dpop_htu_mismatch"
    if access_token is None:
        if "ath" in p:
            return "dpop_ath_unexpected"
    elif "ath" not in p:
        return "dpop_ath_missing"
    elif not isinstance(p["ath"], str) or not hmac.compare_digest(
            p["ath"], b64url(hashlib.sha256(access_token.encode("ascii")).digest())):
        return "dpop_ath_mismatch"
    if not _int_claim(p.get("iat")):
        return "dpop_malformed"
    if p["iat"] < now - skew:
        return "dpop_iat_stale"
    if p["iat"] > now + skew:
        return "dpop_iat_future"
    jti = p.get("jti")
    if not isinstance(jti, str) or not jti or len(jti.encode("utf-8")) > MAX_JTI_BYTES:
        return "dpop_jti_invalid"
    digest = p.get(CONTENT_DIGEST_CLAIM)
    if digest is None:
        return "dpop_content_unbound" if require_content_binding else None
    if not isinstance(digest, str) or not hmac.compare_digest(digest, b64url(hashlib.sha256(content).digest())):
        return "dpop_content_mismatch"
    return None


def check_dpop(proof: str, method: str, url: str, at: str, *, expected_jkt: str, access_token: str | None,
               content: bytes = b"", skew: int = DEFAULT_SKEW,
               require_content_binding: bool = True) -> tuple[DpopProof | None, str]:
    """Every RFC 9449 section 4.3 check of one proof except the single-use commit.

    ``url`` is the verifier's own external URL for the request, never one built from the client's Host
    header. ``expected_jkt`` comes from issuer-signed content (the grant's ``cnf``, the token's ``cnf``),
    never from the proof. Returns the proof or the refusal code."""
    if not isinstance(proof, str) or len(proof) > MAX_PROOF_BYTES:
        return None, "dpop_too_large" if isinstance(proof, str) else "dpop_malformed"
    parts = proof.split(".")
    if len(parts) != 3 or not all(parts):
        return None, "dpop_malformed"
    head, body, sig = parts
    alg, key, problem = _header(head, expected_jkt)
    if problem:
        return None, problem
    try:
        signature = unb64url(sig)
    except (ValueError, TypeError):
        return None, "dpop_malformed"
    if not _verify_sig(alg, key, f"{head}.{body}".encode("ascii"), signature):
        return None, "dpop_signature_unverified"
    try:
        claims = _segment_json(body)
    except ValueError as exc:
        return None, "dpop_duplicate_member" if str(exc) == "duplicate" else "dpop_malformed"
    now = int(ts(at).timestamp())
    problem = _claims_problem(claims, method, url, now, skew, access_token, content, require_content_binding)
    if problem:
        return None, problem
    return DpopProof(jkt=expected_jkt, jti=claims["jti"], iat=claims["iat"],
                     replay_exp=claims["iat"] + skew + REPLAY_GRACE), "ok"


def commit_dpop(proof: DpopProof, replay: ReplayCache, at: str) -> str:
    """Spend the proof's ``jti``: ``ok``, ``dpop_replayed`` or ``replay_cache_full``. Keyed by SHA-256 of the
    ``jti`` so the cache's size is bounded in bytes whatever the proof carried."""
    key = b64url(hashlib.sha256(proof.jti.encode("utf-8")).digest())
    try:
        seen = replay.check_and_store(key, exp=proof.replay_exp, now=int(ts(at).timestamp()))
    except ReplayCacheFull:
        return "replay_cache_full"
    return "dpop_replayed" if seen else "ok"


def verify_dpop(proof: str, method: str, url: str, at: str, replay: ReplayCache, *, expected_jkt: str,
                access_token: str | None, content: bytes = b"", skew: int = DEFAULT_SKEW,
                require_content_binding: bool = True) -> tuple[DpopProof | None, str]:
    """``check_dpop`` then the single-use commit."""
    result, reason = check_dpop(proof, method, url, at, expected_jkt=expected_jkt, access_token=access_token,
                                content=content, skew=skew, require_content_binding=require_content_binding)
    if result is None:
        return None, reason
    spent = commit_dpop(result, replay, at)
    return (result, "ok") if spent == "ok" else (None, spent)


def sign_dpop(key: Any, method: str, url: str, *, iat: int, jti: str, access_token: str | None = None,
              content: bytes | None = b"") -> str:
    """A DPoP proof by ``key`` (EC P-256 or Ed25519, or a ``Signer``) for one request. ``content`` None leaves
    the content digest claim out, which a verifier requiring content binding refuses."""
    if isinstance(key, Signer):
        key = key.key
    jwk = public_jwk(key)
    alg = "EdDSA" if jwk["kty"] == "OKP" else "ES256"
    claims: dict[str, Any] = {"htm": method, "htu": normalize_htu(url), "iat": iat, "jti": jti}
    if access_token is not None:
        claims["ath"] = b64url(hashlib.sha256(access_token.encode("ascii")).digest())
    if content is not None:
        claims[CONTENT_DIGEST_CLAIM] = b64url(hashlib.sha256(content).digest())
    head = b64url(json.dumps({"alg": alg, "jwk": jwk, "typ": DPOP_TYP}, separators=(",", ":")).encode())
    body = b64url(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{head}.{body}".encode("ascii")
    if alg == "EdDSA":
        sig = key.sign(signing_input)
    else:
        r, s = decode_dss_signature(key.sign(signing_input, ec.ECDSA(hashes.SHA256())))
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return f"{head}.{body}.{b64url(sig)}"


# ---------- mutual TLS ----------

def check_client_certificate(der: bytes | None, expected: str, at: str) -> str:
    """``ok`` when ``der`` (the certificate the TLS endpoint authenticated) has the confirmed thumbprint and is
    within its validity period at ``at``."""
    if der is None:
        return "mtls_certificate_missing"
    if not hmac.compare_digest(cnf_for_certificate(der)["x5t#S256"], expected):
        return "mtls_certificate_not_confirmed"
    try:
        cert = x509.load_der_x509_certificate(der)
    except ValueError:
        return "mtls_certificate_invalid"
    when = ts(at)
    if when < cert.not_valid_before_utc:
        return "mtls_certificate_not_yet_valid"
    if when > cert.not_valid_after_utc:
        return "mtls_certificate_expired"
    return "ok"


# ---------- a grant presented on a request ----------

@dataclass(frozen=True)
class Presentation:
    """One request presenting a grant. ``url`` is the verifier's own external URL for it; ``access_token`` is
    the agent's credential from ``Authorization``; ``dpop`` the DPoP header; ``client_certificate`` the DER
    certificate the TLS endpoint authenticated; ``content`` the request body as received."""

    method: str
    url: str
    access_token: str
    dpop: str | None = None
    client_certificate: bytes | None = None
    content: bytes = b""


def _possession(cnf: Mapping[str, str], p: Presentation, at: str, skew: int,
                require_content_binding: bool) -> tuple[DpopProof | dict[str, str] | None, str]:
    if "jkt" in cnf:
        if p.dpop is None:
            return None, "dpop_proof_missing"
        return check_dpop(p.dpop, p.method, p.url, at, expected_jkt=cnf["jkt"], access_token=p.access_token,
                          content=p.content, skew=skew, require_content_binding=require_content_binding)
    reason = check_client_certificate(p.client_certificate, cnf["x5t#S256"], at)
    return ({"method": "mtls", "x5t#S256": cnf["x5t#S256"]}, "ok") if reason == "ok" else (None, reason)


def _deny(reason: str, chain: list[Mapping[str, Any]] | None = None, digest: str | None = None) -> dict[str, Any]:
    from .grants import grant_digest

    return {"decision": "deny", "reason": reason, "grantDigest": digest,
            "chain": [grant_digest(g["body"]) for g in chain] if chain else [], "possession": None}


def verify_held_grant(chain: list[Mapping[str, Any]], tool: str, args: Any, at: str, root_key_ids: set[str], *,
                      presentation: Presentation, agent: Mapping[str, Any], jwks: Mapping[str, Any],
                      pins: Mapping[str, Any], audience: str, replay: ReplayCache,
                      revoked_grants: set[str] | None = None, key_revoked: Callable[[str, str], bool] | None = None,
                      ctx: Mapping[str, Any] | None = None, skew: int = DEFAULT_SKEW,
                      require_content_binding: bool = True) -> dict[str, Any]:
    """Decide one call presented under a grant chain: ``{"decision", "reason", "grantDigest", "chain",
    "possession"}``, ``decision`` one of ``allow``, ``needs_approval`` and ``deny``.

    The call is let through only when the chain verifies, ``agent`` is a pinned principal whose access token is
    the presented one and names ``audience``, the agent's token and the leaf grant confirm the same key, and the
    request proves possession of that key. The proof's ``jti`` is spent only for a call that is let through."""
    from .grants import grant_digest

    leaf, reason = verify_chain(list(chain), root_key_ids, at, revoked_grants, key_revoked)
    if leaf is None:
        return _deny(reason)
    digest = grant_digest(leaf)
    problem = check_principal(agent, at, pins)
    if problem:
        return _deny(f"agent_principal:{problem}", chain, digest)
    problem = verify_token(agent, presentation.access_token, jwks)
    if problem:
        return _deny(f"agent_token:{problem}", chain, digest)
    if audience not in agent["audience"]:
        return _deny("agent_token_wrong_audience", chain, digest)
    if "cnf" not in agent:
        return _deny("agent_credential_is_bearer", chain, digest)
    if agent["cnf"] != leaf["cnf"]:
        return _deny("grant_holder_is_not_the_agent", chain, digest)
    held, reason = _possession(leaf["cnf"], presentation, at, skew, require_content_binding)
    if held is None:
        return _deny(reason, chain, digest)
    verdict = verify_call_under_grant(leaf, tool, args, ctx)
    decision = {"ok": "allow", "approval_required": "needs_approval"}.get(verdict, "deny")
    if decision == "deny":
        return _deny(verdict, chain, digest)
    if isinstance(held, DpopProof):
        spent = commit_dpop(held, replay, at)
        if spent != "ok":
            return _deny(spent, chain, digest)
        held = {"method": "dpop", "jkt": held.jkt, "jti": held.jti}
    return {"decision": decision, "reason": verdict, "grantDigest": digest,
            "chain": [grant_digest(g["body"]) for g in chain], "possession": held}
