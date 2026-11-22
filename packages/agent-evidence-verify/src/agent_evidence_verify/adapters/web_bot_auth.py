"""``web_bot_auth/v1``: was this HTTP request signed, under Web Bot Auth, by the agent the consumer pinned?

Web Bot Auth is HTTP Message Signatures (RFC 9421) as profiled by ``draft-ietf-webbotauth-httpsig-protocol-01``:
a ``Signature-Agent`` header names the signer's key directory, and the signature carries ``created``,
``expires``, ``keyid`` and ``tag="web-bot-auth"``. The claim is checked offline from three things the
case binds and one set of values the consumer pins:

* ``request``: the request as the verifier received it (method, target URI, header lines);
* ``body``: its body bytes, when it had any;
* ``directory``: the key directory (a JWK set) the consumer trusts for the signer.

The verifying key comes only from the pinned directory (the consumer pins its SHA-256 in
``directory_sha256``). The request's ``keyid`` chooses among the directory's keys and nothing else: a key,
algorithm or directory URL the request names is never fetched or trusted. ``keyid`` must equal the key's RFC 7638
thumbprint, which is recomputed. Only Ed25519 is read, and the request's ``alg`` parameter, when present, must
say so.

The checks run in this order, and the first that fails names the reason:

1. The signature is chosen (the consumer's ``label``, else the first whose ``tag`` is ``web-bot-auth``) and its
   parameters are read; ``created``, ``expires`` and ``keyid`` are required.
2. The covered components include ``signature-agent`` (as a Dictionary member) and ``@authority`` or
   ``@target-uri``, plus every component the consumer requires. The covered ``Signature-Agent`` member is
   the URL the consumer pinned in ``signature_agent``, and the request was for the authority the consumer
   serves (``authority``): a signature made for another host or another signer is ``contradicted``.
3. The signature is current at the consumer's instant ``at`` (``expires`` ahead, ``created`` not ahead of it by
   more than 60 s), within the consumer's ``max_age_seconds`` and ``max_validity_seconds`` when pinned.
4. A body is covered. When the request has a body, the signature must cover ``content-digest`` and the header
   must equal the digest of the received body (RFC 9421 section 7.2.8 names the substitution attack that
   verifying the signature alone does not stop; RFC 9530 defines the header). When ``content-digest`` is covered
   and no body is bound, the body is taken to be empty.
5. The key is in the pinned directory (otherwise ``not_established``: a stale pin is not a forgery), is not
   a published test key unless the consumer says it is testing, and verifies the signature base RFC 9421
   section 2.5 defines.

``supported`` means the pinned directory's key signed this request, for this authority, inside its validity, over
the body that arrived. It does not establish that the request was not replayed inside that window (this adapter keeps no
state; a gateway that wants one-use admission keeps its own record of the signature's ``nonce`` or digest), who
holds the key, or that the directory is the signer's own. A request that is not a well-formed capture, or a
policy that is not, raises :class:`CaseError`; a malformed signature header on a well-formed capture is
``contradicted``.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, quote, urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .. import strictb64
from ..common import CaseError, _digest, _instant, _string
from ..ijson import IJSONError, parse_ijson
from . import _sf as sf
from .bound_records import assessment_for, bound, decision

CLAIM_TYPE = "web_bot_auth/v1"
TAG = "web-bot-auth"
#: RFC 9421 Appendix B.1.4's published Ed25519 key, which the Web Bot Auth drafts' test vectors also use.
KNOWN_TEST_KEYS_X = frozenset({"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"})
MAX_SKEW_SECONDS = 60
MAX_HEADERS = 256
MAX_FIELD_BYTES = 16 * 1024
DIGESTS: dict[str, Callable[[bytes], bytes]] = {
    "sha-256": lambda body: hashlib.sha256(body).digest(),
    "sha-512": lambda body: hashlib.sha512(body).digest(),
}
LIMIT = ("Checks that the pinned directory's key signed this request, for the authority the consumer serves, "
         "inside the signature's validity and over the body that arrived. It keeps no state, so it does not "
         "establish that the request was not replayed inside that window, who holds the key, or that the directory "
         "is the signer's own.")

REQUIRED = {"request", "directory", "directory_sha256", "signature_agent", "authority", "at"}
OPTIONAL = {"body", "label", "required_components", "max_age_seconds", "max_validity_seconds", "allow_test_keys"}


class _Fail(Exception):
    """A check that stops the run: ``decision`` and ``reason`` are the verdict."""

    def __init__(self, verdict: str, reason: str, detail: str) -> None:
        super().__init__(detail)
        self.verdict, self.reason, self.detail = verdict, reason, detail


def _contradicted(reason: str, detail: str) -> _Fail:
    return _Fail("contradicted", reason, detail)


# -- the captured request ------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Request:
    """The request as the verifier received it. ``headers`` keeps every line, in order."""

    method: str
    url: str
    headers: tuple[tuple[str, str], ...]

    def field_value(self, name: str) -> str | None:
        """RFC 9421 section 2.1: every line of the field, trimmed, joined with a comma and a space."""
        values = [v.strip(" \t") for n, v in self.headers if n.lower() == name.lower()]
        return ", ".join(values) if values else None


_TCHAR = frozenset("!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")


def _field_name(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or not set(value) <= _TCHAR:
        raise CaseError(f"{label}: expected an HTTP field name")
    return value


def _field_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or len(value.encode("utf-8")) > MAX_FIELD_BYTES:
        raise CaseError(f"{label}: expected a field value of at most {MAX_FIELD_BYTES} bytes")
    if any(c in value for c in "\r\n\0"):
        raise CaseError(f"{label}: a field value holds a line break or NUL")
    return value


def _request(raw: bytes) -> Request:
    try:
        obj = parse_ijson(raw, integers_only=True)
    except IJSONError as error:
        raise CaseError("request: not strict UTF-8 JSON") from error
    if not isinstance(obj, dict) or set(obj) != {"method", "url", "headers"}:
        raise CaseError("request: expected exactly method, url and headers")
    method = _field_name(obj["method"], "request.method")
    url = _string(obj["url"], "request.url")
    try:
        parts = urlsplit(url)
        parts.port  # noqa: B018 - reading it raises ValueError on an invalid port
    except ValueError as error:
        raise CaseError("request.url: not a URL") from error
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.fragment or parts.username is not None:
        raise CaseError("request.url: expected an absolute http or https target URI without a fragment or credentials")
    headers = obj["headers"]
    if not isinstance(headers, list) or len(headers) > MAX_HEADERS:
        raise CaseError(f"request.headers: expected a list of at most {MAX_HEADERS} [name, value] pairs")
    lines = []
    for index, pair in enumerate(headers):
        if not isinstance(pair, list) or len(pair) != 2:
            raise CaseError(f"request.headers[{index}]: expected a [name, value] pair")
        lines.append((_field_name(pair[0], f"request.headers[{index}][0]"),
                      _field_text(pair[1], f"request.headers[{index}][1]")))
    return Request(method, url, tuple(lines))


# -- the pinned key directory --------------------------------------------------------------------------------


def jwk_thumbprint(key: dict[str, Any]) -> str:
    """RFC 7638 thumbprint of an OKP key (RFC 8037 Appendix A.3), base64url without padding."""
    required = {"crv": key.get("crv"), "kty": key.get("kty"), "x": key.get("x")}
    canonical = json.dumps(required, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(hashlib.sha256(canonical).digest()).decode("ascii").rstrip("=")


def _directory(raw: bytes) -> dict[str, dict[str, Any]]:
    """The Ed25519 keys of the pinned directory, by ``kid``; a key whose label is not its thumbprint is refused."""
    try:
        obj = parse_ijson(raw, integers_only=True)
    except IJSONError as error:
        raise CaseError("directory: not strict UTF-8 JSON") from error
    if not isinstance(obj, dict) or not isinstance(obj.get("keys"), list):
        raise CaseError("directory: expected a JWK set, an object with a keys list")
    keys: dict[str, dict[str, Any]] = {}
    for index, key in enumerate(obj["keys"]):
        label = f"directory.keys[{index}]"
        if not isinstance(key, dict):
            raise CaseError(f"{label}: expected an object")
        if key.get("kty") != "OKP" or key.get("crv") != "Ed25519":
            continue  # a key of another algorithm: never read, never an error
        x, kid = _string(key.get("x"), f"{label}.x"), _string(key.get("kid"), f"{label}.kid")
        try:
            if len(strictb64.url(x)) != 32:
                raise ValueError("an Ed25519 public key is 32 bytes")
        except ValueError as error:
            raise CaseError(f"{label}.x: not a canonical base64url Ed25519 key") from error
        if jwk_thumbprint(key) != kid:
            raise CaseError(f"{label}.kid: is not the key's RFC 7638 thumbprint")
        if kid in keys:
            raise CaseError(f"{label}.kid: repeated")
        keys[kid] = key
    return keys


# -- RFC 9421 section 2: the signature base ------------------------------------------------------------------


def _authority(url: str) -> str:
    """The ``@authority`` of a target URI: lowercase host, and the port unless it is the scheme's default."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if ":" in host:
        host = f"[{host}]"
    default = {"http": 80, "https": 443}[parts.scheme]
    port = parts.port
    return f"{host}:{port}" if port not in (None, default) else host


def _no_params(name: str, params: dict[str, sf.BareItem]) -> None:
    if params:
        raise _contradicted("signature_base_invalid", f"{name} takes no parameters")


def _derived(request: Request, name: str, params: dict[str, sf.BareItem]) -> str:
    parts = urlsplit(request.url)
    if name == "@query-param":
        wanted = params.get("name")
        if not isinstance(wanted, str) or set(params) != {"name"}:
            raise _contradicted("signature_base_invalid", "@query-param needs exactly one parameter, name")
        found = [v for k, v in parse_qsl(parts.query, keep_blank_values=True) if k == wanted]
        if len(found) != 1:
            raise _contradicted("signature_base_invalid", f"@query-param {wanted!r} occurs {len(found)} times")
        return quote(found[0], safe="")
    values = {
        "@method": lambda: request.method.upper(),
        "@target-uri": lambda: request.url,
        "@authority": lambda: _authority(request.url),
        "@scheme": lambda: parts.scheme.lower(),
        "@request-target": lambda: (parts.path or "/") + (f"?{parts.query}" if parts.query else ""),
        "@path": lambda: parts.path or "/",
        "@query": lambda: f"?{parts.query}",
    }
    if name not in values:
        raise _contradicted("signature_base_invalid", f"derived component {name!r} is not supported")
    _no_params(name, params)
    return values[name]()


def _field(request: Request, name: str, params: dict[str, sf.BareItem]) -> str:
    if name != name.lower():
        raise _contradicted("signature_base_invalid", f"field name {name!r} must be lowercase")
    unknown = set(params) - {"key", "sf"}
    if unknown:
        raise _contradicted("signature_base_invalid", f"field parameter(s) {sorted(unknown)} are not supported")
    value = request.field_value(name)
    if value is None:
        raise _contradicted("component_not_covered", f"the request has no {name} field")
    try:
        if "key" in params:
            key = params["key"]
            if not isinstance(key, str) or isinstance(key, sf.Token):
                raise sf.SFError("the key parameter must be a String")
            members = sf.parse_dictionary(value)
            if key not in members:
                raise sf.SFError(f"no member {key!r}")
            return sf.serialize_member(members[key])
        if "sf" in params:
            return value if value.startswith("(") else sf.serialize_member(sf.parse_item(value))
    except sf.SFError as error:
        raise _contradicted("signature_base_invalid", f"{name} is not the Structured Field its parameter says: {error}") from error
    return value


def signature_base(request: Request, inner: sf.InnerList) -> str:
    """The signature base for the label's Signature-Input member over ``request`` (RFC 9421 section 2.5)."""
    lines: list[str] = []
    seen: set[str] = set()
    for item in inner.items:
        identifier = sf.serialize_item(item)
        if identifier in seen:
            raise _contradicted("signature_base_invalid", f"component {identifier} is covered twice")
        seen.add(identifier)
        if not isinstance(item.value, str) or isinstance(item.value, sf.Token):
            raise _contradicted("signature_base_invalid", f"component identifier {identifier} is not a String")
        derive = _derived if item.value.startswith("@") else _field
        lines.append(f"{identifier}: {derive(request, item.value, item.params)}")
    lines.append(f'"@signature-params": {sf.serialize_inner_list(inner)}')
    base = "\n".join(lines)
    if not base.isascii():
        raise _contradicted("signature_base_invalid", "the signature base is not ASCII")
    return base


# -- the signature headers ------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Signature:
    label: str
    inner: sf.InnerList
    signature: bytes
    created: int
    expires: int
    keyid: str
    agent_member: str
    components: tuple[str, ...]


def _dictionary(request: Request, name: str, absent: str = "signature_absent") -> dict[str, sf.Member]:
    raw = request.field_value(name)
    if raw is None:
        raise _contradicted(absent, f"the request carries no {name} header")
    try:
        return sf.parse_dictionary(raw)
    except sf.SFError as error:
        raise _contradicted("signature_headers_malformed", f"{name}: {error}") from error


def _chosen(request: Request, label: str | None) -> tuple[str, sf.InnerList]:
    inputs = _dictionary(request, "signature-input")
    for candidate in [label] if label else list(inputs):
        member = inputs.get(candidate)
        if member is None and label:
            raise _contradicted("signature_absent", f"no Signature-Input for label {label!r}")
        if isinstance(member, sf.InnerList) and (label or member.params.get("tag") == TAG):
            return candidate, member
        if label:
            raise _contradicted("signature_headers_malformed", f"Signature-Input {label!r} is not an Inner List")
    raise _contradicted("signature_absent", f"no signature carries tag={TAG!r}")


def _parameters(inner: sf.InnerList) -> tuple[int, int, str]:
    params = inner.params
    for required in ("created", "expires", "keyid"):
        if required not in params:
            raise _contradicted("signature_parameters_invalid", f"the signature parameters lack {required!r}")
    created, expires, keyid = params["created"], params["expires"], params["keyid"]
    if (type(created) is not int or type(expires) is not int or not isinstance(keyid, str)
            or isinstance(keyid, sf.Token)):
        raise _contradicted("signature_parameters_invalid", "created and expires must be Integers and keyid a String")
    if params.get("tag") != TAG or isinstance(params.get("tag"), sf.Token):
        raise _contradicted("signature_parameters_invalid", f"tag is {params.get('tag')!r}, not {TAG!r}")
    alg = params.get("alg")
    if alg is not None and (isinstance(alg, sf.Token) or alg != "ed25519"):
        raise _contradicted("signature_parameters_invalid", f"alg {alg!r} is not supported; only ed25519 is")
    if expires <= created:
        raise _contradicted("signature_parameters_invalid", "expires is not after created")
    return created, expires, keyid


def _agent_member(inner: sf.InnerList) -> str:
    members = [str(i.params["key"]) for i in inner.items if i.value == "signature-agent" and "key" in i.params]
    if len(members) != 1:
        raise _contradicted("component_not_covered",
                            "the signature must cover exactly one Signature-Agent Dictionary member (the key parameter)")
    return members[0]


def _read_signature(request: Request, label: str | None) -> _Signature:
    chosen, inner = _chosen(request, label)
    created, expires, keyid = _parameters(inner)
    value = _dictionary(request, "signature").get(chosen)
    if not isinstance(value, sf.Item) or not isinstance(value.value, bytes):
        raise _contradicted("signature_headers_malformed", f"no Signature byte sequence for label {chosen!r}")
    components = tuple(str(i.value) for i in inner.items)
    return _Signature(chosen, inner, value.value, created, expires, keyid, _agent_member(inner), components)


# -- the checks ------------------------------------------------------------------------------------------------


def _check_components(sig: _Signature, required: list[str]) -> None:
    covered = set(sig.components)
    if not covered & {"@authority", "@target-uri"}:
        raise _contradicted("component_not_covered", "the signature covers neither @authority nor @target-uri")
    for name in required:
        if name not in covered:
            raise _contradicted("component_not_covered", f"the signature does not cover {name}, which the consumer requires")


def _check_agent(request: Request, sig: _Signature, pinned: str) -> str:
    member = _dictionary(request, "signature-agent", "signature_agent_mismatch").get(sig.agent_member)
    if (not isinstance(member, sf.Item) or not isinstance(member.value, str) or isinstance(member.value, sf.Token)
            or member.params):
        raise _contradicted("signature_agent_mismatch",
                            f"Signature-Agent has no plain String member {sig.agent_member!r}")
    if member.value != pinned:
        raise _contradicted("signature_agent_mismatch", f"the signature names {member.value!r}, not the pinned signer")
    return member.value


def _check_authority(request: Request, pinned: str) -> str:
    observed = _authority(request.url)
    if observed != pinned:
        raise _contradicted("authority_mismatch", f"the request was for {observed!r}, not {pinned!r}")
    return observed


def _check_time(sig: _Signature, at: int, assessment: dict) -> None:
    if sig.expires <= at:
        raise _contradicted("signature_expired", f"expired at {_iso(sig.expires)}, before {_iso(at)}")
    if sig.created > at + MAX_SKEW_SECONDS:
        raise _contradicted("signature_created_in_future", f"created {_iso(sig.created)}, after {_iso(at)}")
    age = assessment.get("max_age_seconds")
    if age is not None and at - sig.created > age:
        raise _contradicted("signature_too_old", f"created {at - sig.created} s before {_iso(at)}, over the {age} s limit")
    window = assessment.get("max_validity_seconds")
    if window is not None and sig.expires - sig.created > window:
        raise _contradicted("validity_window_too_long", f"valid for {sig.expires - sig.created} s, over the {window} s limit")


def _iso(seconds: int) -> str:
    return datetime.fromtimestamp(seconds, tz=UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _check_body(request: Request, sig: _Signature, body: bytes) -> dict[str, Any]:
    """The covered Content-Digest equals the digest of the received body, and a body is always covered."""
    covered = "content-digest" in sig.components
    if body and not covered:
        raise _contradicted("body_not_covered", "the request has a body and the signature does not cover content-digest")
    if not covered:
        return {"id": "body", "status": "met", "covered": False, "length": 0}
    members = _dictionary_of_digest(request)
    verified = []
    for algorithm, compute in DIGESTS.items():
        member = members.get(algorithm)
        if member is None:
            continue
        if not isinstance(member, sf.Item) or not isinstance(member.value, bytes) or member.value != compute(body):
            raise _contradicted("content_digest_mismatch", f"{algorithm} is not the digest of the received body")
        verified.append(algorithm)
    if not verified:
        raise _contradicted("content_digest_unsupported", "content-digest carries no sha-256 or sha-512 member")
    return {"id": "body", "status": "met", "covered": True, "length": len(body), "algorithms": verified}


def _dictionary_of_digest(request: Request) -> dict[str, sf.Member]:
    raw = request.field_value("content-digest")
    if raw is None:
        raise _contradicted("content_digest_mismatch", "content-digest is covered but the request has no such field")
    try:
        return sf.parse_dictionary(raw)
    except sf.SFError as error:
        raise _contradicted("content_digest_mismatch", f"content-digest: {error}") from error


def _check_signature(sig: _Signature, request: Request, keys: dict[str, dict], allow_test: bool) -> dict[str, Any]:
    key = keys.get(sig.keyid)
    if key is None:
        raise _Fail("not_established", "key_not_in_directory", f"keyid {sig.keyid[:12]}... is not in the pinned directory")
    if key["x"] in KNOWN_TEST_KEYS_X and not allow_test:
        raise _contradicted("test_key_refused", "the signing key is a published test key (RFC 9421 Appendix B.1.4)")
    base = signature_base(request, sig.inner)
    try:
        Ed25519PublicKey.from_public_bytes(strictb64.url(key["x"])).verify(sig.signature, base.encode("ascii"))
    except InvalidSignature:
        raise _contradicted("signature_invalid", "the signature does not verify over the covered components") from None
    return {"id": "signature", "status": "met", "algorithm": "ed25519", "keyid": sig.keyid,
            "signature_base_sha256": hashlib.sha256(base.encode("ascii")).hexdigest()}


# -- the claim ---------------------------------------------------------------------------------------------------


def _policy(assessment: dict) -> int:
    """Check the consumer's pinned values for shape; return the consumer's instant as epoch seconds."""
    _digest(assessment["directory_sha256"], "assessment.directory_sha256")
    agent = _string(assessment["signature_agent"], "assessment.signature_agent")
    parts = urlsplit(agent)
    if parts.scheme != "https" or not parts.hostname or parts.fragment or parts.username is not None:
        raise CaseError("assessment.signature_agent: expected an https URL without a fragment or credentials")
    authority = _string(assessment["authority"], "assessment.authority")
    if authority != authority.lower() or any(c in authority for c in "/?#@ "):
        raise CaseError("assessment.authority: expected a lowercase host[:port]")
    at = int(_instant(assessment["at"], "assessment.at").timestamp())
    required = assessment.get("required_components", [])
    if (not isinstance(required, list) or not all(isinstance(r, str) and r for r in required)
            or required != sorted(set(required))):
        raise CaseError("assessment.required_components: expected a sorted list of distinct component names")
    for name in ("max_age_seconds", "max_validity_seconds"):
        value = assessment.get(name)
        if value is not None and (type(value) is not int or value <= 0):
            raise CaseError(f"assessment.{name}: expected a positive integer")
    if not isinstance(assessment.get("allow_test_keys", False), bool):
        raise CaseError("assessment.allow_test_keys: expected a boolean")
    if "label" in assessment:
        _string(assessment["label"], "assessment.label")
    return at


def adjudicate(case: Any, policy: Any, artifact_root: Path) -> dict:
    """Judge one bound request under the consumer's pinned signer, directory and clock."""
    case_id, artifacts, assessment = assessment_for(case, policy, CLAIM_TYPE, REQUIRED, OPTIONAL)
    at = _policy(assessment)
    scope: dict[str, Any] = {
        "signature_agent": assessment["signature_agent"], "authority": assessment["authority"],
        "at": assessment["at"], "directory_sha256": assessment["directory_sha256"], "limit": LIMIT,
    }
    raw, request_binding = bound(artifacts, artifact_root, assessment["request"], "assessment.request")
    scope["request"] = request_binding
    if raw is None:
        return decision(case_id, CLAIM_TYPE, scope, "not_established", "request_unavailable")
    request = _request(raw)
    directory_raw, directory_binding = bound(artifacts, artifact_root, assessment["directory"], "assessment.directory")
    scope["directory"] = directory_binding
    if directory_raw is None:
        return decision(case_id, CLAIM_TYPE, scope, "not_established", "directory_unavailable")
    pinned = {"id": "directory_pinned",
              "status": "met" if directory_binding["sha256"] == assessment["directory_sha256"] else "failed",
              "expected": assessment["directory_sha256"], "observed": directory_binding["sha256"]}
    if pinned["status"] != "met":
        return decision(case_id, CLAIM_TYPE, scope, "not_established", "directory_not_pinned", [pinned])
    keys = _directory(directory_raw)
    body = b""
    if "body" in assessment:
        body_raw, body_binding = bound(artifacts, artifact_root, assessment["body"], "assessment.body")
        scope["body"] = body_binding
        if body_raw is None:
            return decision(case_id, CLAIM_TYPE, scope, "not_established", "body_unavailable", [pinned])
        body = body_raw
    checks: list[dict[str, Any]] = [pinned]
    try:
        sig = _read_signature(request, assessment.get("label"))
        checks.append({"id": "signature_headers", "status": "met", "label": sig.label,
                       "created": sig.created, "expires": sig.expires, "keyid": sig.keyid})
        _check_components(sig, assessment.get("required_components", []))
        checks.append({"id": "components", "status": "met", "covered": list(sig.components)})
        agent = _check_agent(request, sig, assessment["signature_agent"])
        checks.append({"id": "signature_agent", "status": "met", "observed": agent})
        checks.append({"id": "authority", "status": "met", "observed": _check_authority(request, assessment["authority"])})
        _check_time(sig, at, assessment)
        checks.append({"id": "validity", "status": "met", "created": _iso(sig.created), "expires": _iso(sig.expires)})
        checks.append(_check_body(request, sig, body))
        checks.append(_check_signature(sig, request, keys, bool(assessment.get("allow_test_keys", False))))
    except _Fail as failure:
        checks.append({"id": failure.reason, "status": "failed", "detail": failure.detail})
        return decision(case_id, CLAIM_TYPE, scope, failure.verdict, failure.reason, checks)
    scope["record"] = {"label": sig.label, "keyid": sig.keyid, "created": sig.created, "expires": sig.expires,
                       "covered": list(sig.components)}
    return decision(case_id, CLAIM_TYPE, scope, "supported", "request_signed_by_pinned_agent", checks)
