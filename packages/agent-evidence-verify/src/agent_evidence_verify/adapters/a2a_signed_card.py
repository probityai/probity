"""``a2a_signed_card/v1``: did the card's own key sign this Agent Card, and may that key speak for it?

An A2A Agent Card carries its signatures in a ``signatures`` member, each a JWS in flattened form
(``protected``, ``signature``, optional unprotected ``header``) over the RFC 8785 bytes of the card
with ``signatures`` removed (A2A specification sections 8.4.1 to 8.4.3, RFC 7515, RFC 8785). A
signature proves only that some key signed the bytes. A card reader that fetches the key from the
card's own ``jku``, or from whatever key set came with the card, accepts a card a stranger signed
with a key of their own: the discovery record is mistaken for authority. This reader closes that
hole the same way every signed-record reader in this package does: the consumer names the card's
DID, every ``kid`` must be a key of that DID, and the key that verifies must be authorised under
the consumer's ``key_authority`` (:mod:`agent_evidence_verify.key_authority`).

Checks, in order; the first refusal is the decision:

1. The card is I-JSON (duplicate members refused, no lone surrogates, integers within 2**53 - 1,
   finite numbers) and a JSON object (``card_invalid``); such a value always has RFC 8785 bytes.
2. ``signatures`` is a non-empty list of objects with exactly the members ``protected``,
   ``signature`` and an optional ``header`` object (``signatures_malformed``, ``null`` included; a
   card with no ``signatures`` member, or an empty list, is ``card_unsigned``).
3. Each protected header is strict unpadded base64url of an I-JSON object (``header_malformed``)
   naming ``alg`` and ``kid`` as strings (``kid_missing``, ``alg_unsupported`` for anything but
   ES256 and EdDSA, ``none`` included). It carries no ``crit`` (``jws_crit_unsupported``) and no
   ``b64`` (``jws_b64_unsupported``: the A2A construction signs the base64url payload). The
   protected and unprotected header names are disjoint (RFC 7515 section 7.2.1,
   ``header_names_not_disjoint``), so a ``kid`` or ``alg`` is read only where the signature covers
   it.
4. Each ``kid`` is a DID URL of the card's own DID: the DID, ``#`` and a non-empty fragment
   (``kid_not_under_card_did``). A bare ``key-1``, or a key of another DID, names no key the card's
   owner holds.
5. The key: the JWK whose ``kid`` equals the header's in the key set the case supplies (the bytes
   the reader fetched from ``jku`` or a key store), or, with no key set and a ``did-web``
   authority, the verification method of that id in the authority's pinned DID document. A key
   set that is not a JWK Set is ``jwks_malformed``, and two JWKs with one ``kid`` is
   ``jwks_kid_ambiguous``. The key is a public JWK (a private member such as ``d``, a coordinate of
   the wrong length, or an Ed25519 key that is a non-canonical or small-order point, under which one
   signature verifies every message, is ``key_malformed``), marked for signing (a ``use`` other
   than ``sig``, or ``key_ops`` without ``verify``, is ``key_not_for_signing``), of the type ``alg``
   names, with no JWK ``alg`` member naming another algorithm (``alg_key_mismatch``). A key in the
   JWS header itself (``jwk``, ``x5c``) is never used.
6. Each signature verifies over ``ASCII(protected) || "." || BASE64URL(JCS(card - signatures))``
   (``signature_invalid``; ES256 as raw ``r || s``, RFC 7518 section 3.4). A signature whose key
   is missing does not stop the others: every signature with a key is checked first, so a forged
   signature is ``contradicted`` even beside one whose key was withheld; only then is a missing key
   ``not_established`` (``key_unavailable``).
7. A card that lists the conformance extension
   (``https://w3id.org/agent-evidence/vocab/v1/conformance_extension``) in
   ``capabilities.extensions`` names its corpus and verifier with exact versions: ``params`` holds
   exactly ``corpus``, ``corpus_version``, ``verifier`` and ``verifier_version``, each a non-empty
   string, each version one exact release in one spelling, never a range
   (``conformance_extension_malformed``). A version is a normalized PEP 440 public version
   (``0.7.0``, ``1.0rc1``, ``0.7.0.post1``, ``2.0.dev3``) or a SemVer 2.0.0 version without build
   metadata (``1.0.0-rc.1``); leading zeros, separators PEP 440 normalizes away (``1.0-rc1``,
   ``1.0.0alpha``), an epoch, a local label and any operator or wildcard are refused, so the pin
   names one release, never a set of them. The extension is read only here, inside a card whose
   signatures verify, so stripping it breaks the card's signature.

Then key authority, once per signature, with the card's DID as the subject and the ``kid`` as the
key id: every signing key authorised is ``supported`` (``card_signature_authorized``); any key the
authority refuses is ``contradicted`` with the authority's reason; no authority, or authority
evidence that is missing, is ``not_established``. Fail closed on purpose: every signature on the
card covers the same bytes, so a signer that rotated keys drops the signature under the retired key
rather than asking readers to ignore it.

The card is read as served. The A2A rule that a verifier first removes properties holding protocol
default values needs the card's Protocol Buffers schema and its field-presence history, which the
served JSON does not carry; a card whose signer removed a default the server then wrote back reads
``signature_invalid`` here. That is the safe reading: the bytes the signer covered are the bytes the
reader judges.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ..common import CaseError, _string
from ..ijson import IJSONError, parse_ijson
from ..jose import (
    b64url,
    b64url_decode,
    ed25519_weak_key,
    jwk_signs,
    public_key,
    verify_signature,
)
from . import jcs_canonical
from .bound_records import assessment_for, bound, decision

CLAIM_TYPE = "a2a_signed_card/v1"
LIMIT = ("Says which keys of the card's own DID signed the card's bytes and whether the consumer's "
         "key authority lets those keys speak for that DID. It does not show the agent behind the "
         "card does what the card says, or that its endpoints are reachable.")
CONFORMANCE_EXTENSION = "https://w3id.org/agent-evidence/vocab/v1/conformance_extension"
EXTENSION_PARAMS = ("corpus", "corpus_version", "verifier", "verifier_version")
ALGS = ("ES256", "EdDSA")
REASONS = (
    "card_invalid", "card_unsigned", "signatures_malformed",
    "header_malformed", "kid_missing", "alg_unsupported", "jws_crit_unsupported",
    "jws_b64_unsupported", "header_names_not_disjoint", "kid_not_under_card_did",
    "jwks_malformed", "jwks_kid_ambiguous", "key_malformed", "key_not_for_signing",
    "alg_key_mismatch", "signature_invalid", "conformance_extension_malformed",
)
_DID = re.compile(r"did:[a-z0-9]+:[A-Za-z0-9._:%-]+")
_N = r"(?:0|[1-9][0-9]*)"
_SEMVER_ID = r"(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
#: One exact release: a normalized PEP 440 public version, or SemVer 2.0.0 without build metadata.
_EXACT_VERSION = re.compile(
    rf"{_N}(?:\.{_N})*(?:(?:a|b|rc){_N})?(?:\.post{_N})?(?:\.dev{_N})?"
    rf"|{_N}\.{_N}\.{_N}-{_SEMVER_ID}(?:\.{_SEMVER_ID})*")
_SIGNATURE_MEMBERS = {"protected", "signature"}
_SEVERITY = {"unauthorized": 2, "unknown": 1, "authorized": 0}
_REQUIRED = {"card", "card_did"}
_OPTIONAL = {"keys", "key_authority", "at"}


class Refused(Exception):
    """A check failed; ``args[0]`` is its code."""


class Unavailable(Exception):
    """Evidence a check needs was not supplied; ``args[0]`` is the not_established reason."""


def _strict(data: bytes, code: str) -> Any:
    try:
        return parse_ijson(data)
    except IJSONError as exc:
        raise Refused(code) from exc


def signing_input(card: dict[str, Any], protected: str) -> bytes:
    """The JWS signing input of one signature over the card minus its ``signatures`` member."""
    body = {name: value for name, value in card.items() if name != "signatures"}
    try:
        payload = jcs_canonical.serialize(body)
    except jcs_canonical.Refusal as exc:  # unreachable after the strict read; refused, never raised
        raise Refused("card_invalid") from exc
    return protected.encode("ascii") + b"." + b64url(payload).encode("ascii")


def _headers(entry: Any) -> tuple[str, dict[str, Any], bytes]:
    """The protected text, the protected header object and the signature bytes of one entry."""
    if (not isinstance(entry, dict) or not _SIGNATURE_MEMBERS <= set(entry)
            or not set(entry) <= _SIGNATURE_MEMBERS | {"header"}
            or not isinstance(entry["protected"], str) or not isinstance(entry["signature"], str)
            or not isinstance(entry.get("header", {}), dict)):
        raise Refused("signatures_malformed")
    try:
        header_bytes = b64url_decode(entry["protected"])
        signature = b64url_decode(entry["signature"])
    except ValueError as exc:
        raise Refused("header_malformed") from exc
    header = _strict(header_bytes, "header_malformed")
    if not isinstance(header, dict):
        raise Refused("header_malformed")
    if set(header) & set(entry.get("header", {})):
        raise Refused("header_names_not_disjoint")
    if not isinstance(header.get("kid"), str) or not header["kid"]:
        raise Refused("kid_missing")
    if header.get("alg") not in ALGS:
        raise Refused("alg_unsupported")
    if "crit" in header:
        raise Refused("jws_crit_unsupported")
    if "b64" in header:
        raise Refused("jws_b64_unsupported")
    return entry["protected"], header, signature


def _under(kid: str, card_did: str) -> bool:
    prefix = card_did + "#"
    return kid.startswith(prefix) and len(kid) > len(prefix)


def _jwks_key(key_set: Any, kid: str) -> dict[str, Any] | None:
    if not isinstance(key_set, dict) or not isinstance(key_set.get("keys"), list):
        raise Refused("jwks_malformed")
    found = [jwk for jwk in key_set["keys"] if isinstance(jwk, dict) and jwk.get("kid") == kid]
    if len(found) > 1:
        raise Refused("jwks_kid_ambiguous")
    return found[0] if found else None


def _document_key(document: bytes | None, card_did: str, kid: str) -> dict[str, Any] | None:
    """The JWK of the verification method ``kid`` in the pinned DID document, else None.

    Whether that method is listed for assertions, and whether the document is the pinned one, is
    the key authority's question; this only finds the key the ``kid`` names.
    """
    if document is None:
        return None
    try:
        parsed = parse_ijson(document)
    except IJSONError:
        return None
    if not isinstance(parsed, dict):
        return None

    def listed(member: str) -> list:  # any other shape names no method; the authority refuses it
        value = parsed.get(member)
        return [m for m in value if isinstance(m, dict)] if isinstance(value, list) else []

    candidates = listed("verificationMethod")
    for relationship in ("assertionMethod", "authentication"):
        candidates += listed(relationship)
    for method in candidates:
        if not isinstance(method, dict) or not isinstance(method.get("id"), str):
            continue
        mid = card_did + method["id"] if method["id"].startswith("#") else method["id"]
        if mid == kid and isinstance(method.get("publicKeyJwk"), dict):
            return method["publicKeyJwk"]
    return None


def _extension(card: dict[str, Any]) -> dict[str, str] | None:
    """The conformance extension's pinned parameters, None when the card does not list it."""
    capabilities = card.get("capabilities")
    extensions = capabilities.get("extensions") if isinstance(capabilities, dict) else None
    if not isinstance(extensions, list):
        return None
    listed = [e for e in extensions if isinstance(e, dict) and e.get("uri") == CONFORMANCE_EXTENSION]
    if not listed:
        return None
    params = listed[0].get("params")
    if (len(listed) != 1 or not isinstance(params, dict) or set(params) != set(EXTENSION_PARAMS)
            or not all(isinstance(params[name], str) and params[name] for name in EXTENSION_PARAMS)
            or not all(_EXACT_VERSION.fullmatch(params[name])
                       for name in ("corpus_version", "verifier_version"))):
        raise Refused("conformance_extension_malformed")
    return {name: params[name] for name in EXTENSION_PARAMS}


def _signing_key(jwk: dict[str, Any], header_alg: str) -> tuple[Any, bytes]:
    """The key object and raw key bytes of a JWK that may verify a ``header_alg`` signature."""
    from ..key_authority import jwk_key_bytes
    try:
        raw = jwk_key_bytes(jwk, "key")
    except CaseError as exc:
        raise Refused("key_malformed") from exc
    if not jwk_signs(jwk):
        raise Refused("key_not_for_signing")
    alg, key = public_key({"publicKeyJwk": jwk})
    if alg != header_alg or jwk.get("alg", header_alg) != header_alg:
        raise Refused("alg_key_mismatch")
    if alg == "EdDSA" and ed25519_weak_key(raw):
        raise Refused("key_malformed")
    return key, raw


def judge(card_bytes: bytes, card_did: str, key_set: Any, document: bytes | None,
          ) -> tuple[list[tuple[str, bytes]], dict[str, str] | None]:
    """The (kid, raw key) of every signature that verifies, and the conformance extension's params.

    Raises :class:`Refused` with the first failing check's code, or :class:`Unavailable` once
    every signature whose key is available has verified.
    """
    card = _strict(card_bytes, "card_invalid")
    if not isinstance(card, dict):
        raise Refused("card_invalid")
    if "signatures" not in card or card["signatures"] == []:
        raise Refused("card_unsigned")
    entries = card["signatures"]
    if not isinstance(entries, list):
        raise Refused("signatures_malformed")
    parsed = [_headers(entry) for entry in entries]
    for _, header, _ in parsed:
        if not _under(header["kid"], card_did):
            raise Refused("kid_not_under_card_did")
    signers, missing = [], False
    for protected, header, signature in parsed:
        kid = header["kid"]
        jwk = _jwks_key(key_set, kid) if key_set is not None else _document_key(document, card_did,
                                                                                kid)
        if jwk is None:
            missing = True  # judged after every signature that has a key
            continue
        key, raw = _signing_key(jwk, header["alg"])
        if not verify_signature(header["alg"], key, signing_input(card, protected), signature):
            raise Refused("signature_invalid")
        signers.append((kid, raw))
    if missing:
        raise Unavailable("key_unavailable")
    return signers, _extension(card)


def _context(assessment: dict) -> str:
    card_did = _string(assessment["card_did"], "assessment.card_did")
    if not _DID.fullmatch(card_did):
        raise CaseError("assessment.card_did: expected a DID such as did:web:agent.example")
    return card_did


def adjudicate(case: Any, policy: Any, artifact_root: Path) -> dict:
    """Judge the bound card, then ask the consumer's key authority about every signing key."""
    from ..key_authority import AUTHORIZED, UNAUTHORIZED, authority_evidence, authorize
    case_id, artifacts, assessment = assessment_for(case, policy, CLAIM_TYPE, _REQUIRED, _OPTIONAL)
    card_did = _context(assessment)
    scope: dict[str, Any] = {"card_did": card_did, "limit": LIMIT}
    card, scope["card"] = bound(artifacts, artifact_root, assessment["card"], "assessment.card")
    key_set_bytes = None
    if "keys" in assessment:
        key_set_bytes, scope["keys"] = bound(artifacts, artifact_root, assessment["keys"],
                                             "assessment.keys")
        if key_set_bytes is None:
            return decision(case_id, CLAIM_TYPE, scope, "not_established", "keys_unavailable")
    if card is None:
        return decision(case_id, CLAIM_TYPE, scope, "not_established", "card_unavailable")
    config = assessment.get("key_authority")
    document, proof = authority_evidence(config, artifacts, artifact_root, scope)
    check: dict[str, Any] = {"id": "a2a_signed_card"}
    try:
        key_set = None if key_set_bytes is None else _strict(key_set_bytes, "jwks_malformed")
        signers, extension = judge(card, card_did, key_set, document)
    except Refused as refusal:
        check.update(status="fail", reason=str(refusal.args[0]))
        return decision(case_id, CLAIM_TYPE, scope, "contradicted", str(refusal.args[0]), [check])
    except Unavailable as missing:
        check.update(status="unavailable", reason=str(missing.args[0]))
        return decision(case_id, CLAIM_TYPE, scope, "not_established", str(missing.args[0]),
                        [check])
    check.update(status="pass", reason="card_signatures_verify",
                 signers=[kid for kid, _ in signers])
    if extension is not None:
        check["conformance_extension"] = extension
    answers = [authorize(config, key, kid=kid, subject=card_did, at=assessment.get("at"),
                         did_document=document, inclusion_proof=proof) for kid, key in signers]
    authority = max(answers, key=lambda answer: _SEVERITY[answer.outcome])
    checks = [check, authority.check()]
    if authority.outcome == AUTHORIZED:
        return decision(case_id, CLAIM_TYPE, scope, "supported", "card_signature_authorized",
                        checks)
    if authority.outcome == UNAUTHORIZED:
        return decision(case_id, CLAIM_TYPE, scope, "contradicted", authority.reason, checks)
    return decision(case_id, CLAIM_TYPE, scope, "not_established", authority.reason, checks)
