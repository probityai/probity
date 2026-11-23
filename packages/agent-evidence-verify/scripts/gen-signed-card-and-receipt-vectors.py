"""Write the a2a_signed_card/v1 and co_signed_receipt/v1 vectors under tests/data.

Every key is a test key derived from a fixed label, every signature is real (Ed25519, and ES256
with RFC 6979 deterministic nonces), so a rerun writes the same bytes. Hosts are example.test
names; nothing is copied from any other project's vectors. Each case directory holds the evidence
files, and cases.json pins each case's assessment and expected decision and reason.

    uv run --directory packages/agent-evidence-verify python scripts/gen-signed-card-and-receipt-vectors.py
    uv run --directory packages/agent-evidence-verify python scripts/gen-signed-card-and-receipt-vectors.py --check
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "tests" / "data"

CARD_DID = "did:web:agent.example.test"
OTHER_DID = "did:web:other.example.test"
EXTENSION = "https://w3id.org/agent-evidence/vocab/v1/conformance_extension"
AT = "2026-11-17T12:00:00Z"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def jcs(value: Any) -> bytes:
    """RFC 8785 for the values these vectors hold (ASCII member names, strings, integers,
    booleans, null), written independently of the reader under test so a fault in its
    canonicalizer cannot hide in the vectors."""
    for node in _walk(value):
        if isinstance(node, float):
            raise TypeError("these vectors hold integers only")
        if isinstance(node, dict) and not all(k.isascii() for k in node):
            raise ValueError("these vectors hold ASCII member names only")
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _walk(value: Any):
    yield value
    children = value.values() if isinstance(value, dict) else value if isinstance(value, list) else ()
    for child in children:
        yield from _walk(child)


def seed(label: str) -> bytes:
    return hashlib.sha256(f"agent-evidence-verify test key: {label}".encode()).digest()


class Ed:
    def __init__(self, label: str) -> None:
        self.key = Ed25519PrivateKey.from_private_bytes(seed(label))
        self.raw = self.key.public_key().public_bytes(serialization.Encoding.Raw,
                                                      serialization.PublicFormat.Raw)
        self.alg = "EdDSA"

    def jwk(self, kid: str | None = None) -> dict[str, Any]:
        jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64url(self.raw)}
        return dict(jwk, kid=kid) if kid else jwk

    def sign(self, message: bytes) -> bytes:
        return self.key.sign(message)


class P256:
    def __init__(self, label: str) -> None:
        self.key = ec.derive_private_key(int.from_bytes(seed(label), "big") % (2**255), ec.SECP256R1())
        numbers = self.key.public_key().public_numbers()
        self.x, self.y = numbers.x.to_bytes(32, "big"), numbers.y.to_bytes(32, "big")
        self.raw = b"\x04" + self.x + self.y
        self.alg = "ES256"

    def jwk(self, kid: str | None = None) -> dict[str, Any]:
        jwk = {"kty": "EC", "crv": "P-256", "x": b64url(self.x), "y": b64url(self.y)}
        return dict(jwk, kid=kid) if kid else jwk

    def sign(self, message: bytes) -> bytes:
        der = self.key.sign(message, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
        r, s = decode_dss_signature(der)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")


OWNER = Ed("card owner ed25519")
OWNER_P256 = P256("card owner p-256")
NEXT = Ed("card owner next ed25519")
STRANGER = Ed("stranger ed25519")
AGENT = Ed("receipt agent ed25519")
CALLER = Ed("receipt caller ed25519")
FORGER = Ed("receipt forger ed25519")


class SmallOrder:
    """The identity point as an Ed25519 public key: under it, R = identity and S = 0 verify every
    message in OpenSSL, so this "signature" needs no private key."""

    raw = b"\x01" + b"\x00" * 31
    alg = "EdDSA"

    def jwk(self, kid: str | None = None) -> dict[str, Any]:
        jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64url(self.raw)}
        return dict(jwk, kid=kid) if kid else jwk

    def sign(self, message: bytes) -> bytes:
        return self.raw + b"\x00" * 32


WEAK = SmallOrder()


def digest(key: Any) -> str:
    return hashlib.sha256(key.raw).hexdigest()


def pin(*keys: tuple[Any, str | None]) -> dict[str, Any]:
    pins = []
    for key, kid in keys:
        entry = {"public_key_sha256": digest(key)}
        if kid:
            entry["kid"] = kid
        pins.append(entry)
    return {"kind": "pin", "keys": pins}


def base_card() -> dict[str, Any]:
    return {
        "name": "Invoice Reader",
        "description": "Reads invoices and returns their line items.",
        "supportedInterfaces": [{"url": "https://agent.example.test/a2a/v1",
                                 "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}],
        "version": "1.4.0",
        "capabilities": {"streaming": False},
        "defaultInputModes": ["application/pdf"],
        "defaultOutputModes": ["application/json"],
        "skills": [{"id": "read-invoice", "name": "Read invoice",
                    "description": "Returns the line items of one invoice.", "tags": ["invoice"]}],
    }


def payload(card: dict[str, Any], keep_signatures: bool = False) -> bytes:
    """The bytes a signer covers. ``keep_signatures`` is the signer that canonicalized the card with
    its ``signatures`` member still in it, as the empty list it holds before the first signature is
    added; A2A section 8.4.1 removes the member, so the reader judges other bytes."""
    if keep_signatures:
        return jcs(dict(card, signatures=card.get("signatures", [])))
    return jcs({k: v for k, v in card.items() if k != "signatures"})


def jws(card: dict[str, Any], key: Any, kid: str | None, *, header: dict | None = None,
        unprotected: dict | None = None, keep_signatures: bool = False) -> dict[str, Any]:
    protected = header if header is not None else {"alg": key.alg, "typ": "JOSE", "kid": kid}
    encoded = b64url(json.dumps(protected, separators=(",", ":")).encode())
    message = encoded.encode() + b"." + b64url(payload(card, keep_signatures)).encode()
    entry = {"protected": encoded, "signature": b64url(key.sign(message))}
    if unprotected is not None:
        entry["header"] = unprotected
    return entry


def signed(card: dict[str, Any], *entries_of: Any) -> dict[str, Any]:
    out = copy.deepcopy(card)
    out["signatures"] = [entry(out) for entry in entries_of]
    return out


def did_document(*methods: tuple[str, Any]) -> dict[str, Any]:
    vms = [{"id": f"{CARD_DID}#{frag}", "type": "JsonWebKey2020", "controller": CARD_DID,
            "publicKeyJwk": key.jwk()} for frag, key in methods]
    return {"id": CARD_DID, "verificationMethod": vms, "assertionMethod": [m["id"] for m in vms]}


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def card_cases() -> list[dict[str, Any]]:
    kid = f"{CARD_DID}#ed25519"
    kid_p = f"{CARD_DID}#es256"
    owner_jwks = {"keys": [OWNER.jwk(kid), OWNER_P256.jwk(kid_p)]}
    owner_pin = pin((OWNER, kid))
    card = base_card()
    with_extension = copy.deepcopy(card)
    with_extension["capabilities"]["extensions"] = [{
        "uri": EXTENSION, "description": "Records this agent emits are judged by the named corpus.",
        "params": {"corpus": "agent-evidence-vectors", "corpus_version": "0.37.0",
                   "verifier": "agent-evidence-verify", "verifier_version": "0.7.0"}}]
    ranged = copy.deepcopy(with_extension)
    ranged["capabilities"]["extensions"][0]["params"]["corpus_version"] = ">=0.37"
    leading_zero = copy.deepcopy(with_extension)
    leading_zero["capabilities"]["extensions"][0]["params"]["corpus_version"] = "0.037.0"
    prerelease = copy.deepcopy(with_extension)
    prerelease["capabilities"]["extensions"][0]["params"].update(
        corpus_version="1.0.0-rc.1", verifier_version="0.7.0.post1")

    def by(key: Any, k: str | None = kid, **options: Any):
        return lambda c: jws(c, key, k, **options)

    stripped = signed(with_extension, by(OWNER))
    stripped["capabilities"].pop("extensions")
    tampered = signed(card, by(OWNER))
    tampered["description"] = "Reads invoices and pays them."
    two_one_bad = signed(card, by(OWNER), by(OWNER_P256, kid_p))
    two_one_bad["signatures"][1]["signature"] = two_one_bad["signatures"][0]["signature"]
    duplicate = json.dumps(signed(card, by(OWNER)), indent=2).replace(
        '"name": "Invoice Reader",', '"name": "Invoice Reader",\n  "name": "Invoice Payer",', 1)
    stranger_jwks = {"keys": [STRANGER.jwk(kid)]}
    padded = signed(card, by(OWNER))
    withheld_then_forged = signed(card, by(STRANGER, f"{CARD_DID}#withheld"), by(OWNER))
    withheld_then_forged["signatures"][1]["signature"] = withheld_then_forged["signatures"][0][
        "signature"]

    def owner_jwk(**members: Any) -> dict[str, Any]:
        return {"keys": [dict(OWNER.jwk(kid), **members)]}

    methods_not_a_list = did_document(("ed25519", OWNER))
    methods_not_a_list["verificationMethod"] = True
    padded["signatures"][0]["protected"] += "=" * (-len(padded["signatures"][0]["protected"]) % 4 or 4)
    cases = [
        ("valid-eddsa-pinned", signed(card, by(OWNER)), owner_jwks, None,
         {"key_authority": owner_pin}, "supported", "card_signature_authorized",
         "the owner's Ed25519 key signs; the consumer pins it"),
        ("valid-es256-pinned", signed(card, by(OWNER_P256, kid_p)), owner_jwks, None,
         {"key_authority": pin((OWNER_P256, kid_p))}, "supported", "card_signature_authorized",
         "the owner's P-256 key signs (ES256, raw r || s)"),
        ("valid-did-web", signed(card, by(OWNER)), None, did_document(("ed25519", OWNER)),
         {"key_authority": "did-web"}, "supported", "card_signature_authorized",
         "no key set: the key comes from the pinned DID document, listed for assertions"),
        ("valid-conformance-extension", signed(with_extension, by(OWNER)), owner_jwks, None,
         {"key_authority": owner_pin}, "supported", "card_signature_authorized",
         "the card lists the conformance extension inside its signature"),
        ("extension-stripped", stripped, owner_jwks, None, {"key_authority": owner_pin},
         "contradicted", "signature_invalid",
         "the conformance extension is removed after signing: the card's own signature fails"),
        ("extension-version-range", signed(ranged, by(OWNER)), owner_jwks, None,
         {"key_authority": owner_pin}, "contradicted", "conformance_extension_malformed",
         "a corpus version range, signed: the extension pins no version"),
        ("tampered-description", tampered, owner_jwks, None, {"key_authority": owner_pin},
         "contradicted", "signature_invalid", "the description changes after signing"),
        ("signatures-included", signed(card, by(OWNER, keep_signatures=True)), owner_jwks, None,
         {"key_authority": owner_pin}, "contradicted", "signature_invalid",
         "the signer covered the signatures member; A2A 8.4.1 excludes it"),
        ("wrong-kid-other-did", signed(card, by(OWNER, f"{OTHER_DID}#ed25519")),
         {"keys": [OWNER.jwk(f"{OTHER_DID}#ed25519")]}, None, {"key_authority": owner_pin},
         "contradicted", "kid_not_under_card_did", "the kid names a key of another DID"),
        ("wrong-kid-bare", signed(card, by(OWNER, "key-1")), {"keys": [OWNER.jwk("key-1")]}, None,
         {"key_authority": owner_pin}, "contradicted", "kid_not_under_card_did",
         "the bare kid of the specification's example names no key of the card's DID"),
        ("foreign-key-no-authority", signed(card, by(STRANGER)), stranger_jwks, None, {},
         "not_established", "no_key_authority_in_policy",
         "a stranger signs under the owner's kid and serves the key set; nothing says whose key"),
        ("foreign-key-pinned-owner", signed(card, by(STRANGER)), stranger_jwks, None,
         {"key_authority": owner_pin}, "contradicted", "key_not_pinned",
         "the same forgery under a pin of the owner's key"),
        ("foreign-key-did-web", signed(card, by(STRANGER, f"{CARD_DID}#stranger")),
         {"keys": [STRANGER.jwk(f"{CARD_DID}#stranger")]}, did_document(("ed25519", OWNER)),
         {"key_authority": "did-web"}, "contradicted", "key_not_in_did_document",
         "a stranger's key under a fragment of the owner's DID that the DID document never lists"),
        ("alg-none", signed(card, by(OWNER, header={"alg": "none", "typ": "JOSE", "kid": kid})),
         owner_jwks, None, {"key_authority": owner_pin}, "contradicted", "alg_unsupported",
         "alg none"),
        ("crit-header", signed(card, by(OWNER, header={"alg": "EdDSA", "kid": kid,
                                                         "crit": ["exp"], "exp": 1})),
         owner_jwks, None, {"key_authority": owner_pin}, "contradicted", "jws_crit_unsupported",
         "a critical header parameter this reader does not implement"),
        ("b64-header", signed(card, by(OWNER, header={"alg": "EdDSA", "kid": kid, "b64": True})),
         owner_jwks, None, {"key_authority": owner_pin}, "contradicted", "jws_b64_unsupported",
         "b64 is outside the A2A construction"),
        ("kid-unprotected", signed(card, by(OWNER, header={"alg": "EdDSA", "typ": "JOSE"},
                                            unprotected={"kid": kid})),
         owner_jwks, None, {"key_authority": owner_pin}, "contradicted", "kid_missing",
         "the kid is only in the unprotected header, which the signature does not cover"),
        ("kid-in-both-headers", signed(card, by(OWNER, unprotected={"kid": f"{CARD_DID}#other"})),
         owner_jwks, None, {"key_authority": owner_pin}, "contradicted",
         "header_names_not_disjoint", "the unprotected header repeats kid (RFC 7515 7.2.1)"),
        ("alg-key-mismatch", signed(card, by(OWNER, header={"alg": "ES256", "kid": kid})),
         owner_jwks, None, {"key_authority": owner_pin}, "contradicted", "alg_key_mismatch",
         "the header says ES256 over an Ed25519 key"),
        ("jwks-kid-ambiguous", signed(card, by(OWNER)),
         {"keys": [OWNER.jwk(kid), STRANGER.jwk(kid)]}, None, {"key_authority": owner_pin},
         "contradicted", "jwks_kid_ambiguous", "two keys in the key set share the kid"),
        ("key-unavailable", signed(card, by(OWNER)), {"keys": [OWNER_P256.jwk(kid_p)]}, None,
         {"key_authority": owner_pin}, "not_established", "key_unavailable",
         "the key set has no key for the kid"),
        ("duplicate-member", duplicate, owner_jwks, None, {"key_authority": owner_pin},
         "contradicted", "card_invalid", "the card names name twice"),
        ("unsigned", card, owner_jwks, None, {"key_authority": owner_pin}, "contradicted",
         "card_unsigned", "no signatures member"),
        ("signatures-not-a-list", dict(card, signatures={"protected": "e30", "signature": ""}),
         owner_jwks, None, {"key_authority": owner_pin}, "contradicted", "signatures_malformed",
         "signatures is an object, not a list"),
        ("protected-padded", padded, owner_jwks, None, {"key_authority": owner_pin},
         "contradicted", "header_malformed", "the protected header carries base64 padding"),
        ("jwks-not-a-key-set", signed(card, by(OWNER)), [OWNER.jwk(kid)], None,
         {"key_authority": owner_pin}, "contradicted", "jwks_malformed",
         "the key set is a bare list, not a JWK Set"),
        ("second-signature-invalid", two_one_bad, owner_jwks, None,
         {"key_authority": pin((OWNER, kid), (OWNER_P256, kid_p))}, "contradicted",
         "signature_invalid", "one of two signatures does not verify"),
        ("withheld-key-beside-forged-signature", withheld_then_forged, owner_jwks, None,
         {"key_authority": owner_pin}, "contradicted", "signature_invalid",
         "the first signature's key is withheld and the second is forged: the forgery decides"),
        ("withheld-key-beside-valid-signature", signed(card, by(STRANGER, f"{CARD_DID}#withheld"),
                                                       by(OWNER)),
         owner_jwks, None, {"key_authority": owner_pin}, "not_established", "key_unavailable",
         "one signature verifies and the other's key is withheld: nothing refuses, nothing decides"),
        ("signatures-null", dict(card, signatures=None), owner_jwks, None,
         {"key_authority": owner_pin}, "contradicted", "signatures_malformed",
         "signatures is null: present, so malformed, not unsigned"),
        ("key-for-encryption", signed(card, by(OWNER)), owner_jwk(use="enc"), None,
         {"key_authority": owner_pin}, "contradicted", "key_not_for_signing",
         "the served key is marked use enc (RFC 7517 4.2)"),
        ("key-ops-without-verify", signed(card, by(OWNER)), owner_jwk(key_ops=["encrypt"]), None,
         {"key_authority": owner_pin}, "contradicted", "key_not_for_signing",
         "the served key's key_ops omit verify (RFC 7517 4.3)"),
        ("jwk-alg-names-another-algorithm", signed(card, by(OWNER)), owner_jwk(alg="ES256"), None,
         {"key_authority": owner_pin}, "contradicted", "alg_key_mismatch",
         "the served Ed25519 key says alg ES256"),
        ("key-set-holds-private-key", signed(card, by(OWNER)),
         owner_jwk(d=b64url(seed("card owner ed25519"))), None, {"key_authority": owner_pin},
         "contradicted", "key_malformed", "the served key carries its private member d"),
        ("small-order-key", signed(card, by(WEAK)), {"keys": [WEAK.jwk(kid)]}, None,
         {"key_authority": pin((WEAK, kid))}, "contradicted", "key_malformed",
         "the identity point as the key, pinned: R = identity, S = 0 verifies every card"),
        ("did-document-methods-not-a-list", signed(card, by(OWNER)), None, methods_not_a_list,
         {"key_authority": "did-web"}, "not_established", "key_unavailable",
         "the DID document's verificationMethod is true: it names no key, and nothing raises"),
        ("extension-version-leading-zero", signed(leading_zero, by(OWNER)), owner_jwks, None,
         {"key_authority": owner_pin}, "contradicted", "conformance_extension_malformed",
         "corpus_version 0.037.0 is not one spelling of a release"),
        ("extension-version-prerelease", signed(prerelease, by(OWNER)), owner_jwks, None,
         {"key_authority": owner_pin}, "supported", "card_signature_authorized",
         "a SemVer pre-release corpus and a PEP 440 post-release verifier are exact releases"),
        ("retired-key-signature-kept", signed(card, by(OWNER), by(NEXT, f"{CARD_DID}#next")),
         {"keys": [OWNER.jwk(kid), NEXT.jwk(f"{CARD_DID}#next")]}, None,
         {"key_authority": pin((NEXT, f"{CARD_DID}#next"))}, "contradicted", "key_not_pinned",
         "both signatures verify, the consumer pins only the new key: the retired one is refused"),
    ]
    return cases


def receipt_cases() -> list[dict[str, Any]]:
    base = {"formatVersion": "1", "agentDid": "did:web:agent.example.test",
            "callerDid": "did:web:caller.example.test", "toolName": "translate",
            "taskHash": hashlib.sha256(b"task: translate one paragraph").hexdigest(),
            "resultHash": hashlib.sha256(b"result: one paragraph").hexdigest(),
            "success": True, "failureType": "", "latencyMs": 142,
            "timestamp": "2026-11-17T11:59:58.250Z"}
    keys = {base["agentDid"]: AGENT.jwk(), base["callerDid"]: CALLER.jwk()}
    authority = {"key_authority": pin((AGENT, None)), "cosigner_key_authority": pin((CALLER, None))}
    registry = {"kind": "registry", "bindings": [
        {"subject": base["agentDid"], "public_key_sha256": digest(AGENT),
         "not_before": "2026-01-01T00:00:00Z"},
        {"subject": base["callerDid"], "public_key_sha256": digest(CALLER),
         "not_before": "2026-01-01T00:00:00Z"}]}

    def message(receipt: dict[str, Any], *, null_absent: tuple[str, ...] = ()) -> bytes:
        body = {k: v for k, v in receipt.items() if k not in ("signature", "callerSignature")}
        for name in null_absent:
            body.setdefault(name, None)
        return jcs(body)

    def sign(receipt: dict[str, Any], *, cosign: bool = True, agent: Any = AGENT,
             caller: Any = CALLER, **options: Any) -> dict[str, Any]:
        out = {k: v for k, v in receipt.items() if k not in ("signature", "callerSignature")}
        if not cosign:
            out.pop("callerDid", None)
        msg = message(out, **options)
        out["signature"] = agent.sign(msg).hex()
        if cosign:
            out["callerSignature"] = caller.sign(msg).hex()
        return out

    def without(name: str) -> dict[str, Any]:
        return {k: v for k, v in base.items() if k != name}

    wrong_cosignature = sign(base)
    wrong_cosignature["callerSignature"] = AGENT.sign(message(dict(base, latencyMs=143))).hex()
    long_signature = sign(base)
    long_signature["signature"] += "0"
    forged_keys = dict(keys, **{base["agentDid"]: FORGER.jwk()})
    same_key = {base["agentDid"]: AGENT.jwk(), base["callerDid"]: AGENT.jwk()}
    p256_agent = dict(keys, **{base["agentDid"]: OWNER_P256.jwk()})
    wrong_signature = sign(base)
    wrong_signature["signature"] = AGENT.sign(message(dict(base, latencyMs=143))).hex()
    encryption_key = dict(keys, **{base["agentDid"]: dict(AGENT.jwk(), use="enc")})
    weak_keys = dict(keys, **{base["agentDid"]: WEAK.jwk()})
    weak_authority = dict(authority, key_authority=pin((WEAK, None)))
    caller_withheld = {base["agentDid"]: AGENT.jwk()}
    return [
        ("valid-co-signed", sign(base), keys, authority, "supported",
         "receipt_signers_authorized", "co_signed", "both parties sign, both keys pinned"),
        ("valid-single-signed", sign(base, cosign=False), keys, {"key_authority": pin((AGENT, None))},
         "supported", "receipt_signers_authorized", "single_signed", "the agent alone signs"),
        ("valid-co-signed-registry", sign(base), keys,
         {"key_authority": registry, "cosigner_key_authority": registry}, "supported",
         "receipt_signers_authorized", "co_signed",
         "both keys bound to their DIDs at the receipt's timestamp"),
        ("valid-no-authority", sign(base), keys, {}, "not_established",
         "no_key_authority_in_policy", None,
         "both signatures verify and nothing says whose keys they are: no attribution yet"),
        ("foreign-agent-key", sign(base, agent=FORGER), forged_keys, authority, "contradicted",
         "key_not_pinned", "unattributed_evidence",
         "a forger signs as the agent and supplies a key for the agent's DID: it binds no party"),
        ("same-key-both-parties", sign(base, caller=AGENT), same_key, authority, "contradicted",
         "cosigner-is-signer", None, "one key signs as both parties: one party shown as two"),
        ("agent-key-not-ed25519", sign(base), p256_agent, authority, "contradicted",
         "key_malformed", None, "the key set gives the agent a P-256 key"),
        ("agent-signature-does-not-verify", wrong_signature, keys, authority, "contradicted",
         "signature-invalid", "unattributed_evidence",
         "the agent's signature covers other bytes"),
        ("agent-key-for-encryption", sign(base), encryption_key, authority, "contradicted",
         "key_not_for_signing", None, "the agent's key is marked use enc"),
        ("agent-key-small-order", sign(base, agent=WEAK), weak_keys, weak_authority, "contradicted",
         "key_malformed", None,
         "the identity point as the agent's key, pinned: its signature verifies every receipt"),
        ("forged-agent-signature-caller-key-withheld", wrong_signature, caller_withheld, authority,
         "contradicted", "signature-invalid", "unattributed_evidence",
         "the agent's signature is forged and the caller's key withheld: the forgery decides"),
        ("broken-01-uppercase-hash", sign(dict(base, taskHash=base["taskHash"].upper())), keys,
         authority, "contradicted", "hash-not-lowercase-hex64", None,
         "an uppercase taskHash under two valid signatures"),
        ("broken-02-absent-task-hash", sign(without("taskHash")), keys, authority, "contradicted",
         "member-missing", None, "no taskHash, signed over a payload without it"),
        ("broken-03-absent-task-hash-signed-as-null",
         sign(without("taskHash"), null_absent=("taskHash",)), keys, authority, "contradicted",
         "member-missing", None, "no taskHash, signed over a payload that carried taskHash null"),
        ("broken-04-unknown-format-version", sign(dict(base, formatVersion="2")), keys, authority,
         "contradicted", "version-unknown", None, "format version 2, both signatures valid"),
        ("broken-05-cosignature-does-not-verify", wrong_cosignature, keys, authority,
         "contradicted", "cosignature-invalid", "unattributed_evidence",
         "the agent's signature verifies; the present co-signature does not"),
        ("broken-06-negative-latency", sign(dict(base, latencyMs=-1)), keys, authority,
         "contradicted", "latency-out-of-range", None, "latencyMs -1, both signatures valid"),
        ("broken-07-signature-129-hex", long_signature, keys, authority, "contradicted",
         "signature-not-lowercase-hex128", None,
         "a valid signature with one more hex digit, which a lenient decoder truncates"),
        ("broken-08-failure-type-omitted", sign(without("failureType")), keys, authority,
         "contradicted", "member-missing", None, "success true and no failureType member"),
    ]


def build(out: Path) -> None:
    card_root = out / "a2a-signed-card"
    card_root.mkdir(parents=True)
    index = []
    for name, card, key_set, document, auth, want, reason, why in card_cases():
        directory = card_root / name
        directory.mkdir()
        if isinstance(card, str):
            (directory / "card.json").write_text(card + "\n", encoding="utf-8")
        else:
            write_json(directory / "card.json", card)
        assessment: dict[str, Any] = {"card": "card.json", "card_did": CARD_DID, "at": AT}
        if key_set is not None:
            write_json(directory / "jwks.json", key_set)
            assessment["keys"] = "jwks.json"
        if document is not None:
            write_json(directory / "did.json", document)
        if auth.get("key_authority") == "did-web":
            raw = (directory / "did.json").read_bytes()
            assessment["key_authority"] = {"kind": "did-web", "did": CARD_DID,
                                           "document": "did.json",
                                           "document_sha256": hashlib.sha256(raw).hexdigest()}
        elif "key_authority" in auth:
            assessment["key_authority"] = auth["key_authority"]
        index.append({"id": name, "description": why, "assessment": assessment,
                      "expect": {"decision": want, "reason": reason}})
    write_json(card_root / "cases.json", {"claim_type": "a2a_signed_card/v1", "cases": index})

    receipt_root = out / "co-signed-receipt"
    receipt_root.mkdir()
    index = []
    for name, receipt, key_map, auth, want, reason, attribution, why in receipt_cases():
        directory = receipt_root / name
        directory.mkdir()
        write_json(directory / "receipt.json", receipt)
        write_json(directory / "keys.json", key_map)
        assessment = {"receipt": "receipt.json", "keys": "keys.json", **auth}
        expect = {"decision": want, "reason": reason}
        if attribution:
            expect["evidence_attribution"] = attribution
        index.append({"id": name, "description": why, "assessment": assessment, "expect": expect})
    write_json(receipt_root / "cases.json", {"claim_type": "co_signed_receipt/v1", "cases": index})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="exit 1 when tests/data differs")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        fresh = Path(tmp)
        build(fresh)
        stale = []
        for family in ("a2a-signed-card", "co-signed-receipt"):
            new = {p.relative_to(fresh): p.read_bytes() for p in (fresh / family).rglob("*")
                   if p.is_file()}
            have = {p.relative_to(DATA): p.read_bytes() for p in (DATA / family).rglob("*")
                    if p.is_file()} if (DATA / family).exists() else {}
            if new != have:
                stale.append(family)
                if not args.check:
                    shutil.rmtree(DATA / family, ignore_errors=True)
                    shutil.copytree(fresh / family, DATA / family)
        if args.check and stale:
            print(f"gen-signed-card-and-receipt-vectors: {', '.join(stale)} out of date; rerun",
                  file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
