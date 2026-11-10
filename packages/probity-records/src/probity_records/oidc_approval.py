"""Human approvals authenticated by an OpenID Connect provider instead of a key the approver holds.

An approver who signs in at the organisation's identity provider holds no signing key of their own. The
approval is bound to that sign-in instead. The relying party (the gateway) asks the provider for an ID token
whose ``nonce`` is ``approval_nonce(body)``, the SHA-256 of the approval body's canonical (JCS) bytes, and forces
a fresh sign-in (``prompt=login``, ``max_age=0``). The provider signs the token, so the approval verifies offline
under the provider's key, which an auditor pins by RFC 7638 thumbprint; the relying party holds no key that can
produce it.

An embedded OIDC approval carries, in place of ``approvalSig``:

- ``approvalToken``: the compact ID token;
- ``approvalPrincipal``: the audit-record principal member for it (``source`` ``id-token``, see identity.py);
- ``approvalJwks``: the provider's JWKS snapshot whose digest the principal's ``jwksDigest`` names.

The quorum policy pins such an approver as ``{"issuer", "subject"}``, and the approval body's ``keyId`` is
``principal_id(issuer, subject)``. ``verify_oidc_approval`` returns None or the first problem:

- the principal's own problems (``check_principal``) at the record's ``decisionTime``: an issuer or key thumbprint
  the auditor did not pin, a token outside its validity;
- the token's (``verify_token``): another token, a signature that does not verify, a claim that disagrees;
- ``approval_principal_not_pinned``: the token's issuer or subject is not the one pinned for the approver;
- ``approval_key_id_is_not_the_principal``;
- ``approval_nonce_mismatch``: the token answers another body (an edited body, or a sign-in for another request);
- ``approval_auth_not_fresh``: ``auth_time`` is missing, earlier than the body's ``issuedAt`` (less a 60 s clock
  allowance), or later than its ``expiresAt``: a reused session, not a sign-in for this approval.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Iterable, Mapping
from typing import Any

from .core import canonical, sha256_hex
from .grants import ts
from .identity import check_principal, unb64url, verify_token

SKEW_SECONDS = 60


def principal_id(issuer: str, subject: str) -> str:
    """The ``keyId`` of an approval made by signing in as ``subject`` at ``issuer``."""
    return sha256_hex(canonical({"issuer": issuer, "subject": subject}))


def approval_nonce(body: Mapping[str, Any]) -> str:
    """The ``nonce`` a sign-in for this exact approval body carries."""
    return sha256_hex(canonical(dict(body)))


def embed_oidc_approval(record: Mapping[str, Any], payload: bytes, token: str, principal: Mapping[str, Any],
                        jwks: Mapping[str, Any]) -> dict[str, Any]:
    """The embedded form of an approval-binding record whose approval is an OIDC sign-in."""
    return {"approvalJwks": dict(jwks), "approvalPrincipal": dict(principal), "approvalToken": token,
            "payloadB64": base64.b64encode(payload).decode("ascii"), "record": dict(record)}


def verify_oidc_approval(embedded: Mapping[str, Any], pinned: Any, pins: Mapping[str, Iterable[str]]) -> str | None:
    """None when ``embedded`` is an approval made by a fresh sign-in, as the approver ``pinned``
    (``{"issuer", "subject"}``), for exactly its approval body, under a provider key in ``pins``
    (issuer to RFC 7638 thumbprints)."""
    record = embedded.get("record") or {}
    approval = record.get("approval") or {}
    principal = embedded.get("approvalPrincipal")
    token, jwks = embedded.get("approvalToken"), embedded.get("approvalJwks")
    if not isinstance(principal, dict) or not isinstance(token, str) or not isinstance(jwks, dict):
        return "approval_oidc_evidence_missing"
    if not isinstance(pinned, Mapping) or (principal.get("issuer"), principal.get("subject")) != (
            pinned.get("issuer"), pinned.get("subject")):
        return "approval_principal_not_pinned"
    if principal.get("source") != "id-token":
        return "approval_principal_not_an_id_token"
    problem = check_principal(principal, str(record.get("decisionTime")), {k: list(v) for k, v in pins.items()})
    if problem is None:
        problem = verify_token(principal, token, jwks)
    if problem is not None:
        return problem
    if approval.get("keyId") != principal_id(str(pinned["issuer"]), str(pinned["subject"])):
        return "approval_key_id_is_not_the_principal"
    claims = json.loads(unb64url(token.split(".")[1]))
    if claims.get("nonce") != approval_nonce(approval):
        return "approval_nonce_mismatch"
    auth_time = claims.get("auth_time")
    try:
        issued, expires = ts(approval["issuedAt"]).timestamp(), ts(approval["expiresAt"]).timestamp()
    except (KeyError, TypeError, ValueError):
        return "approval_auth_not_fresh"
    if not isinstance(auth_time, int | float) or isinstance(auth_time, bool) or not (
            issued - SKEW_SECONDS <= auth_time <= expires):
        return "approval_auth_not_fresh"
    return None
