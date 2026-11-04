"""Dispatch of the reference authority profile into the native ticket service.

The pure record, status, veto and delegation checks live in ``authority_checks``
so a reader can run them without the service.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict
from typing import Any

from probity_observer.grant_records import ActionRequest
from probity_observer.ticket_service import TicketStore

from authority_checks import check_authority, check_delegation, check_veto, refuse


def dispatch(
    store: TicketStore, request: ActionRequest, grant: dict[str, Any] | None,
    content: bytes, authority: dict[str, Any] | None, authority_key: str, *, at: int, request_deadline: int,
    hops: list[dict[str, Any]], root: str, veto: dict[str, Any] | None = None, latest: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Check veto, status and exact approved bytes, then enter the native gate.

    No reachable or unavailable human condition creates a grant. A previously
    issued exact grant is required in both cases. A binding veto blocks every
    grant. An unreachable authority source (``authority`` is ``None``) blocks
    dispatch: a fallback grant covers an unavailable human, never missing
    status evidence. Native expiry and persistent revocation are rechecked
    inside :meth:`TicketStore.dispatch`, including cached retries and the
    transaction immediately before the effect.

    Returns
    -------
    dict[str, Any]
        Native signed receipt. Native interruptions remain exceptions; callers
        must retain read-back and task outcome separately, as ``producer.py``
        does. A failed return is not proof of an absent effect.

    Raises
    ------
    VerificationError
        For a binding veto, missing delegated authority, an amplified or
        broken delegation chain, an unreachable or invalid authority source,
        mismatched descriptor bytes, or any native admission refusal.
    """
    check_veto(veto, authority_key, request, at)
    if grant is None:
        refuse("no pre-authorized fallback")
    if type(request_deadline) is not int or at >= request_deadline:
        refuse("original decision window has closed")
    check_delegation(hops, root, request.principal_id, request.tool_id, request.target_path)
    if authority is None:
        refuse("authority source unreachable")
    check_authority(authority, authority_key, request.principal_id, at, latest)
    if hashlib.sha256(content).hexdigest() != request.content_sha256:
        refuse("approved action bytes changed")
    return store.dispatch({"request": asdict(request), "grant": grant, "contentHex": content.hex()})
