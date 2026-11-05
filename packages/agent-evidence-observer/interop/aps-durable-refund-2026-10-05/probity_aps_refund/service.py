"""Host-side durable store for one native APS refund effect.

This consumer profile uses the unchanged installed APS SDK and TicketStore.
The reading side lives in ``verification``.
"""
from __future__ import annotations

import json
import time
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from probity_observer.crypto import SigningKey, VerificationError, canonical
from probity_observer.grant_records import ActionRequest, AuthorizedAction, GrantPolicy
from probity_observer.ticket_service import TicketStore

from .verification import (
    join_report,
    refund_decision_digest,
    refund_operation_id,
    verify_aps,
)


def millisecond_clock() -> datetime:
    """Sample CLOCK_REALTIME at the native profile's declared millisecond resolution."""
    return datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(milliseconds=time.time_ns() // 1_000_000)


class ApsRefundStore(TicketStore):
    """Freeze native evidence and reuse durable ticket intent/effect transactions.

    The host owns the directory, tenant, public-key policy, local grant, service
    key, verifier and clock. It selects the store by tenant and exact APS action
    reference; changing roots or deleting host state does not establish replay
    protection. A completed retry returns the same logical operation, with no
    second intent or effect. A pending operation is refused until explicit
    recovery, never automatically replayed. The effect is a local SQLite row.
    """

    def __init__(self, path: Path, request: ActionRequest, policy: GrantPolicy, key: SigningKey,
                 *, evidence: dict[str, Any], tenant_id: str, node: Path, verifier: Path,
                 verifier_sha256: str, sdk_sha256: str, clock: Callable[[], datetime] = millisecond_clock,
                 crash_hook: Callable[[str], None] | None = None) -> None:
        self._evidence = json.dumps(evidence, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("ascii")
        self._node, self._verifier, self._verifier_pin = node, verifier, verifier_sha256
        self._sdk_pin = sdk_sha256
        report = verify_aps(evidence, node=node, verifier=verifier, verifier_sha256=verifier_sha256, sdk_sha256=sdk_sha256, now=clock())
        operation = refund_operation_id(report["actionRef"], tenant_id)
        if path.name != "refund-" + operation + ".sqlite":
            raise VerificationError("APS refund durable store selection differs")
        self._native_report = canonical(report)
        commitment = refund_decision_digest(report, request, tenant_id=tenant_id,
                                            verifier_sha256=verifier_sha256, sdk_sha256=sdk_sha256)
        super().__init__(path, request, policy, key, clock=clock, crash_hook=crash_hook, decision_digest=commitment,
            time_precision="milliseconds")

    def _authorize(self, grant: Any, *, now: datetime) -> AuthorizedAction:
        """Join genuine native approval and local grant at one transaction clock."""
        report = verify_aps(json.loads(self._evidence), node=self._node, verifier=self._verifier,
                            verifier_sha256=self._verifier_pin, sdk_sha256=self._sdk_pin, now=now)
        join_report(report, self.request)
        if canonical(report) != self._native_report:
            raise VerificationError("APS refund frozen native join differs")
        return super()._authorize(grant, now=now)
