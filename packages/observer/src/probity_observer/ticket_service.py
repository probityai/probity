"""Finite HTTP-owned ticket state with exact authorization and durable recovery.

The server owns a SQLite ticket, not a file-write adapter. An intent commits
before mutation; ticket and receipt commit atomically afterwards. Read-back
queries the native row on a separate HTTP endpoint. This is same-operator
reference evidence, with no claim of remote identity or independent custody.
"""

from __future__ import annotations

import base64
import hashlib
import sqlite3
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from .crypto import (
    SigningKey,
    VerificationError,
    canonical,
    digest,
    strict_loads,
)
from .grant_records import (
    ActionRequest,
    AuthorizedAction,
    GrantPolicy,
    utc_clock,
    verify_grant,
)
from .ticket_state import (  # noqa: F401
    DOMAIN,
    MAX_BODY,
    READBACK_FIELDS,
    RECEIPT_FIELDS,
    STATE_FIELDS,
    VerifiedTicketCapture,
    _hex,
    _ticket_history_transition,
    _TicketHistoryProgress,
    _timestamp,
    _verify_ticket_history,
    _verify_ticket_rows,
    checked_record,
    load_ticket_capture,
    parse_time,
    state_schema,
    ticket_configuration,
    verify_ticket_capture,
    verify_ticket_result,
)


def _signed(payload: dict[str, Any], key: SigningKey) -> dict[str, Any]:
    """Sign native service state under a separately selected service key."""
    return {"payload": payload, "keyid": key.public_hex, "signature": key.sign(DOMAIN, payload)}


class TicketStore:
    """Own one exact ticket update, native persistence and monotonic history.

    ``request.tool_id`` must be ``ticket-update`` and its literal target must
    identify one ticket under ``/work/tickets/``. Tenant, principal, run,
    attempt, request, content and issuer are bound by the existing signed grant.
    The service key and SQLite directory belong to the host. A bearer grant is
    not proof of the HTTP caller's identity. A trusted host clock and local
    SQLite filesystem are required. The optional crash hook is host-only.
    An optional decision digest extends the committed configuration; the native
    decision profile must replay its own inputs before calling this base gate.
    """

    def __init__(
        self, path: Path, request: ActionRequest, policy: GrantPolicy,
        key: SigningKey, *, clock: Callable[[], datetime] = utc_clock,
        crash_hook: Callable[[str], None] | None = None,
        retained_head: dict[str, Any] | None = None,
        decision_digest: str | None = None,
        time_precision: Literal["seconds", "milliseconds"] = "seconds",
    ) -> None:
        self.path, self.request, self.policy, self.key = path, request, policy, key
        self.clock, self.crash_hook = clock, crash_hook
        self.retained_head = retained_head
        self.time_precision = time_precision
        self.configuration = ticket_configuration(request, policy, key.public_hex, decision_digest, time_precision)
        self.ticket_id = request.target_path.removeprefix("/work/tickets/")
        self.configuration_digest = digest(DOMAIN + "-configuration", self.configuration)

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        """Serialize threads and processes with SQLite's durable write lock."""
        try:
            connection = sqlite3.connect(self.path.resolve().as_uri() + "?mode=rw", uri=True, timeout=5, isolation_level=None)
        except sqlite3.Error as error:
            raise VerificationError("ticket store is missing or unavailable") from error
        try:
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except sqlite3.Error as error:
            connection.rollback()
            raise VerificationError("ticket native store is malformed or unavailable") from error
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> dict[str, Any]:
        """Create a fresh store once; never reset a missing restart state."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Exclusive creation keeps a pre-existing or interrupted store distinct.
        with self.path.open("xb"):
            pass
        self.path.chmod(0o600)
        with self._transaction() as db:
            db.execute("CREATE TABLE state (singleton INTEGER PRIMARY KEY CHECK(singleton=1), record BLOB NOT NULL)")
            db.execute("CREATE TABLE tickets (tenant TEXT, ticket TEXT, content BLOB NOT NULL, revision INTEGER NOT NULL, effect TEXT NOT NULL, PRIMARY KEY(tenant,ticket))")
            db.execute("CREATE TABLE events (sequence INTEGER PRIMARY KEY, record BLOB NOT NULL)")
            state = {"format": DOMAIN, "configuration": self.configuration_digest, "phase": "ready", "revision": 0, "contentDigest": None, "effectId": None, "grantDigest": None, "revoked": False, "eventCount": 0, "eventHead": "0" * 64, "intentTime": None, "effectTime": None}
            self._event(db, state, {"kind": "initialize", "configuration": self.configuration_digest})
            db.execute("INSERT INTO state VALUES(1,?)", (canonical(_signed(state, self.key)),))
        return self.readback()

    def _event(self, db: sqlite3.Connection, state: dict[str, Any], event: dict[str, Any]) -> None:
        """Append a service-signed event inside the current native transaction."""
        body = {"sequence": state["eventCount"] + 1, "previous": state["eventHead"], "event": event}
        body["hash"] = digest(DOMAIN + "-event", body)
        db.execute("INSERT INTO events VALUES(?,?)", (body["sequence"], canonical(_signed(body, self.key))))
        state["eventCount"], state["eventHead"] = body["sequence"], body["hash"]

    def _save(self, db: sqlite3.Connection, state: dict[str, Any]) -> None:
        """Commit the state signature in the same transaction as native rows."""
        db.execute("UPDATE state SET record=? WHERE singleton=1", (canonical(_signed(state, self.key)),))

    def _load(self, db: sqlite3.Connection) -> tuple[dict[str, Any], bytes | None]:
        """Query native populations and apply the shared public capture validator."""
        capture = load_ticket_capture(db, self.request, self.policy, self.key.public_hex,
            decision_digest=self.configuration.get("decisionDigest"), retained_head=self.retained_head,
            time_precision=self.time_precision)
        return capture.state, capture.content

    def _authorize(self, grant: Any, *, now: datetime) -> AuthorizedAction:
        """Check host authorization at the transaction's exact sampled reference time."""
        return verify_grant(grant, self.request, self.policy, now=now, reference_precision=self.time_precision)

    def dispatch(self, candidate: Any) -> dict[str, Any]:
        """Authorize, persist an intent, then atomically mutate ticket and receipt."""
        if not isinstance(candidate, dict) or set(candidate) != {"request", "grant", "contentHex"}:
            raise VerificationError("ticket dispatch fields differ")
        if len(canonical(candidate)) > MAX_BODY:
            raise VerificationError("ticket dispatch envelope exceeds finite limit")
        if candidate["request"] != asdict(self.request):
            raise VerificationError("ticket request differs")
        encoded = candidate["contentHex"]
        if not isinstance(encoded, str) or len(encoded) > MAX_BODY or len(encoded) % 2 or any(c not in "0123456789abcdef" for c in encoded):
            raise VerificationError("ticket content encoding differs")
        content = bytes.fromhex(encoded)
        if hashlib.sha256(content).hexdigest() != self.request.content_sha256:
            raise VerificationError("ticket content digest differs")
        with self._transaction() as db:
            state, stored_content = self._load(db)
            # Fresh grant validity and host revocation apply to cached retries too.
            intent_time = self.clock()
            authorized = self._authorize(candidate["grant"], now=intent_time)
            if state["revoked"]:
                raise VerificationError("ticket authority is revoked")
            if state["grantDigest"] not in (None, authorized.grant_digest):
                raise VerificationError("ticket grant differs from committed intent")
            if state["phase"] == "completed":
                if intent_time < parse_time(state["effectTime"], self.time_precision):
                    raise VerificationError("ticket host clock predates cached effect")
                self._require_readable_readback(state, None if stored_content is None else stored_content.hex())
                return self._response(state)
            if state["phase"] != "ready":
                raise VerificationError("ticket effect remains incomplete; automatic replay refused")
            self._require_readable_completion(state, encoded, authorized.grant_digest, intent_time)
            state["phase"], state["grantDigest"] = "pending", authorized.grant_digest
            state["intentTime"] = _timestamp(intent_time, self.time_precision)
            state["effectId"] = digest(DOMAIN + "-effect", {"configuration": self.configuration_digest, "requestId": self.request.request_id, "grantDigest": authorized.grant_digest})
            self._event(db, state, {"kind": "intent", "request": asdict(self.request), "grantDigest": authorized.grant_digest, "effectId": state["effectId"], "beforeRevision": 0, "intentTime": state["intentTime"]})
            self._save(db, state)
        self._fault("after-intent")
        with self._transaction() as db:
            state, _ = self._load(db)
            # A revocation racing the gap between transactions wins admission.
            effect_time = self.clock()
            self._authorize(candidate["grant"], now=effect_time)
            if effect_time < parse_time(state["intentTime"], self.time_precision):
                raise VerificationError("ticket host clock moved backwards before effect")
            if state["revoked"] or state["phase"] != "pending":
                raise VerificationError("ticket pending authority or phase differs")
            db.execute("INSERT INTO tickets VALUES(?,?,?,?,?)", (self.request.tenant_id, self.ticket_id, content, 1, state["effectId"]))
            self._fault("inside-effect-transaction")
            state.update(phase="completed", revision=1, contentDigest=self.request.content_sha256, effectTime=_timestamp(effect_time, self.time_precision))
            self._event(db, state, {"kind": "effect", "effectId": state["effectId"], "revision": 1, "contentDigest": self.request.content_sha256, "effectTime": state["effectTime"], "grantDigest": state["grantDigest"]})
            self._save(db, state)
        self._fault("after-effect")
        return self.readback()["receipt"]

    def _fault(self, point: str) -> None:
        """Invoke an optional host-only interruption control."""
        if self.crash_hook is not None:
            self.crash_hook(point)

    def _receipt_payload(self, state: dict[str, Any]) -> dict[str, Any]:
        """Use one receipt shape for size admission and completed signatures."""
        return {**state, "request": asdict(self.request), "authorityKey": self.policy.issuer_key, "witnessScope": "PEER", "coverage": "one-native-ticket-row-and-service-events"}

    def _response(self, state: dict[str, Any]) -> dict[str, Any]:
        """Sign a bounded service receipt retaining each identity separately."""
        return _signed(self._receipt_payload(state), self.key)

    def _native_response(self, state: dict[str, Any], encoded: str | None, receipt: dict[str, Any]) -> dict[str, Any]:
        """Build the exact GET envelope used by admission and actual read-back."""
        return {"tenantId": self.request.tenant_id, "ticketId": self.ticket_id, "contentHex": encoded, "revision": state["revision"], "effectId": state["effectId"], "receipt": receipt}

    def _require_readable_completion(self, state: dict[str, Any], encoded: str, grant_digest: str, intent_time: datetime) -> None:
        """Refuse an unreadable native effect before its durable intent exists."""
        completed = {**state, "phase": "completed", "revision": 1, "contentDigest": self.request.content_sha256, "effectId": "0" * 64, "grantDigest": grant_digest, "eventCount": state["eventCount"] + 2, "eventHead": "0" * 64, "intentTime": _timestamp(intent_time, self.time_precision), "effectTime": _timestamp(intent_time, self.time_precision)}
        self._require_readable_readback(completed, encoded)

    def _require_readable_readback(self, state: dict[str, Any], encoded: str | None) -> None:
        """Apply one exact envelope bound to new and retained native state."""
        # Every digest has 64 ASCII bytes; an Ed25519 signature has 88 base64
        # bytes. Selected timestamp precision determines their exact width.
        # This unsigned shape
        # measures the future envelope without signing an unobserved effect.
        receipt = {"payload": self._receipt_payload(state), "keyid": self.key.public_hex, "signature": base64.b64encode(bytes(64)).decode("ascii")}
        if len(canonical(self._native_response(state, encoded, receipt))) > MAX_BODY:
            raise VerificationError("ticket native read-back exceeds finite limit")

    def readback(self) -> dict[str, Any]:
        """Query actual SQLite ticket bytes separately from dispatch responses."""
        if not self.path.exists():
            raise VerificationError("ticket store is missing; initialization required")
        with self._transaction() as db:
            state, content = self._load(db)
            encoded = None if content is None else content.hex()
            self._require_readable_readback(state, encoded)
            return self._native_response(state, encoded, self._response(state))

    def revoke(self) -> dict[str, Any]:
        """Persist host-only revocation; there is no network admin endpoint."""
        with self._transaction() as db:
            state, _ = self._load(db)
            if not state["revoked"]:
                state["revoked"] = True
                self._event(db, state, {"kind": "revoke", "authorityKey": self.policy.issuer_key})
                self._save(db, state)
            return self._response(state)

    def recover(self) -> dict[str, Any]:
        """Retain an incomplete terminal for pending effects without repeating them."""
        with self._transaction() as db:
            state, _ = self._load(db)
            if state["phase"] == "pending":
                state["phase"] = "incomplete"
                self._event(db, state, {"kind": "incomplete", "effectId": state["effectId"], "requestId": self.request.request_id, "outcome": "not-established-after-interruption"})
                self._save(db, state)
            return self._response(state)


class TicketHTTPServer(ThreadingHTTPServer):
    """Serve one local ticket on distinct dispatch and read-back HTTP routes."""

    daemon_threads = True

    def __init__(self, store: TicketStore, address: tuple[str, int] = ("127.0.0.1", 0)) -> None:
        if address[0] != "127.0.0.1":
            raise VerificationError("reference ticket server binds only loopback")
        self.store = store
        super().__init__(address, _TicketHandler)

    @property
    def url(self) -> str:
        """Return the concrete bound local HTTP endpoint."""
        return f"http://127.0.0.1:{self.server_address[1]}"


class _TicketHandler(BaseHTTPRequestHandler):
    """Apply finite HTTP framing before reaching the host-owned ticket store."""

    server: TicketHTTPServer

    def log_message(self, format: str, *args: Any) -> None:
        """Keep caller content and bearer grants out of request logs."""

    def _reply(self, code: int, value: dict[str, Any]) -> None:
        """Return a finite canonical JSON response."""
        raw = canonical(value)
        if len(raw) > MAX_BODY:
            raise VerificationError("ticket HTTP response exceeds finite limit")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self) -> None:
        """Dispatch only an exact route, bounded body and canonical JSON object."""
        try:
            lengths = self.headers.get_all("Content-Length", [])
            if self.path != "/dispatch" or len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdecimal() or self.headers.get("Transfer-Encoding") is not None:
                raise VerificationError("ticket HTTP framing or route differs")
            length = int(lengths[0])
            if not 1 <= length <= MAX_BODY:
                raise VerificationError("ticket HTTP body exceeds finite limit")
            self.connection.settimeout(5)
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise VerificationError("ticket HTTP body is incomplete")
            self._reply(200, self.server.store.dispatch(strict_loads(raw)))
        except (VerificationError, ValueError, TimeoutError, RecursionError):
            self._reply(409, {"status": "refused", "reason": "ticket request, authority, state or framing differs"})

    def do_GET(self) -> None:
        """Read native persisted state through a separate tenant/ticket route."""
        store = self.server.store
        if self.path != f"/tickets/{store.request.tenant_id}/{store.ticket_id}":
            self._reply(404, {"status": "unsupported"})
            return
        try:
            self._reply(200, store.readback())
        except (VerificationError, RecursionError):
            self._reply(409, {"status": "refused", "reason": "native ticket state differs"})


@contextmanager
def running_server(store: TicketStore) -> Iterator[TicketHTTPServer]:
    """Run a real local HTTP listener and close all resources on exit."""
    with TicketHTTPServer(store) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server
        finally:
            server.shutdown()
            thread.join(timeout=5)


def http_json(url: str, candidate: dict[str, Any] | None = None) -> tuple[int, dict[str, Any]]:
    """Perform a bounded native HTTP request, preserving refusal status codes."""
    body = None if candidate is None else canonical(candidate)
    if body is not None and len(body) > MAX_BODY:
        raise VerificationError("ticket HTTP request exceeds finite limit")
    request = Request(url, data=body, headers={"Content-Type": "application/json"})
    try:
        response = urlopen(request, timeout=5)
    except HTTPError as error:
        response = error
    with response:
        raw = response.read(MAX_BODY + 1)
        if len(raw) > MAX_BODY:
            raise VerificationError("ticket HTTP response exceeds finite limit")
        return response.code, strict_loads(raw)


