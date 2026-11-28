"""A stamp signed by a window key: the certificate travels in the stamp, and the stamp's own time must fall in it."""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from probity_records import Signer
from probity_records.canonical_identity import CanonicalIdentity, Ref
from probity_records.core import canonical
from probity_records.signing import DelegatedKey, DelegationScope, delegate
from probity_records.stamp import (
    WINDOW_FIELD,
    Stamp,
    StampRefused,
    sign_stamp,
    verify_stamp_in_window,
    window_certificate,
    window_field,
)

URL, BODY = "https://billing.example.com/mcp/refund", b'{"id":1}'
START = datetime(2026, 11, 23, 12, 0, tzinfo=UTC)
CREATED = int(START.timestamp()) + 60
SCOPE = DelegationScope("authority", "customer", "acme", 600)
IDENTITY = CanonicalIdentity(kind="agent", user=Ref("user", "prod", "https://idp.example.com", "alice"),
                             chain=(Ref("agent", "prod", "https://idp.example.com", "agent-refunds"),)).render()
STAMP = Stamp.of(IDENTITY, client="agent-refunds", principals="sha256:" + "a" * 64)


def seed_of(key: DelegatedKey) -> bytes:
    return key._key.private_bytes_raw()


def stamped(key: DelegatedKey, created: int = CREATED, certificate: Any = None, **over: Any) -> dict[str, str]:
    fields = sign_stamp(STAMP, seed=seed_of(key), method="POST", target_uri=URL, body=BODY, created=created,
                        ttl_seconds=60, nonce="n-1")
    return {**fields, WINDOW_FIELD: window_field(key.certificate if certificate is None else certificate), **over}


def verify(headers: Any, root: Signer, **over: Any) -> Any:
    args: dict[str, Any] = {"method": "POST", "target_uri": URL, "body": BODY, "roots": [root.public],
                            "now": (CREATED + 5) * 10**9, **over}
    return verify_stamp_in_window(headers, **args)


def code(headers: Any, root: Signer, **over: Any) -> str:
    with pytest.raises(StampRefused) as err:
        verify(headers, root, **over)
    return err.value.code


def test_a_stamp_signed_inside_its_window_verifies_under_the_certified_session_key() -> None:
    root = Signer.generate()
    key = delegate(root, SCOPE, now=START)
    got = verify(stamped(key), root)
    assert got.nonce == "n-1" and got.stamp.identity == IDENTITY


def test_a_stamp_created_outside_the_window_its_certificate_covers_is_refused() -> None:
    root = Signer.generate()
    key = delegate(root, SCOPE, now=START)
    start, end = int(START.timestamp()), int((START + timedelta(seconds=600)).timestamp())
    assert code(stamped(key, created=start - 1), root, now=(start + 5) * 10**9) == "stamp_window_outside"
    assert code(stamped(key, created=end), root, now=(end + 5) * 10**9) == "stamp_window_outside"
    assert verify(stamped(key, created=start), root, now=(start + 5) * 10**9).expires == start + 60
    assert code(stamped(key, created=10**14), root) == "stamp_window_outside"


def test_a_certificate_no_pinned_root_signed_or_of_the_retired_format_is_refused() -> None:
    root, other = Signer.generate(), Signer.generate()
    key = delegate(root, SCOPE, now=START)
    assert code(stamped(key), other) == "stamp_window_refused"
    retired = {"body": {**key.certificate["body"], "format": "probity-key-delegation/v1"}, "sig": key.certificate["sig"]}
    with pytest.raises(StampRefused, match="delegation_format_retired") as err:
        verify(stamped(key, certificate=retired), root)
    assert err.value.code == "stamp_window_refused"


def test_a_stamp_signed_by_another_key_than_the_certified_session_key_is_refused() -> None:
    root = Signer.generate()
    key, rival = delegate(root, SCOPE, now=START), delegate(root, SCOPE, now=START)
    forged = stamped(rival, certificate=key.certificate)
    assert code(forged, root) == "stamp_key_mismatch"


def test_the_window_field_is_present_and_the_canonical_base64_of_a_certificate() -> None:
    root = Signer.generate()
    key = delegate(root, SCOPE, now=START)
    headers = stamped(key)
    assert window_certificate(headers) == key.certificate
    assert code({k: v for k, v in headers.items() if k != WINDOW_FIELD}, root) == "stamp_window_missing"
    for bad in ("not base64!", base64.b64encode(b"[1]").decode(), base64.b64encode(b'{"a": 1}').decode(),
                base64.b64encode(canonical({"body": {}, "sig": "x"})[:-1]).decode()):
        assert code({**headers, WINDOW_FIELD: bad}, root) == "stamp_window_malformed"
    assert code({k: v for k, v in headers.items() if k.startswith("probity-p")}, root) == "stamp_malformed"
    twice = [*headers.items(), (WINDOW_FIELD, headers[WINDOW_FIELD])]
    assert code(twice, root) == "stamp_window_malformed"


def test_a_request_with_no_stamp_is_dropped_and_the_ordinary_checks_still_run() -> None:
    root = Signer.generate()
    key = delegate(root, SCOPE, now=START)
    assert code({WINDOW_FIELD: window_field(key.certificate)}, root) == "stamp_dropped"
    assert code(stamped(key), root, body=b"other") == "stamp_request_mismatch"
    assert code(stamped(key), root, now=(CREATED + 61) * 10**9) == "stamp_expired"
