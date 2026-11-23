"""One contract every key custody backend keeps, run against every backend.

The per-backend tests in test_signing.py check what each backend does differently. This file
checks what they must all do the same, so a rule proved on one backend cannot be missing from
another: a misrouted signature refused on Vault and returned on Cloud KMS is the defect this
shape exists to catch. Each backend runs over a fake of its service that holds a real Ed25519
key, and the fake can be told to answer with a key the backend never pinned.
"""

from __future__ import annotations

import io
import json
from collections.abc import Callable
from dataclasses import dataclass
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from probity_records import (
    AwsKmsKey,
    GcpKmsKey,
    Journal,
    Signer,
    SigningError,
    SigningKey,
    Trust,
    VaultTransitKey,
    delegate,
    verify_journal,
)
from probity_records.clock import SystemClock, to_datetime
from probity_records.core import key_id
from test_signing import FakeAwsKms, FakeGcpKms, FakeVault

SYSTEM_CLOCK = SystemClock()  # these cases judge windows against the host's time


@dataclass
class Backend:
    """A backend under the contract: the key, what a verifier pins, and its custody label."""

    name: str
    key: SigningKey
    custody: str
    pinned_pem: bytes
    custody_pin: dict[str, str]


def _remote(name: str, key: SigningKey) -> Backend:
    return Backend(name, key, name, key.public_pem(), {key.key_id: name})


def _vault_service() -> tuple[SigningKey, Callable[[], None]]:
    vault = FakeVault()
    key = VaultTransitKey("http://vault:8200", "authority", token="t", opener=vault)
    return key, lambda: vault.keys.__setitem__(1, Ed25519PrivateKey.generate())


def _aws_service() -> tuple[SigningKey, Callable[[], None]]:
    kms = FakeAwsKms()
    return AwsKmsKey("k1", client=kms), lambda: setattr(
        kms, "key", Ed25519PrivateKey.generate()
    )


def _gcp_service() -> tuple[SigningKey, Callable[[], None]]:
    kms = FakeGcpKms()
    name = "projects/p/locations/global/keyRings/r/cryptoKeys/a/cryptoKeyVersions/1"
    return GcpKmsKey(name, client=kms), lambda: setattr(
        kms, "key", Ed25519PrivateKey.generate()
    )


SERVICES = {
    "vault-transit": _vault_service,
    "aws-kms": _aws_service,
    "gcp-kms": _gcp_service,
}


def _local() -> Backend:
    key = Signer.generate()
    return Backend("local", key, "local", key.public_pem(), {})


def _delegated() -> Backend:
    root = AwsKmsKey("root", client=FakeAwsKms())
    return Backend(
        "delegated",
        delegate(root, now=to_datetime(SYSTEM_CLOCK.now())),
        "delegated",
        root.public_pem(),
        {root.key_id: "aws-kms"},
    )


BACKENDS: dict[str, Callable[[], Backend]] = {
    "local": _local,
    **{
        name: (lambda name=name: _remote(name, SERVICES[name]()[0]))
        for name in SERVICES
    },
    "delegated": _delegated,
}


@pytest.fixture(params=sorted(BACKENDS))
def backend(request: pytest.FixtureRequest) -> Backend:
    return BACKENDS[request.param]()


def test_it_is_a_signing_key(backend: Backend) -> None:
    assert isinstance(backend.key, SigningKey)


@pytest.mark.parametrize(
    "message",
    [b"", b"m", bytes(range(256)) * 16],
    ids=["empty", "one-byte", "4096-bytes"],
)
def test_every_signature_verifies_under_the_pinned_key_over_exactly_the_message(
    backend: Backend, message: bytes
) -> None:
    signature = backend.key.sign(message)
    assert len(signature) == 64
    backend.key.public.verify(signature, message)


def test_the_key_id_and_pem_name_the_pinned_key(backend: Backend) -> None:
    assert backend.key.key_id == key_id(backend.key.public)
    loaded = load_pem_public_key(backend.key.public_pem())
    assert isinstance(loaded, Ed25519PublicKey)
    assert loaded.public_bytes_raw() == backend.key.public.public_bytes_raw()


def test_provenance_names_the_custody_and_does_not_change(backend: Backend) -> None:
    first = dict(backend.key.provenance)
    assert first["backend"] == backend.custody
    backend.key.sign(b"m")
    assert dict(backend.key.provenance) == first


@pytest.mark.parametrize("service", sorted(SERVICES))
def test_a_signature_from_a_key_never_pinned_never_leaves_sign(service: str) -> None:
    key, misroute = SERVICES[service]()
    key.public.verify(key.sign(b"m"), b"m")
    misroute()
    with pytest.raises(SigningError):
        key.sign(b"m")


class _GarbledVault(FakeVault):
    """Transit answering each sign request with ``answer`` as the response body."""

    def __init__(self, answer: object) -> None:
        super().__init__()
        self.answer = answer

    def __call__(self, req, timeout=None):
        if req.get_method() == "GET":
            return super().__call__(req, timeout)
        return io.BytesIO(json.dumps(self.answer).encode())


class _GarbledAws(FakeAwsKms):
    def __init__(self, answer: object) -> None:
        super().__init__()
        self.answer = answer

    def sign(self, **kw):
        return self.answer


class _GarbledGcp(FakeGcpKms):
    def __init__(self, answer: object) -> None:
        super().__init__()
        self.answer = answer

    def asymmetric_sign(self, request):
        return self.answer


def _garbled(service: str, answer: object) -> SigningKey:
    if service == "vault-transit":
        opener = _GarbledVault(answer)
        return VaultTransitKey("http://vault:8200", "authority", token="t", opener=opener)
    if service == "aws-kms":
        return AwsKmsKey("k1", client=_GarbledAws(answer))
    name = "projects/p/locations/global/keyRings/r/cryptoKeys/a/cryptoKeyVersions/1"
    return GcpKmsKey(name, client=_GarbledGcp(answer))


GARBLED = [
    ("vault-transit", {"data": {"signature": "garbage"}}),
    ("vault-transit", {"data": {"signature": None}}),
    ("vault-transit", {"data": {}}),
    ("vault-transit", {"errors": ["permission denied"]}),
    ("vault-transit", {"data": {"signature": "vault:v1:not base64!"}}),
    ("aws-kms", {}),
    ("aws-kms", {"Signature": None}),
    ("aws-kms", {"Signature": "c2lnbmF0dXJl"}),
    ("aws-kms", {"Signature": 64}),
    ("gcp-kms", object()),
    ("gcp-kms", SimpleNamespace(signature=None)),
    ("gcp-kms", SimpleNamespace(signature="c2lnbmF0dXJl")),
]


@pytest.mark.parametrize(("service", "answer"), GARBLED, ids=[f"{s}-{i}" for i, (s, _) in enumerate(GARBLED)])
def test_an_answer_with_no_readable_signature_raises_signing_error(service: str, answer: object) -> None:
    # The break: these answers escaped sign() as IndexError, KeyError, TypeError and
    # AttributeError, so a caller handling SigningError crashed instead of refusing; and
    # ``bytes(64)`` turned a number into 64 zero bytes before the check.
    key = _garbled(service, answer)
    with pytest.raises(SigningError):
        key.sign(b"m")


def test_a_journal_signed_through_it_verifies_under_its_pins(
    backend: Backend, tmp_path
) -> None:
    journal = Journal(tmp_path, backend.key, clock=SYSTEM_CLOCK)
    journal.append("https://example.test/t", "s", "0" * 64, {"phase": "note"})
    trust = Trust(key_custody=backend.custody_pin) if backend.custody_pin else None
    out = verify_journal(
        tmp_path, [backend.pinned_pem], journal.checkpoint(), trust=trust
    )
    assert out["verdict"] == "PASS", out["failures"]
    stranger = Signer.generate()
    assert (
        verify_journal(tmp_path, [stranger.public_pem()], journal.checkpoint())[
            "verdict"
        ]
        == "FAIL"
    )
