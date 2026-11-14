"""Where a record's signature comes from: a key the signing code never holds in the agent's process.

Every backend here signs Ed25519, so the records, permits and checkpoints it signs verify under the
same public key with any Ed25519 verifier (Python, Rust, Go, TypeScript) and nothing else changes.

- ``Signer`` (core) holds a local key: for tests, demos and the separate-uid authority service.
- ``VaultTransitKey``: HashiCorp Vault (or OpenBao) transit engine, ``ed25519`` key type.
- ``AwsKmsKey``: AWS KMS, key spec ``ECC_NIST_EDWARDS25519``, algorithm ``ED25519_SHA_512``.
- ``GcpKmsKey``: Google Cloud KMS, algorithm ``EC_SIGN_ED25519``.
- ``delegate``: a short-lived session key in the signing process's memory, certified by any of the
  above. A KMS round trip per permit costs a network call and a fee, and AWS caps a raw Ed25519
  message at 4096 bytes; the session key signs the hot path and the root signs once per window.

Each backend checks every signature it is handed under the public key it pinned at construction, so a
backend that answers with another key's signature (a swapped key version, a misrouted request) fails
the call instead of writing a record no verifier accepts. Each names its custody in ``provenance``,
which the journal's checkpoint and every permit carry and an auditor compares with what it pinned.
"""

from __future__ import annotations

import base64
import json
import os
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol, runtime_checkable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_public_key

from .core import _b64, _unb64, canonical, key_id, load_public

DELEGATION_DOMAIN = b"probity-key-delegation-v1\x00"
DELEGATION_FORMAT = "probity-key-delegation/v1"
AWS_RAW_LIMIT = 4096


class SigningError(RuntimeError):
    """A backend refused to sign, or answered with a signature its pinned key does not accept."""


@runtime_checkable
class SigningKey(Protocol):
    """What the journal, permits and checkpoints need from a key: sign bytes, name the key."""

    @property
    def public(self) -> Ed25519PublicKey: ...

    @property
    def key_id(self) -> str: ...

    @property
    def provenance(self) -> Mapping[str, Any]: ...

    def public_pem(self) -> bytes: ...

    def sign(self, data: bytes) -> bytes: ...


class _PinnedKey:
    """Shared by the remote backends: the public key is fetched once and every signature checked."""

    _public: Ed25519PublicKey

    @property
    def public(self) -> Ed25519PublicKey:
        return self._public

    @property
    def key_id(self) -> str:
        return key_id(self._public)

    def public_pem(self) -> bytes:
        return self._public.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

    def _checked(self, data: bytes, sig: bytes) -> bytes:
        try:
            self._public.verify(sig, data)
        except InvalidSignature as exc:
            raise SigningError(f"{type(self).__name__} returned a signature its pinned key does not accept") from exc
        return sig


def _raw_public(raw: bytes) -> Ed25519PublicKey:
    if len(raw) != 32:
        raise SigningError("expected a 32-byte Ed25519 public key")
    return Ed25519PublicKey.from_public_bytes(raw)


@dataclass
class VaultTransitKey(_PinnedKey):
    """Vault transit key ``mount/keys/name`` of type ``ed25519``; token from ``token`` or ``VAULT_TOKEN``.

    ``version`` pins one key version; left ``None`` it pins the latest version at construction, so a
    later rotation never silently changes the key a running authority signs with.
    """

    address: str
    name: str
    mount: str = "transit"
    version: int | None = None
    token: str | None = None
    namespace: str | None = None
    opener: Callable[..., Any] = urllib.request.urlopen
    timeout: float = 10.0

    def __post_init__(self) -> None:
        info = self._call("GET", f"keys/{self.name}")["data"]
        if info.get("type") != "ed25519":
            raise SigningError(f"Vault transit key {self.name!r} is {info.get('type')!r}, not ed25519")
        if self.version is None:
            self.version = int(info["latest_version"])
        entry = info["keys"].get(str(self.version))
        if not isinstance(entry, Mapping) or "public_key" not in entry:
            raise SigningError(f"Vault transit key {self.name!r} has no version {self.version}")
        self._public = _raw_public(base64.b64decode(entry["public_key"]))

    def _call(self, method: str, path: str, body: Mapping[str, Any] | None = None) -> dict[str, Any]:
        token = self.token or os.environ.get("VAULT_TOKEN")
        if not token:
            raise SigningError("no Vault token (pass token= or set VAULT_TOKEN)")
        headers = {"X-Vault-Token": token, **({"X-Vault-Namespace": self.namespace} if self.namespace else {})}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(f"{self.address.rstrip('/')}/v1/{self.mount}/{path}", data=data,
                                     headers=headers, method=method)
        with self.opener(req, timeout=self.timeout) as resp:
            return json.loads(resp.read())

    @property
    def provenance(self) -> Mapping[str, Any]:
        return {"backend": "vault-transit", "key": f"{self.mount}/{self.name}", "version": self.version}

    def sign(self, data: bytes) -> bytes:
        out = self._call("POST", f"sign/{self.name}", {"input": _b64(data), "key_version": self.version})
        text = str(out["data"]["signature"])
        prefix = f"vault:v{self.version}:"
        if not text.startswith(prefix):
            raise SigningError(f"Vault signed with another key version: {text.split(':')[1]!r}")
        return self._checked(data, base64.b64decode(text[len(prefix):]))


@dataclass
class AwsKmsKey(_PinnedKey):
    """An AWS KMS key of spec ``ECC_NIST_EDWARDS25519``; ``client`` defaults to ``boto3.client("kms")``.

    KMS signs a raw Ed25519 message of at most 4096 bytes; larger messages raise ``SigningError``.
    Wrap the key with ``delegate`` for journals whose records carry approval bindings.
    """

    key: str
    client: Any = None
    region: str | None = None

    def __post_init__(self) -> None:
        if self.client is None:
            import boto3  # noqa: PLC0415 - optional extra

            self.client = boto3.client("kms", region_name=self.region)
        out = self.client.get_public_key(KeyId=self.key)
        if out.get("KeySpec") != "ECC_NIST_EDWARDS25519":
            raise SigningError(f"KMS key {self.key!r} is {out.get('KeySpec')!r}, not ECC_NIST_EDWARDS25519")
        public = load_der_public_key(out["PublicKey"])
        if not isinstance(public, Ed25519PublicKey):
            raise SigningError("KMS returned a public key that is not Ed25519")
        self._public = public
        self._arn = str(out.get("KeyId", self.key))

    @property
    def provenance(self) -> Mapping[str, Any]:
        return {"backend": "aws-kms", "key": self._arn}

    def sign(self, data: bytes) -> bytes:
        if len(data) > AWS_RAW_LIMIT:
            raise SigningError(f"AWS KMS signs at most {AWS_RAW_LIMIT} raw bytes; this message is {len(data)}"
                               " (sign through delegate(AwsKmsKey(...)))")
        out = self.client.sign(KeyId=self.key, Message=data, MessageType="RAW", SigningAlgorithm="ED25519_SHA_512")
        return self._checked(data, bytes(out["Signature"]))


@dataclass
class GcpKmsKey(_PinnedKey):
    """A Cloud KMS key version ``projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/V``
    with algorithm ``EC_SIGN_ED25519``; ``client`` defaults to ``KeyManagementServiceClient()``."""

    name: str
    client: Any = None

    def __post_init__(self) -> None:
        if self.client is None:
            from google.cloud import kms  # noqa: PLC0415 - optional extra

            self.client = kms.KeyManagementServiceClient()
        out = self.client.get_public_key(request={"name": self.name})
        algorithm = getattr(out.algorithm, "name", str(out.algorithm))
        if algorithm != "EC_SIGN_ED25519":
            raise SigningError(f"Cloud KMS key {self.name!r} is {algorithm!r}, not EC_SIGN_ED25519")
        self._public = load_public(out.pem.encode())

    @property
    def provenance(self) -> Mapping[str, Any]:
        return {"backend": "gcp-kms", "key": self.name}

    def sign(self, data: bytes) -> bytes:
        out = self.client.asymmetric_sign(request={"name": self.name, "data": data})
        return self._checked(data, bytes(out.signature))


def _ts(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


@dataclass
class DelegatedKey:
    """A session key held only in this process's memory, certified by ``root`` for one window.

    ``key_id`` is the session key's; ``certificate`` is what a verifier needs, with the root's public
    key pinned, to accept the session key (``verify_delegation``).
    """

    root: SigningKey
    certificate: dict[str, Any]
    _key: Ed25519PrivateKey = field(repr=False)

    @property
    def public(self) -> Ed25519PublicKey:
        return self._key.public_key()

    @property
    def key_id(self) -> str:
        return key_id(self.public)

    @property
    def provenance(self) -> Mapping[str, Any]:
        body = self.certificate["body"]
        return {"backend": "delegated", "notAfter": body["notAfter"], "root": dict(self.root.provenance),
                "rootKeyId": body["rootKeyId"]}

    def public_pem(self) -> bytes:
        return self.public.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

    def sign(self, data: bytes) -> bytes:
        return self._key.sign(data)


def delegate(root: SigningKey, lifetime: timedelta = timedelta(hours=1), *,
             now: datetime | None = None) -> DelegatedKey:
    """A fresh session key and the root's signed certificate for it, valid from ``now`` for ``lifetime``."""
    start = now or datetime.now(UTC)
    session = Ed25519PrivateKey.generate()
    body = {"format": DELEGATION_FORMAT, "notAfter": _ts(start + lifetime), "notBefore": _ts(start),
            "rootKeyId": root.key_id, "rootProvenance": dict(root.provenance),
            "sessionKey": _b64(session.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))}
    sig = root.sign(DELEGATION_DOMAIN + canonical(body))
    try:
        root.public.verify(sig, DELEGATION_DOMAIN + canonical(body))
    except InvalidSignature as exc:
        raise SigningError("the root signed the delegation with a key it does not name") from exc
    return DelegatedKey(root, {"body": body, "sig": _b64(sig)}, session)


@dataclass(frozen=True)
class Delegation:
    """A verified delegation: the session key, its window, and the root key that certified it."""

    session: Ed25519PublicKey
    session_key_id: str
    root_key_id: str
    not_before: str
    not_after: str

    def covers(self, at: str) -> bool:
        """Whether a record time ``at`` (RFC 3339, UTC ``Z``) falls inside the window."""
        try:
            moment = _parse(at)
        except ValueError:
            return False
        return _parse(self.not_before) <= moment <= _parse(self.not_after)


def _parse(text: str) -> datetime:
    if not isinstance(text, str) or not text.endswith("Z"):
        raise ValueError("expected an RFC 3339 UTC time ending in Z")
    return datetime.fromisoformat(text[:-1] + "+00:00")


def verify_delegation(certificate: Any, roots: list[Ed25519PublicKey]) -> Delegation:
    """The delegation when one pinned root signed it; ``ValueError`` otherwise. Nothing in the
    certificate selects its root: every pinned root is tried."""
    if not isinstance(certificate, Mapping) or not isinstance(certificate.get("body"), Mapping):
        raise ValueError("delegation_shape")
    body = dict(certificate["body"])
    if body.get("format") != DELEGATION_FORMAT or not {"notAfter", "notBefore", "rootKeyId", "sessionKey"} <= body.keys():
        raise ValueError("delegation_shape")
    message = DELEGATION_DOMAIN + canonical(body)
    sig = _unb64(certificate.get("sig"))
    for root in roots:
        try:
            root.verify(sig, message)
        except InvalidSignature:
            continue
        if key_id(root) != body["rootKeyId"]:
            raise ValueError("delegation_root_key_id_mismatch")
        session = _raw_public(_unb64(body["sessionKey"]))
        _parse(body["notBefore"]), _parse(body["notAfter"])
        return Delegation(session, key_id(session), body["rootKeyId"], body["notBefore"], body["notAfter"])
    raise ValueError("delegation_unverified")
